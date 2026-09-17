import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { analyzeModule, requiresAuth, writesStorage, canUpgradeSelf } from "../src/analyze.ts";
import { detect, detectFull, lacunas, lerSpec } from "../src/detect.ts";
import { hostFn, AUTH_FNS, STORAGE_WRITE_FNS, SIG_SCHEME_FNS } from "../src/hostfns.ts";

const CORPUS = new URL("../corpus/", import.meta.url).pathname;
const files = readdirSync(CORPUS).filter((f) => f.endsWith(".wasm"));
const load = (f: string) => new Uint8Array(readFileSync(CORPUS + f));

/** Exporta `__constructor` E `initialize` — o caso que caía no detector genérico. */
const CTOR_MAIS_INIT = "CCR2CH4GQVCZHG7CHFVMNANCK45CU5DVKXZIIITDZQAU3CEJZ7RQH2MQ.wasm";
const ESCROW = "CDZZ5HUOBL2QGELMWQMWNIPMA4TWYMX3KWMA6PWQL3OUTBDXUOL742T5.wasm";
const POOL_ROUTER = "CBBMQBNHB2FYVZYV7VNHOJHUMTFJLR4PUMRVQYNW6RHIKZO2NQMIBUCV.wasm";

test("catálogo de host functions resolve as chaves que os detectores dependem", () => {
  assert.equal(hostFn("a.0")?.name, "require_auth");
  assert.equal(hostFn("l._")?.name, "put_contract_data");
  assert.equal(hostFn("x.1")?.name, "contract_event");
  assert.ok(AUTH_FNS.has("require_auth"));
  assert.ok(STORAGE_WRITE_FNS.has("put_contract_data"));
});

test("todo WASM do corpus parseia sem exceção", () => {
  assert.ok(files.length >= 10, `corpus pequeno demais: ${files.length}`);
  for (const f of files) assert.doesNotThrow(() => analyzeModule(load(f)), f);
});

test("exceções de ciclo de vida nunca viram achado", () => {
  for (const f of files) {
    for (const fd of detect(analyzeModule(load(f)))) {
      assert.ok(
        fd.entrypoint !== "__constructor" && fd.entrypoint !== "__check_auth",
        `${f}: ${fd.class} disparou em ${fd.entrypoint}, que é exceção de ciclo de vida`,
      );
    }
  }
});

test("achado de autorização implica ausência real de require_auth no alcance", () => {
  for (const f of files) {
    const an = analyzeModule(load(f));
    for (const fd of detect(an)) {
      // `third-party-state-tampering` é o mesmo fato de bytecode com outra letra: um
      // escritor sem auth. O invariante vale igual e não pode escapar por mudança de classe.
      if (!/unauthenticated-state-mutation|initialization-front-running|third-party-state-tampering/.test(fd.class)) continue;
      const ep = an.entrypoints.find((e) => e.name === fd.entrypoint)!;
      assert.equal(requiresAuth(ep), false, `${f}:${fd.entrypoint} alcança auth mas foi reportado`);
      assert.equal(writesStorage(ep), true, `${f}:${fd.entrypoint} não alcança escrita mas foi reportado`);
    }
  }
});

test("toda afirmação de nível A é acompanhada de evidência não vazia", () => {
  for (const f of files) {
    for (const fd of detect(analyzeModule(load(f)))) {
      assert.ok(fd.evidence.length > 0, `${f}: ${fd.id} sem evidência`);
      for (const ev of fd.evidence) assert.ok(ev.claim.length > 20, `${f}: ${fd.id} evidência vazia`);
      assert.ok(fd.id, "achado sem id no padrão do template");
    }
  }
});

test("IDs seguem o padrão do template oficial", () => {
  for (const f of files) {
    for (const fd of detect(analyzeModule(load(f)))) {
      assert.match(fd.id!, /^(Spoof|Tamper|Repudiate|Info|DoS|Elevation)\.\d+$/, `${f}: id inválido ${fd.id}`);
    }
  }
});

test("supressões são contabilizadas, nunca silenciosas", () => {
  for (const f of files) {
    const wasm = load(f);
    const r = detectFull(analyzeModule(wasm), wasm);
    for (const s of r.suppressed) {
      assert.ok(s.motivo.length > 20, `${f}: supressão sem motivo explicado em ${s.entrypoint}`);
      assert.ok(!r.findings.some((x) => x.entrypoint === s.entrypoint && /unauthenticated|initialization/.test(x.class)),
        `${f}: ${s.entrypoint} foi suprimido e reportado ao mesmo tempo`);
    }
  }
});

test("funções reservadas `__` nunca viram achado", () => {
  for (const f of files) {
    const wasm = load(f);
    for (const fd of detectFull(analyzeModule(wasm), wasm).findings) {
      assert.ok(!fd.entrypoint.startsWith("__"), `${f}: ${fd.class} disparou em ${fd.entrypoint} (reservada pelo host, CAP-0058)`);
    }
  }
});

test("achado de SDK vulnerável cita versão e advisory", () => {
  let n = 0;
  for (const f of files) {
    const wasm = load(f);
    for (const fd of detectFull(analyzeModule(wasm), wasm).findings.filter((x) => x.class === "vulnerable-sdk")) {
      n++;
      assert.match(fd.evidence[0].claim, /rssdkver = \d+\.\d+\.\d+/, "sem versão concreta");
      assert.match(fd.evidence[1].claim, /(CVE|GHSA)/, "sem identificador de advisory");
      assert.ok(fd.evidence.some((e) => e.tier === "C" && /curated as of/.test(e.claim)), "sem aviso de que a lista envelhece");
    }
  }
  assert.ok(n > 0, "nenhum achado de SDK no corpus — detector provavelmente quebrado");
});

/* ---------- advisories de SDK: faixa, filtro de import, severidade de exposição ---------- */

import { xdr } from "@stellar/stellar-sdk";
import { advisoriesFor, advisoriesForWasm, readSdkMeta, PAIRING_CURVE_FNS, ADVISORIES } from "../src/sdkver.ts";

const CVE = "CVE-2026-26267 / GHSA-4chv-4c6w-w254";
const X2HW = "GHSA-x2hw-px52-wp4m";
const ids = (v: string | undefined) => advisoriesFor(v).map((a) => a.id);

/** WASM mínimo: seção de tipo, imports `c.<x>` dados e `contractmetav0` com rssdkver. */
function wasmSintetico(rssdkver: string | undefined, importKeys: string[]): Uint8Array {
  const leb = (n: number) => { const o: number[] = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; o.push(b); } while (n); return o; };
  const str = (s: string) => { const b = [...Buffer.from(s)]; return [...leb(b.length), ...b]; };
  const sec = (id: number, body: number[]) => [id, ...leb(body.length), ...body];
  const bytes: number[] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  bytes.push(...sec(1, [1, 0x60, 0, 0]));
  const imps = importKeys.flatMap((k) => { const [m, n] = k.split("."); return [...str(m), ...str(n), 0x00, 0]; });
  bytes.push(...sec(2, [...leb(importKeys.length), ...imps]));
  if (rssdkver) {
    const meta = [...xdr.ScMetaEntry.scMetaV0(new xdr.ScMetaV0({ key: "rssdkver", val: rssdkver })).toXDR()];
    bytes.push(...sec(0, [...str("contractmetav0"), ...meta]));
  }
  return new Uint8Array(bytes);
}

test("CVE-2026-26267: faixa segue o advisory (<=22.0.9, 23.0.0–23.5.1, 25.0.0–25.1.0)", () => {
  for (const v of ["21.7.7", "22.0.9", "23.0.0", "23.5.1", "25.0.0", "25.1.0", "22.0.8-rc.1"]) assert.ok(ids(v).includes(CVE), `${v} deveria estar na faixa`);
  for (const v of ["22.0.10", "22.0.11", "23.5.2", "23.5.3", "25.1.1", "25.3.1", "26.0.0"]) assert.ok(!ids(v).includes(CVE), `${v} é corrigida`);
  assert.deepEqual(ids(undefined), []);
});

test("GHSA-x2hw: faixa começa em 22.0.0 (Fr não existe antes) e termina antes das correções", () => {
  for (const v of ["21.7.7", "20.0.0", "22.0.11", "23.5.3", "25.3.0", "26.0.0"]) assert.ok(!ids(v).includes(X2HW), `${v} fora da faixa`);
  for (const v of ["22.0.0", "22.0.10", "23.0.0", "23.5.2", "25.0.0", "25.2.0"]) assert.ok(ids(v).includes(X2HW), `${v} na faixa`);
});

test("GHSA-x2hw só é emitido se o WASM importar host function de BLS12-381/BN254", () => {
  assert.ok(PAIRING_CURVE_FNS.has("bls12_381_fr_add") && PAIRING_CURVE_FNS.has("bn254_g1_mul"));
  assert.equal(hostFn("c.h")?.name, "bls12_381_fr_add");
  const sem = wasmSintetico("23.0.0", ["a.0"]);
  const com = wasmSintetico("23.0.0", ["a.0", "c.h"]);
  assert.equal(readSdkMeta(sem).version, "23.0.0");
  assert.deepEqual(advisoriesForWasm(sem).map((h) => h.advisory.id), [CVE]);
  const hits = advisoriesForWasm(com);
  assert.deepEqual(hits.map((h) => h.advisory.id).sort(), [CVE, X2HW].sort());
  assert.deepEqual(hits.find((h) => h.advisory.id === X2HW)!.gateHits, ["bls12_381_fr_add"]);
  const fx = detectFull(analyzeModule(com), com).findings.find((f) => f.title.includes(X2HW))!;
  assert.ok(fx.evidence.some((e) => e.tier === "C" && /Heuristic filter/.test(e.claim)), "filtro heurístico não declarado na evidência C");
  // no corpus: nenhum x2hw em contrato sem import de curva
  for (const f of files) {
    const wasm = load(f);
    if (detectFull(analyzeModule(wasm), wasm).findings.some((x) => x.title.includes(X2HW))) {
      const an = analyzeModule(wasm);
      assert.ok(an.imports.some((i) => i.name && PAIRING_CURVE_FNS.has(i.name)), `${f}: x2hw sem import BLS/BN254`);
    }
  }
});

test("achado de exposição de SDK nunca herda a severidade do advisory", () => {
  const w = wasmSintetico("22.0.8", ["c.h"]);
  const fs = detectFull(analyzeModule(w), w).findings.filter((x) => x.class === "vulnerable-sdk");
  assert.equal(fs.length, 2);
  for (const fd of fs) {
    assert.equal(fd.severity, "Low");
    assert.match(fd.title, /^Exposure: .*exploitability not confirmed/);
    assert.match(fd.evidence[1].claim, /\((High|Medium) in the advisory\)/, "severidade do advisory deve ficar na evidência A");
  }
  for (const f of files) {
    const wasm = load(f);
    for (const fd of detectFull(analyzeModule(wasm), wasm).findings.filter((x) => x.class === "vulnerable-sdk")) {
      assert.notEqual(fd.severity, "High", `${f}: exposição com High`);
      assert.notEqual(fd.severity, "Critical", `${f}: exposição com Critical`);
    }
  }
});

/* ---------- AE-1: fronteira de confiança rebaixa, não suprime ---------- */

import { callsOut } from "../src/analyze.ts";

test("escritor sem auth que chama outro contrato é rebaixado a High, nunca suprimido", () => {
  let vistos = 0;
  for (const f of files) {
    const wasm = load(f);
    const an = analyzeModule(wasm);
    const r = detectFull(an, wasm);
    for (const fd of r.findings) {
      if (fd.class !== "unauthenticated-state-mutation") continue;
      const ep = an.entrypoints.find((e) => e.name === fd.entrypoint)!;
      if (!callsOut(ep)) continue;
      vistos++;
      assert.notEqual(fd.severity, "Critical", `${f}:${fd.entrypoint} — alcança call/try_call e não pode sair Critical`);
      assert.ok(
        fd.evidence.some((e) => e.tier === "C" && /delegated to a called contract/.test(e.claim)),
        `${f}:${fd.entrypoint} — sem a ressalva C de autorização no callee`,
      );
      assert.ok(
        !fd.evidence.some((e) => /Any address can invoke this and change the contract state/.test(e.claim)),
        `${f}:${fd.entrypoint} — mantém a afirmação C que o binário não sustenta`,
      );
      // rebaixamento é declarado, como supressão é
      assert.ok(
        r.suppressed.some((s) => s.entrypoint === `<downgraded:${fd.entrypoint}>`),
        `${f}:${fd.entrypoint} — rebaixamento silencioso`,
      );
    }
  }
  assert.ok(vistos > 0, "nenhum escritor sem auth com call/try_call no corpus — caso não exercitado");
});

/* ---------- AQ-3: PRNG com fan-out alto sai agregado ---------- */

const PRNG_FANOUT = "CDZVUPNQYESKVQ37OCXM2GSSMIBASKGOZROZQ4NVT6ZS5RO7EGAXAWLL.wasm";

test("PRNG alcançado por mais de 3 entrypoints vira UM achado de contrato", () => {
  const wasm = load(PRNG_FANOUT);
  const fs = detectFull(analyzeModule(wasm), wasm).findings.filter((x) => x.class === "host-prng-in-value-path");
  assert.equal(fs.length, 1, `esperado 1 achado agregado, veio ${fs.length}`);
  const [fd] = fs;
  assert.equal(fd.entrypoint, "<contrato>");
  // os entrypoints não somem na agregação: ficam na evidência A
  for (const ep of ["init", "withdraw", "approve", "upgrade", "dapp_invoker"]) {
    assert.ok(fd.evidence.some((e) => e.tier === "A" && e.claim.includes(ep)), `entrypoint ${ep} sumiu da evidência`);
  }
  assert.match(fd.evidence[0].claim, /\d+ hops?\b/, "achado de PRNG sem contagem de saltos");
});

test("todo achado de PRNG declara saltos, e o agregado só existe acima de 3 entrypoints", () => {
  for (const f of files) {
    const wasm = load(f);
    for (const fd of detectFull(analyzeModule(wasm), wasm).findings.filter((x) => x.class === "host-prng-in-value-path")) {
      assert.match(fd.evidence[0].claim, /\d+ hops?\b/, `${f}: achado de PRNG sem saltos`);
      if (fd.entrypoint === "<contrato>") {
        assert.match(fd.evidence[0].claim, /,/, `${f}: agregado com um único entrypoint`);
      }
      assert.ok(["Medium", "Low"].includes(fd.severity), `${f}: PRNG com severidade ${fd.severity}`);
    }
  }
});

/* ---------- AE-9: verbo de leitura depois do underscore ---------- */

test("`gauges_get_reward_info` é suprimido como read-shaped, e escritor com verbo na frente não é", () => {
  const f = "CA6PUJLBYKZKUEKLZJMKBZLEKP2OTHANDEOWSFF44FTSYLKQPIICCJBE.wasm";
  const wasm = load(f);
  const r = detectFull(analyzeModule(wasm), wasm);
  assert.ok(
    r.suppressed.some((s) => s.entrypoint === "gauges_get_reward_info" && /read-shaped name/.test(s.motivo)),
    "gauges_get_reward_info deveria entrar em suppressed com motivo declarado",
  );
  assert.ok(
    !r.findings.some((x) => x.entrypoint === "gauges_get_reward_info"),
    "gauges_get_reward_info suprimido e reportado ao mesmo tempo",
  );
  // Ground truth de docs/triagem-unauth: nenhum TP humano pode ser suprimido pela nova regra.
  // A CLASSE de um TP pode mudar — `third-party-state-tampering` re-letra parte do que saía
  // como `unauthenticated-state-mutation` (Elevation → Tamper) sem mexer no fato de bytecode.
  // O que o ground truth prende é que o entrypoint continue REPORTADO, não sob qual classe.
  const TP = new Set(["init", "submit", "update_b_rate", "add_yield", "delete_note", "update_signer", "initialize", "initialize_escrow"]);
  const CLASSES_TP = new Set([
    "unauthenticated-state-mutation",
    "third-party-state-tampering",
    "initialization-front-running",
  ]);
  for (const g of files) {
    const w = load(g);
    for (const s of detectFull(analyzeModule(w), w).suppressed) {
      assert.ok(!TP.has(s.entrypoint), `${g}: ${s.entrypoint} é TP verificado por humano e foi suprimido`);
    }
  }
  // Não basta não suprimir: os dois TPs de init da triagem têm que CONTINUAR reportados,
  // e agora como front-running (a classe certa), não como escritor genérico sem auth.
  // e todo TP que aparece no corpus continua reportado sob uma das classes aceitas
  let tpVistos = 0;
  for (const g of files) {
    const w = load(g);
    for (const fd of detectFull(analyzeModule(w), w).findings) {
      if (!TP.has(fd.entrypoint)) continue;
      tpVistos++;
      assert.ok(CLASSES_TP.has(fd.class), `${g}: ${fd.entrypoint} saiu como ${fd.class}, fora das classes aceitas`);
    }
  }
  assert.ok(tpVistos > 0, "nenhum TP do ground truth apareceu no corpus");
  for (const [g, ep] of [[CTOR_MAIS_INIT, "initialize"], [ESCROW, "initialize_escrow"]] as const) {
    const w = load(g);
    const fd = detectFull(analyzeModule(w), w).findings.find((x) => x.entrypoint === ep);
    assert.ok(fd, `${g}: ${ep} é TP verificado por humano e sumiu do relatório`);
    assert.equal(fd!.class, "initialization-front-running", `${g}: ${ep} saiu como ${fd!.class}`);
  }
});

/* ---------- init-shaped: classe é front-running mesmo com __constructor ---------- */

test("nome de init com __constructor no módulo continua front-running, nunca Critical genérico", () => {
  const wasm = load(CTOR_MAIS_INIT);
  const an = analyzeModule(wasm);
  assert.ok(an.entrypoints.some((e) => e.name === "__constructor"), "caso perdeu o pressuposto: sem __constructor");
  const fd = detectFull(an, wasm).findings.find((x) => x.entrypoint === "initialize")!;
  assert.ok(fd, "initialize sumiu do relatório");
  assert.equal(fd.class, "initialization-front-running");
  assert.notEqual(fd.severity, "Critical", "init nunca é Critical: depende de o deploy não ser atômico");
  assert.ok(["High", "Medium"].includes(fd.severity), `severidade inesperada: ${fd.severity}`);
  // a existência do construtor é nota C, não some
  assert.ok(
    fd.evidence.some((e) => e.tier === "C" && /DOES export `__constructor`/.test(e.claim)),
    "sem a nota C de que o construtor existe (segunda etapa ou legado)",
  );
  // alcançabilidade de has_contract_data é fato A
  assert.ok(
    fd.evidence.some((e) => e.tier === "A" && /`has_contract_data` IS reachable/.test(e.claim)),
    "sem o fato A de alcançabilidade da guarda de já-inicializado",
  );
});

test("a guarda de init sai em DUAS evidências: alcançabilidade em [A], leitura em [C]", () => {
  // A linha antiga dizia, sob [A], "`has_contract_data` É alcançável — provável guarda de já
  // inicializado": metade fato de bytecode, metade opinião, com o crachá do fato.
  const wasm = load(CTOR_MAIS_INIT);
  const an = analyzeModule(wasm);
  const fd = detectFull(an, wasm).findings.find((x) => x.class === "initialization-front-running")!;
  assert.ok(fd, "o caso perdeu o achado de init");

  // (o claim `base` lista o conjunto alcançável inteiro e também contém o nome — a linha da
  // guarda é a que COMEÇA por ele)
  const fatos = fd.evidence.filter((e) => e.tier === "A" && /^`has_contract_data`/.test(e.claim));
  assert.equal(fatos.length, 1, "a alcançabilidade da guarda tem que sair em exatamente um fato A");
  assert.match(fatos[0].claim, /^`has_contract_data` IS (NOT )?reachable from this export\.$/);
  // e o fato não pode carregar nenhuma inferência de carona
  assert.ok(
    !/likely|guard|inference|suggests/i.test(fatos[0].claim),
    `fato A ainda mistura inferência: ${fatos[0].claim}`,
  );
  // a leitura ("é uma guarda de já-inicializado") continua no documento, como C
  assert.ok(
    fd.evidence.some((e) => e.tier === "C" && /already-initialized guard/.test(e.claim)),
    "a leitura da guarda sumiu em vez de virar nível C",
  );
});

test("nenhuma evidência [A] de init/PRNG carrega inferência sob o crachá de fato", () => {
  // Varredura: as marcas abaixo são de opinião (probabilidade, leitura, decisão de relatório).
  // Num claim de nível A elas são exatamente o erro que o PROBLEMA.md proíbe: apresentar C como A.
  const OPINIAO = /\blikely\b|\bprobably\b|\bsuggests\b|\binference\b|is read here as|hence it is reported/i;
  let vistos = 0;
  for (const f of files) {
    const wasm = load(f);
    for (const fd of detectFull(analyzeModule(wasm), wasm).findings) {
      for (const e of fd.evidence) {
        if (e.tier !== "A") continue;
        vistos++;
        assert.ok(!OPINIAO.test(e.claim), `${f}:${fd.entrypoint} — [A] com inferência: ${e.claim}`);
      }
    }
  }
  assert.ok(vistos > 50, `poucas evidências A varridas: ${vistos}`);
});

test("severidade de init: High só sem guarda visível E caminho curto; a regra sai na evidência", (t) => {
  let comGuarda = 0;
  let semGuarda = 0;
  for (const f of files) {
    const wasm = load(f);
    const an = analyzeModule(wasm);
    for (const fd of detectFull(an, wasm).findings.filter((x) => x.class === "initialization-front-running")) {
      const ep = an.entrypoints.find((e) => e.name === fd.entrypoint)!;
      const guarda = ep.reaches.has("has_contract_data");
      const hops = Math.min(
        ...[...STORAGE_WRITE_FNS].map((w) => ep.pathTo.get(w)).filter(Boolean).map((c) => (c as readonly number[]).length - 1),
      );
      const esperada = !guarda && hops <= 2 ? "High" : "Medium";
      assert.equal(fd.severity, esperada, `${f}:${fd.entrypoint} — guarda=${guarda}, ${hops} saltos`);
      // a regra não fica implícita no código: ela é impressa, com os dois valores que a decidiram
      const regra = fd.evidence.find((e) => /Severity rule applied/.test(e.claim));
      assert.ok(regra, `${f}:${fd.entrypoint} — a regra de severidade não aparece na evidência`);
      assert.equal(regra!.tier, "C", "regra de severidade é julgamento, não fato de bytecode");
      assert.match(regra!.claim, new RegExp(`guard reachable = ${guarda ? "yes" : "no"}`));
      assert.ok(regra!.claim.endsWith(`→ ${esperada}.`), `a regra não fecha na severidade: ${regra!.claim}`);
      if (guarda) { comGuarda++; assert.equal(fd.severity, "Medium", "guarda alcançável e ainda High"); }
      else semGuarda++;
    }
  }
  assert.ok(comGuarda > 0, "nenhum init com guarda alcançável no corpus: o caso novo não foi exercitado");
  // O único contrato do corpus original com init sem guarda visível está retido do corpus
  // público (SECURITY.md). Enquanto não houver fixture sintético para o ramo High, este teste
  // só verifica a regra nos casos presentes e registra quantos foram.
  t.diagnostic(`init com guarda: ${comGuarda} · sem guarda: ${semGuarda}`);
});

test("todo achado de init declara a guarda has_contract_data e nunca sai Critical", () => {
  let n = 0;
  for (const f of files) {
    const wasm = load(f);
    for (const fd of detectFull(analyzeModule(wasm), wasm).findings.filter((x) => x.class === "initialization-front-running")) {
      n++;
      assert.notEqual(fd.severity, "Critical", `${f}:${fd.entrypoint} — init com Critical`);
      assert.ok(
        fd.evidence.some((e) => e.tier === "A" && /has_contract_data` IS (NOT )?reachable/.test(e.claim)),
        `${f}:${fd.entrypoint} — sem a alcançabilidade de has_contract_data na evidência`,
      );
    }
  }
  assert.ok(n > 0, "nenhum achado de init no corpus — caso não exercitado");
});

/* ---------- silent-mutation: getter não é entrypoint que muda estado ---------- */

test("silent-mutation não conta getters, e diz quantos excluiu", () => {
  const wasm = load(POOL_ROUTER);
  const fd = detectFull(analyzeModule(wasm), wasm).findings.find((x) => x.class === "silent-mutation")!;
  assert.ok(fd, "silent-mutation sumiu do contrato de referência");
  const listados = fd.evidence.find((e) => e.tier === "A")!.claim;
  for (const g of ["estimate_swap", "gauges_get_reward_info", "get_user_reward"]) {
    assert.ok(!listados.includes(g), `${g} é getter e continua listado como entrypoint que muda estado`);
  }
  const nota = fd.evidence.find((e) => /read-shaped .*excluded/.test(e.claim));
  assert.ok(nota, "exclusão silenciosa: nenhuma evidência diz que getters ficaram de fora");
  assert.match(nota!.claim, /^\d+ read-shaped/, "a nota de exclusão não diz QUANTOS");
  for (const g of ["estimate_swap", "gauges_get_reward_info"]) {
    assert.ok(nota!.claim.includes(g), `${g} excluído mas não listado na nota`);
  }
  // numerador e denominador saem do mesmo conjunto, já sem getters
  const m = fd.title.match(/(\d+) of (\d+)/)!;
  assert.ok(m, `título fora do formato "N of M": ${fd.title}`);
  assert.ok(Number(m[1]) <= Number(m[2]));
});

test("nenhum getter read-shaped aparece na lista de entrypoints que mudam estado, em todo o corpus", () => {
  const getter = /^(get|estimate|quote|preview|view|query|calc|simulate|peek)_/;
  for (const f of files) {
    const wasm = load(f);
    for (const fd of detectFull(analyzeModule(wasm), wasm).findings) {
      if (fd.class !== "silent-mutation" && fd.class !== "archival-risk") continue;
      const listados = fd.evidence.filter((e) => e.tier === "A").map((e) => e.claim).join(" ");
      const nomes = listados.split(/[\s,.:]+/).filter((s) => getter.test(s));
      assert.deepEqual(nomes, [], `${f}: ${fd.class} lista getters como mutadores: ${nomes.join(", ")}`);
    }
  }
});

/* ---------- a frase genérica de PROBLEMA.md não pode sobreviver em lugar nenhum ---------- */

test("nenhum achado do corpus repete a frase genérica de contra-exemplo", () => {
  const GENERICA = "Any address can invoke this and change the contract state";
  let especificas = 0;
  for (const f of files) {
    const wasm = load(f);
    for (const fd of detectFull(analyzeModule(wasm), wasm).findings) {
      for (const e of fd.evidence) {
        assert.ok(!e.claim.includes(GENERICA), `${f}: ${fd.id} ainda usa a frase genérica`);
      }
      const esp = fd.evidence.find((e) => /^Any address can invoke `/.test(e.claim));
      if (!esp) continue;
      especificas++;
      assert.match(esp.claim, new RegExp("Any address can invoke `" + fd.entrypoint + "`"), `${f}: a linha C não nomeia o entrypoint`);
      assert.match(esp.claim, /storage write \(\d+ hops?\)/, `${f}: a linha C não diz quantos saltos`);
      assert.match(esp.claim, /not derivable here/, `${f}: a linha C não declara o limite da afirmação`);
    }
  }
  assert.ok(especificas > 0, "nenhuma linha C específica no corpus — caso não exercitado");
});

/* ---------- AE-7: parse estrito de versão ---------- */

import { cmp, evaluateVersion, parseVersion } from "../src/sdkver.ts";

test("versão não parseável não é comparada: vira lacuna declarada, não achado de advisory", () => {
  for (const v of ["main", "22.0", "sem-versao", "abc"]) {
    assert.equal(parseVersion(v), undefined, `${v} não deveria parsear`);
    assert.equal(evaluateVersion(v).status, "nao-parseavel", `${v} deveria ser lacuna`);
    assert.deepEqual(ids(v), [], `${v} não pode casar advisory nenhum`);
    assert.throws(() => cmp(v, "22.0.9"), /not parseable/, `cmp(${v}) deveria estourar`);
  }
  assert.equal(evaluateVersion(undefined).status, "ausente");
  // `v26.0.0` PARSEIA (prefixo v é aceito) e está fora de toda faixa
  assert.deepEqual(parseVersion("v26.0.0"), { major: 26, minor: 0, patch: 0, prerelease: false });
  assert.equal(evaluateVersion("v26.0.0").status, "avaliada");
  assert.deepEqual(ids("v26.0.0"), [], "v26.0.0 é posterior a toda faixa afetada");
});

test("pré-release vem ANTES da release: 22.0.10-rc.1 não tem o patch de 22.0.10", () => {
  assert.equal(cmp("22.0.10-rc.1", "22.0.10"), -1);
  assert.equal(cmp("22.0.10", "22.0.10-rc.1"), 1);
  assert.equal(cmp("22.0.9", "22.0.10-rc.1"), -1);
  assert.ok(ids("22.0.9").includes(CVE), "22.0.9 é afetada (baseline do caso)");
  assert.ok(ids("22.0.10-rc.1").includes(CVE), "22.0.10-rc.1 é afetada, como 22.0.9");
  assert.ok(!ids("22.0.10").includes(CVE), "22.0.10 é a correção");
  assert.ok(!ids("25.3.0").includes(X2HW), "25.3.0 é a correção (limite superior exclusivo)");
  assert.ok(ids("25.2.999").includes(X2HW), "faixa exclusiva cobre tudo abaixo de 25.3.0");
});

test("faixas codificadas batem com o texto dos advisories, sem número inventado", () => {
  for (const a of ADVISORIES) {
    for (const r of a.affected) {
      assert.ok(parseVersion(r.min) && parseVersion(r.max), `${a.id}: faixa não parseável ${r.min}..${r.max}`);
      assert.equal(typeof r.maxInclusive, "boolean", `${a.id}: faixa sem limite superior declarado`);
    }
  }
});

test("achado de exposição de SDK diz que exposição não é vulnerabilidade, com número de fonte", () => {
  const w = wasmSintetico("22.0.8", ["c.h"]);
  for (const fd of detectFull(analyzeModule(w), w).findings.filter((x) => x.class === "vulnerable-sdk")) {
    const e = fd.evidence.find((x) => /20 verified as not affected/.test(x.claim));
    assert.ok(e, "sem a linha de verificação por fonte");
    assert.equal(e!.tier, "C", "a base rate não é derivada deste binário — não pode sair como A");
    assert.match(e!.claim, /34 corpus contracts.*20 verified.*0 confirmed.*14 without source/s);
  }
});

test("rssdkver ilegível vira lacuna declarada, não achado de advisory", () => {
  const w = wasmSintetico("main", ["a.0"]);
  const fs = detectFull(analyzeModule(w), w).findings;
  assert.equal(fs.filter((x) => x.class === "vulnerable-sdk").length, 0, "versão ilegível não pode gerar achado de advisory");
  const gap = fs.find((x) => x.class === "sdk-version-unparseable")!;
  assert.ok(gap, "lacuna não declarada");
  assert.match(gap.title, /not parseable: main/);
  assert.equal(gap.severity, "Low");
});

/* ---------- AE-8: write-before-auth afirma só o que prova ---------- */

test("write-before-auth titula ordem textual e marca a temporalidade como inferência", () => {
  let n = 0;
  for (const f of files) {
    const wasm = load(f);
    for (const fd of detectFull(analyzeModule(wasm), wasm).findings.filter((x) => x.class === "write-before-auth")) {
      n++;
      assert.match(fd.title, /textual order/, `${f}: título ainda afirma ordem de execução`);
      assert.equal(fd.severity, "Low");
      assert.ok(
        fd.evidence.some((e) => e.tier === "C" && /an inference, not a fact/.test(e.claim)),
        `${f}: temporalidade não declarada como inferência`,
      );
    }
  }
  assert.ok(n > 0, "nenhum write-before-auth no corpus — caso não exercitado");
});

/* ---------- a saída é em inglês ---------- */

test("a supressão por nome de leitura sai em inglês", () => {
  const f = "CA6PUJLBYKZKUEKLZJMKBZLEKP2OTHANDEOWSFF44FTSYLKQPIICCJBE.wasm";
  const wasm = load(f);
  const an = analyzeModule(wasm);

  const en = detectFull(an, wasm);
  assert.ok(en.suppressed.some((s) => /read-shaped name/.test(s.motivo)), "inglês é o padrão");
});

/* ------------------------------------------------------------------ *
 * `contractmetav0` repetida: o `rssdkver` estava sendo perdido.
 *
 * O formato WASM permite repetir o nome de uma custom section, e a toolchain grava uma
 * SEGUNDA `contractmetav0` (com `cliver`) depois da que o `soroban-sdk` grava (com
 * `rssdkver`). `parseModule` guarda as custom sections num `Map` por nome e ficava só com a
 * última; `readSdkMeta` decodificava essa única seção com `xdr.decodeStream` dentro de um
 * `try/catch` que engolia o erro e devolvia o mapa parcial. Resultado medido sobre os 25
 * code hashes mais invocados da mainnet: os 25 declaram `rssdkver`, a ferramenta lia 14 e
 * dizia "ausente" em 11 — perdendo 6 achados `vulnerable-sdk`, um deles no pool de
 * empréstimo mais movimentado.
 *
 * As duas seções abaixo são os bytes REAIS de um desses binários (rank 25 do censo). São só
 * strings de metadado de build — `rsver`, `rssdkver`, `cliver` — sem contract id nem
 * qualquer identificador do projeto.
 * ------------------------------------------------------------------ */

/** `contractmetav0` #1: rsver + rssdkver = 21.7.7 (faixa do CVE-2026-26267). */
const META_RSSDKVER =
  "0000000000000005727376657200000000000006312e38382e300000000000000000000872" +
  "7373646b7665720000002f32312e372e37233564613738396335306231386134633262653533333934313338323132666564353666306466633400";
/** `contractmetav0` #2: só `cliver` — a seção que sobrescrevia a primeira no Map. */
const META_CLIVER = "0000000000000006636c6976657200000000000732332e322e302300";

/** WASM mínimo com N custom sections `contractmetav0`, nos bytes dados, na ordem dada. */
function wasmComMetas(...hexes: string[]): Uint8Array {
  const leb = (n: number) => { const o: number[] = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; o.push(b); } while (n); return o; };
  const str = (s: string) => { const b = [...Buffer.from(s)]; return [...leb(b.length), ...b]; };
  const bytes: number[] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  bytes.push(1, ...leb(4), 1, 0x60, 0, 0);
  for (const h of hexes) {
    const body = [...str("contractmetav0"), ...Buffer.from(h, "hex")];
    bytes.push(0, ...leb(body.length), ...body);
  }
  return new Uint8Array(bytes);
}

test("rssdkver é lido mesmo quando uma segunda contractmetav0 vem depois", () => {
  const sozinha = readSdkMeta(wasmComMetas(META_RSSDKVER));
  assert.equal(sozinha.version, "21.7.7");
  assert.equal(sozinha.commit, "5da789c50b18a4c2be53394138212fed56f0dfc4");
  assert.equal(sozinha.partial, false);

  // O caso que se perdia: a segunda seção existe e não tem `rssdkver`.
  const duas = readSdkMeta(wasmComMetas(META_RSSDKVER, META_CLIVER));
  assert.equal(duas.version, "21.7.7", "a segunda contractmetav0 apagava a primeira");
  assert.equal(duas.raw.cliver, "23.2.0#", "as duas seções precisam ser fundidas, não escolhidas");
  assert.equal(duas.raw.rsver, "1.88.0");
  assert.equal(duas.partial, false);
  assert.equal(duas.present, true);

  // …e o achado de advisory que dependia dela volta a sair.
  assert.ok(ids(duas.version).includes(CVE), "21.7.7 está na faixa do CVE-2026-26267");
});

test("readSdkMeta distingue ausente, não-parseável (decode parcial) e avaliada", () => {
  // (1) nenhuma seção: ausente
  const semSecao = readSdkMeta(wasmComMetas());
  assert.equal(semSecao.present, false);
  assert.equal(semSecao.partial, false);
  assert.equal(evaluateVersion(semSecao).status, "ausente");

  // (2) seção completa, sem `rssdkver`: ausente de verdade — declarou e não tem
  const soCliver = readSdkMeta(wasmComMetas(META_CLIVER));
  assert.equal(soCliver.present, true);
  assert.equal(soCliver.partial, false);
  assert.equal(evaluateVersion(soCliver).status, "ausente");

  // (3) seção truncada ANTES do `rssdkver`: não-parseável, não "ausente". Confundir os dois
  //     é afirmar ausência de exposição a partir de uma falha nossa de parse.
  const truncada = META_RSSDKVER.slice(0, 2 * 40) + "ffffffff";
  const parcial = readSdkMeta(wasmComMetas(truncada));
  assert.equal(parcial.version, undefined);
  assert.equal(parcial.partial, true, "decode interrompido precisa ficar registrado");
  assert.equal(typeof parcial.partialAt, "number");
  const ev = evaluateVersion(parcial);
  assert.equal(ev.status, "nao-parseavel");
  assert.match((ev as { raw: string }).raw, /contractmetav0/);

  // (4) versão presente e legível
  assert.equal(evaluateVersion(readSdkMeta(wasmComMetas(META_RSSDKVER))).status, "avaliada");
});

test("decode parcial do contractmetav0 vira lacuna declarada, e não silêncio", () => {
  const w = wasmComMetas(META_RSSDKVER.slice(0, 2 * 40) + "ffffffff");
  const fs = detectFull(analyzeModule(w), w).findings;
  const gap = fs.find((x) => x.class === "sdk-version-unparseable");
  assert.ok(gap, "seção ilegível saiu sem lacuna declarada — é o silêncio que perdeu 6 achados");
  assert.equal(gap!.severity, "Low");
  assert.equal(fs.filter((x) => x.class === "vulnerable-sdk").length, 0, "sem versão não há advisory");
});

/* ---------- silent-mutation: severidade pela CLASSE da ação silenciosa ---------- */

/** Tem `upgrade` entre os entrypoints mudos — o caso que saía Medium pela fração. */
const SILENT_UPGRADE = "CACMENFFJPJMSDAJQLX4R7K3SFZIW2LJSE3R2UMLGSWHFHS353FVXAZV.wasm";
/** Só entrypoints com nome de init entre os mudos — one-shot, o ramo Low. */
const SILENT_SO_INIT = "CAM7DY53G63XA4AJRS24Z6VFYAFSSF76C3RZ45BE5YU3FQS5255OOABP.wasm";

test("silent-mutation: severidade vem da classe da ação silenciosa, não da fração", () => {
  const wasm = load(SILENT_UPGRADE);
  const an = analyzeModule(wasm);
  const fd = detectFull(an, wasm).findings.find((x) => x.class === "silent-mutation")!;
  assert.ok(fd, "o caso perdeu o achado de silent-mutation");
  const m = fd.title.match(/(\d+) of (\d+)/)!;
  assert.notEqual(m[1], m[2], "o caso perdeu o pressuposto: a fração é 1 e a regra antiga já daria High");
  assert.equal(fd.severity, "High", "entrypoint mudo que troca o próprio código tem que sair High");
  // o decisor aparece nomeado, em nível A, e a regra em nível C
  const dec = fd.evidence.find((e) => e.tier === "A" && /listed first above/.test(e.claim))!;
  assert.ok(dec, "os entrypoints decisores não saem em fato A");
  assert.match(dec.claim, /upgrade/, "o entrypoint que decidiu a severidade não é nomeado");
  const regra = fd.evidence.find((e) => /Severity rule applied \(class of the silent action/.test(e.claim))!;
  assert.ok(regra, "a regra de severidade não é impressa");
  assert.equal(regra.tier, "C", "regra de severidade é julgamento, não fato de bytecode");
  assert.ok(regra.claim.endsWith("→ High."), `a regra não fecha na severidade: ${regra.claim}`);
  // e os decisores vêm PRIMEIRO na lista A de entrypoints mudos
  const lista = fd.evidence.find((e) => e.tier === "A" && /do not reach contract_event/.test(e.claim))!.claim;
  const nomes = lista.replace(/^.*contract_event: /, "").replace(/\.$/, "").split(", ");
  const decisores = dec.claim.replace(/^.*listed first above\): /, "").replace(/\.$/, "").split(", ");
  assert.deepEqual(nomes.slice(0, decisores.length), decisores, "os decisores não abrem a lista de nível A");
});

test("silent-mutation: só entrypoints com nome de init entre os mudos sai Low", () => {
  const wasm = load(SILENT_SO_INIT);
  const fd = detectFull(analyzeModule(wasm), wasm).findings.find((x) => x.class === "silent-mutation")!;
  assert.ok(fd, "o caso perdeu o achado de silent-mutation");
  assert.equal(fd.severity, "Low");
  const lista = fd.evidence.find((e) => e.tier === "A" && /do not reach contract_event/.test(e.claim))!.claim;
  for (const n of lista.replace(/^.*contract_event: /, "").replace(/\.$/, "").split(", ")) {
    assert.match(n, /^(initialize|init|setup|bootstrap)(_|$)/i, `${n} não tem nome de init e o achado saiu Low`);
  }
  assert.ok(
    fd.evidence.some((e) => e.tier === "C" && /every silent entrypoint is init-shaped/.test(e.claim)),
    "a regra não declara por que o achado é Low",
  );
});

test("silent-mutation, em todo o corpus: High se e só se há decisor; nunca High por fração", () => {
  const ADMIN = /^(set_admin|transfer_admin|propose_admin|accept_admin|set_owner|transfer_ownership|upgrade|set_permission|grant|revoke|set_.*role|add_signer|remove_signer|update_signer|pause|unpause|kill|set_fee|set_.*config)(_|$)/i;
  let alto = 0;
  for (const f of files) {
    const wasm = load(f);
    const an = analyzeModule(wasm);
    for (const fd of detectFull(an, wasm).findings.filter((x) => x.class === "silent-mutation")) {
      const lista = fd.evidence.find((e) => e.tier === "A" && /do not reach contract_event/.test(e.claim))!.claim;
      const mudos = lista.replace(/^.*contract_event: /, "").replace(/\.$/, "").split(", ");
      const decisores = mudos.filter((n) => {
        const ep = an.entrypoints.find((e) => e.name === n)!;
        return canUpgradeSelf(ep) || ADMIN.test(n);
      });
      const esperada = decisores.length ? "High" : mudos.every((n) => /^(initialize|init|setup|bootstrap)(_|$)/i.test(n)) ? "Low" : "Medium";
      assert.equal(fd.severity, esperada, `${f}: mudos=${mudos.length}, decisores=${decisores.length}`);
      if (fd.severity === "High") alto++;
      // a regra sai SEMPRE, com a severidade no fim
      const regra = fd.evidence.find((e) => /Severity rule applied \(class of the silent action/.test(e.claim))!;
      assert.ok(regra && regra.tier === "C", `${f}: silent-mutation sem a regra em nível C`);
      assert.ok(regra.claim.endsWith(`→ ${fd.severity}.`), `${f}: regra não fecha na severidade`);
    }
  }
  assert.ok(alto > 0, "nenhum silent-mutation High no corpus — o ramo novo não foi exercitado");
});

/* ---------- third-party-state-tampering: Tamper no lugar de Elevation ---------- */

/** `deposit`/`swap`/`withdraw(to: Address)` permissionless — par estilo V2. */
const TAMPER_PAR = "CAM7DY53G63XA4AJRS24Z6VFYAFSSF76C3RZ45BE5YU3FQS5255OOABP.wasm";

test("escritor sem auth que recebe Address no spec vira UM achado de Tamper, não de Elevation", () => {
  const wasm = load(TAMPER_PAR);
  const an = analyzeModule(wasm);
  const fs = detectFull(an, wasm).findings.filter((x) => x.class === "third-party-state-tampering");
  assert.ok(fs.length > 0, "o caso perdeu os achados de tampering");
  for (const fd of fs) {
    assert.equal(fd.stride, "Tamper", "a letra do STRIDE tem que ser Tamper");
    assert.equal(fd.severity, "Medium", "tampering de terceiro sai Medium, não Critical/High");
    assert.equal(fd.family, "auth");
    // o parâmetro que sustenta a classe é nomeado, em nível A
    const p = fd.evidence.find((e) => e.tier === "A" && /contractspecv0.*address parameter/.test(e.claim))!;
    assert.ok(p, `${fd.entrypoint}: sem o fato A do parâmetro de endereço`);
    assert.match(p.claim, new RegExp("`" + fd.entrypoint + "`"), "o fato não nomeia o entrypoint");
    // e a ressalva de taint é obrigatória — é o que impede afirmar o que o bytecode não mostra
    assert.ok(
      fd.evidence.some((e) => e.tier === "C" && /taint from the parameter to the storage key/.test(e.claim)),
      `${fd.entrypoint}: sem a ressalva C de taint`,
    );
    // não pode haver o achado de Elevation do mesmo entrypoint: é UM achado, não dois
    assert.ok(
      !detectFull(an, wasm).findings.some((x) => x.entrypoint === fd.entrypoint && x.class === "unauthenticated-state-mutation"),
      `${fd.entrypoint}: saiu nas DUAS classes`,
    );
  }
});

test("tampering, em todo o corpus: só onde não há auth, há escrita e o spec declara Address", () => {
  let n = 0;
  for (const f of files) {
    const wasm = load(f);
    const an = analyzeModule(wasm);
    const spec = lerSpec(wasm);
    for (const fd of detectFull(an, wasm).findings.filter((x) => x.class === "third-party-state-tampering")) {
      n++;
      const ep = an.entrypoints.find((e) => e.name === fd.entrypoint)!;
      assert.equal(requiresAuth(ep), false, `${f}:${fd.entrypoint} alcança auth e foi reportado como tampering`);
      assert.equal(writesStorage(ep), true, `${f}:${fd.entrypoint} não alcança escrita`);
      assert.ok((spec?.addressParams.get(fd.entrypoint) ?? []).length > 0, `${f}:${fd.entrypoint} sem Address no spec`);
      assert.ok(!/^(initialize|init|setup|bootstrap)(_|$)/i.test(fd.entrypoint), `${f}:${fd.entrypoint} é init e devia ser front-running`);
      assert.equal(fd.severity, "Medium");
    }
  }
  assert.ok(n > 0, "nenhum tampering no corpus — a classe nova não foi exercitada");
});

test("as supressões continuam valendo para a classe nova", () => {
  for (const f of files) {
    const wasm = load(f);
    const r = detectFull(analyzeModule(wasm), wasm);
    const tampering = new Set(r.findings.filter((x) => x.class === "third-party-state-tampering").map((x) => x.entrypoint));
    for (const s of r.suppressed) {
      assert.ok(!tampering.has(s.entrypoint), `${f}: ${s.entrypoint} foi suprimido e reportado como tampering`);
    }
    for (const ep of tampering) assert.ok(!ep.startsWith("__"), `${f}: ${ep} é reservada e virou tampering`);
  }
});

/* ---------- self-implemented-signature-verification: a letra S deixa de ser lacuna ---------- */

/** Verificador estilo EIP-712 dentro do contrato: domain hash, type hash, nonce. */
const SIG_EIP712 = "CCG5EWFY2KCWWYYEIUMIRG6WSAQFLDR5QE5FMCWY25N36XA5GYTCPQWR.wasm";
/** Conta inteligente: alcança de fato as host functions de verificação. */
const SIG_CRYPTO = "CDZK3J2WHJZCOBYQGSZLO5A5JQPBME7FS7XUUOXLH6ZXJI54OI7VGKL2.wasm";

test("spec com domain/type hash e nonce vira achado de Spoof, não lacuna", () => {
  const wasm = load(SIG_EIP712);
  const fs = detectFull(analyzeModule(wasm), wasm).findings.filter((x) => x.class === "self-implemented-signature-verification");
  assert.equal(fs.length, 1, "um fato do contrato, um achado");
  const [fd] = fs;
  assert.equal(fd.stride, "Spoof");
  assert.equal(fd.severity, "Medium");
  assert.equal(fd.entrypoint, "<contrato>");
  assert.equal(fd.family, "sig");
  const simbolos = fd.evidence.find((e) => e.tier === "A" && /Spec symbols matching/.test(e.claim))!;
  assert.ok(simbolos, "os símbolos casados não saem em fato A");
  for (const s of ["get_domain_type_hash", "get_nonce"]) {
    assert.ok(simbolos.claim.includes(s), `${s} sumiu da evidência A`);
  }
  assert.ok(
    fd.evidence.some((e) => e.tier === "C" && /outside the host's `require_auth` framework/.test(e.claim)),
    "sem a linha C que manda revisar o verificador",
  );
  // a letra S deixa de ser lacuna neste contrato
  assert.ok(!lacunas(detectFull(analyzeModule(wasm), wasm).findings).includes("Spoof"), "Spoof continua declarada como lacuna");
});

test("achado de assinatura própria cita as host functions de cripto que alcança", () => {
  const wasm = load(SIG_CRYPTO);
  const an = analyzeModule(wasm);
  const fd = detectFull(an, wasm).findings.find((x) => x.class === "self-implemented-signature-verification")!;
  assert.ok(fd, "o caso perdeu o achado de assinatura própria");
  const cripto = fd.evidence.find((e) => e.tier === "A" && /reach crypto host functions/.test(e.claim))!;
  assert.ok(cripto, "as host functions de cripto não saem em fato A");
  for (const n of cripto.claim.replace(/^.*host functions: /, "").replace(/\.$/, "").split(", ")) {
    assert.ok(SIG_SCHEME_FNS.has(n), `${n} não é host function do recorte de esquema de assinatura`);
    assert.ok(an.entrypoints.some((e) => e.reaches.has(n)), `${n} citado mas não alcançável de nenhum export`);
  }
});

test("assinatura própria só dispara com cripto alcançável OU casamento forte (≥2 símbolos)", () => {
  let n = 0;
  for (const f of files) {
    const wasm = load(f);
    const an = analyzeModule(wasm);
    for (const fd of detectFull(an, wasm).findings.filter((x) => x.class === "self-implemented-signature-verification")) {
      n++;
      const cripto = fd.evidence.find((e) => /reach crypto host functions/.test(e.claim));
      const fraco = fd.evidence.find((e) => /No crypto host function is reachable/.test(e.claim));
      assert.ok(cripto || fraco, `${f}: achado sem declarar se há cripto alcançável`);
      if (fraco) {
        const k = Number(/rests on (\d+) spec symbol/.exec(fraco.claim)![1]);
        assert.ok(k >= 2, `${f}: achado sem cripto e com um único símbolo (${k})`);
      }
      assert.equal(fd.severity, "Medium", `${f}: achado de Spoof com severidade ${fd.severity}`);
    }
  }
  assert.ok(n > 0, "nenhum achado de assinatura própria no corpus — a classe nova não foi exercitada");
});

/* ---------- archival-risk: Medium com a lacuna de durabilidade declarada ---------- */

test("archival-risk é Medium e declara que o impacto depende da durabilidade", () => {
  let n = 0;
  for (const f of files) {
    const wasm = load(f);
    for (const fd of detectFull(analyzeModule(wasm), wasm).findings.filter((x) => x.class === "archival-risk")) {
      n++;
      assert.equal(fd.stride, "DoS", "a letra continua sendo DoS");
      assert.equal(fd.severity, "Medium", `${f}: archival-risk com ${fd.severity} — severidade por ausência`);
      assert.equal(fd.family, "ttl");
      const dur = fd.evidence.find((e) => /Declared gap on the impact/.test(e.claim));
      assert.ok(dur, `${f}: sem a linha de durabilidade`);
      assert.equal(dur!.tier, "C", "a leitura de impacto por durabilidade não é fato de bytecode");
      for (const p of ["restore footprint", "temporary entry is lost", "instance entry"]) {
        assert.ok(dur!.claim.includes(p), `${f}: a linha de durabilidade não cobre "${p}"`);
      }
      assert.match(dur!.claim, /not read from the bytecode here/, `${f}: a lacuna não é declarada`);
    }
  }
  assert.ok(n > 0, "nenhum archival-risk no corpus — caso não exercitado");
});

/* ---------- Finding.family: agregação futura por família ---------- */

test("todo achado do corpus carrega uma família conhecida", () => {
  const FAMILIAS = new Set(["init", "auth", "upgrade", "order", "silent", "ttl", "prng", "sig", "sdk"]);
  const porClasse = new Map<string, Set<string>>();
  for (const f of files) {
    const wasm = load(f);
    for (const fd of detectFull(analyzeModule(wasm), wasm).findings) {
      assert.ok(fd.family, `${f}: ${fd.class} sem família`);
      assert.ok(FAMILIAS.has(fd.family!), `${f}: família desconhecida ${fd.family}`);
      porClasse.set(fd.class, (porClasse.get(fd.class) ?? new Set()).add(fd.family!));
    }
  }
  // a família é do achado, não do contrato: uma classe não pode oscilar de família
  for (const [c, fams] of porClasse) assert.equal(fams.size, 1, `${c} aparece em ${[...fams].join("/")}`);
});
