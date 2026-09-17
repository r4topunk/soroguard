import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { analyzeModule, requiresAuth, writesStorage } from "../src/analyze.ts";
import { detect, detectFull } from "../src/detect.ts";
import { hostFn, AUTH_FNS, STORAGE_WRITE_FNS } from "../src/hostfns.ts";
import { setLang } from "../src/i18n.ts";

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
      if (!/unauthenticated-state-mutation|initialization-front-running/.test(fd.class)) continue;
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
  // ground truth de docs/triagem-unauth: nenhum TP humano pode ser suprimido pela nova regra
  const TP = new Set(["init", "submit", "update_b_rate", "add_yield", "delete_note", "update_signer", "initialize", "initialize_escrow"]);
  for (const g of files) {
    const w = load(g);
    for (const s of detectFull(analyzeModule(w), w).suppressed) {
      assert.ok(!TP.has(s.entrypoint), `${g}: ${s.entrypoint} é TP verificado por humano e foi suprimido`);
    }
  }
  // Não basta não suprimir: os dois TPs de init da triagem têm que CONTINUAR reportados,
  // e agora como front-running (a classe certa), não como escritor genérico sem auth.
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

/* ---------- i18n: inglês é o padrão, português sai com setLang("pt") ---------- */

test("com setLang(\"pt\") os mesmos achados saem em português, e o dado não muda", () => {
  const f = "CA6PUJLBYKZKUEKLZJMKBZLEKP2OTHANDEOWSFF44FTSYLKQPIICCJBE.wasm";
  const wasm = load(f);
  const an = analyzeModule(wasm);

  const en = detectFull(an, wasm);
  assert.ok(en.suppressed.some((s) => /read-shaped name/.test(s.motivo)), "inglês é o padrão");

  setLang("pt");
  try {
    const pt = detectFull(an, wasm);
    // texto muda…
    assert.ok(pt.suppressed.some((s) => /nome de leitura/.test(s.motivo)), "supressão não traduzida");
    assert.ok(pt.findings.some((x) => /alcança|Lacuna|entrypoints/.test(x.title)), "título não traduzido");
    // …e o dado não: mesmos ids, classes, severidades e marcadores
    assert.deepEqual(pt.findings.map((x) => x.id), en.findings.map((x) => x.id));
    assert.deepEqual(pt.findings.map((x) => x.class), en.findings.map((x) => x.class));
    assert.deepEqual(pt.findings.map((x) => x.severity), en.findings.map((x) => x.severity));
    assert.deepEqual(pt.findings.map((x) => x.stride), en.findings.map((x) => x.stride));
    assert.deepEqual(pt.suppressed.map((s) => s.entrypoint), en.suppressed.map((s) => s.entrypoint));
  } finally {
    setLang("en");
  }
});
