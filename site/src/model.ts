import { STRINGS, type Lang } from "./strings";

// Port of Landing.dc.html renderVals(): pure function of state -> everything the sections render.
// Style values stay as CSS strings (converted by sx() at the call site) to keep the port 1:1.

export type Bi = { pt: string; en: string };

export interface State {
  lang: Lang;
  fn: string;
  tier: string;
  out: string;
  tab: string;
  copied: boolean;
}

export interface Actions {
  pickCopy: () => void;
}

interface FnDef {
  on: string[];
  miss: string[];
  cls: "ok" | "bad" | "sup" | "ro";
  token: string;
  tokenStyle: string;
  title: Bi;
  lines: [string, Bi][];
  note: Bi;
}

interface TierDef {
  k: string;
  soft: string;
  fg: string;
  name: Bi;
  desc: Bi;
  claim: Bi;
  why: Bi;
}

interface OutDef {
  side: "tm" | "mp";
  id: string;
  sub: Bi;
  toks: string[];
  link?: string;
  token?: string;
  tokenStyle?: string;
  cls?: "ok" | "sup" | "bad";
  title?: Bi;
  what?: Bi;
  watch?: Bi;
  lines?: [string, Bi][];
  todo?: Bi[];
}
type OutDetail = Required<Omit<OutDef, "link">> & { link?: string };

interface Wire {
  d: string;
  len: string;
  cls: string;
  color: string;
  width: string;
  dash: string;
  marker: string;
}
interface Mark {
  cx: string;
  cy: string;
  fill: string;
  stroke: string;
  glyph: string;
}
interface Label {
  y: string;
  text: string;
  color: string;
}
interface CodeLine {
  pre: string;
  preStyle: string;
  text: string;
  textStyle: string;
}
interface TabDef {
  label: string;
  lines: CodeLine[];
  note: string;
}

export function computeVals(state: State, setState: (patch: Partial<State>) => void, actions: Actions) {
  const L: Lang = state.lang;
  const pt = L === "pt";
  const t = STRINGS[L];
  const tx = (o: Bi): string => (pt ? o.pt : o.en);
  const set =
    <K extends keyof State>(k: K, v: State[K]) =>
    () =>
      setState({ [k]: v } as Pick<State, K>);

  const TEAL = "#0B6B69",
    TEAL_INK = "#0A5E5C",
    TEAL_T = "#DDEFEC";
  const CORAL = "#C4552B",
    CORAL_INK = "#9E3A15",
    CORAL_T = "#FBEAE2";
  const AMBER = "#A66F0A",
    AMBER_INK = "#855300",
    AMBER_T = "#F6ECD4";
  const COBALT = "#4760B5",
    COBALT_INK = "#34509E",
    COBALT_T = "#E4E9F6";
  const INK = "#13201F",
    MUTED = "#5E6B6A",
    LINE = "#E3E8E7";
  const MONO = "'Geist Mono', ui-monospace, Menlo, monospace";

  const tok = (fg: string, bg: string, extra?: string): string =>
    "display: inline-grid; place-items: center; flex: none; min-width: 28px; height: 28px; padding: 0 9px; box-sizing: border-box; border-radius: 10px; font-family: " +
    MONO +
    "; font-size: 13px; font-weight: 500; white-space: nowrap; color: " +
    fg +
    "; background: " +
    bg +
    ";" +
    (extra || "");
  const TIERTOK: Record<string, string> = {
    A: tok(TEAL_INK, TEAL_T),
    B: tok(AMBER_INK, AMBER_T),
    C: tok(COBALT_INK, COBALT_T),
    L: tok(MUTED, "#FFFFFF", " box-shadow: inset 0 0 0 1.5px #AEB8B6;"),
    P: tok(MUTED, "#EEF1F0"),
  };
  const TIERLINE: Record<string, { color: string; dash: string; width: string }> = {
    A: { color: TEAL, dash: "none", width: "2.6" },
    B: { color: AMBER, dash: "7 5", width: "2.6" },
    C: { color: COBALT, dash: "0.1 6", width: "3" },
    L: { color: "#8E9A98", dash: "3 5", width: "1.6" },
  };

  // ---------- language toggle ----------
  const seg = (on: boolean, pad?: number): string =>
    "display: inline-flex; align-items: center; justify-content: center; min-height: 44px; min-width: 44px; padding: 0 " +
    (pad || 12) +
    "px; border: 0; border-radius: 999px; cursor: pointer; font-size: 14.5px; font-weight: 500; transition: background .18s ease, color .18s ease, box-shadow .18s ease; " +
    (on
      ? "background: #FFFFFF; color: " + INK + "; box-shadow: 0 1px 2px rgba(19,32,31,0.08);"
      : "background: transparent; color: #4F5C5B;");
  const langs = (
    [
      ["pt", "PT"],
      ["en", "EN"],
    ] as const
  ).map(([k, label]) => ({
    label,
    pick: set("lang", k),
    pressed: L === k,
    style: seg(L === k, 10),
  }));

  // ---------- keycap command ----------
  const copied = state.copied === true;
  const capsule =
    "margin-top: 40px; display: inline-flex; align-items: center; flex-wrap: wrap; justify-content: center; gap: 18px; max-width: 100%; box-sizing: border-box; padding: 12px 12px 12px 14px; border: 0; cursor: pointer; border-radius: 26px; background: #FFFFFF; " +
    (copied
      ? "transform: translateY(4px); box-shadow: 0 1px 0 #D5DCDA, 0 0 0 4px " + TEAL_T + ", 0 8px 18px -12px rgba(11,107,105,0.35);"
      : "box-shadow: inset 0 -1px 0 #E6EBEA, 0 5px 0 #D9E0DE, 0 26px 44px -26px rgba(11,107,105,0.45);");
  const copyKey =
    "display: inline-flex; align-items: center; gap: 8px; height: 48px; padding: 0 18px; border-radius: 16px; font-size: 15px; font-weight: 500; transition: background .15s ease, color .15s ease; " +
    (copied ? "background: " + TEAL + "; color: #FFFFFF;" : "background: #F2F4F3; color: " + INK + ";");
  // ---------- explorer (mainnet escrow CDZZ5HUO…742T5) ----------
  const FN: Record<string, FnDef> = {
    initialize_escrow: {
      on: ["writes", "event", "call"],
      miss: ["auth"],
      cls: "bad",
      token: "Elevation.1 · Medium",
      tokenStyle: tok(CORAL_INK, CORAL_T),
      title: { pt: "Inicialização sem autorização", en: "Initialization without authorization" },
      lines: [
        [
          "A",
          {
            pt: "Não alcança require_auth: nenhum caminho no binário chega à checagem de assinatura.",
            en: "Does not reach require_auth: no path in the binary leads to a signature check.",
          },
        ],
        [
          "P",
          {
            pt: "Uma escrita de estado é alcançável a 2 saltos (caminho possível).",
            en: "A storage write is reachable 2 hops away (possible path).",
          },
        ],
        [
          "C",
          {
            pt: "has_contract_data parece guarda de “já inicializado”, e o contrato exporta __constructor. O risco que sobra é front-running dessa etapa: Medium, não High.",
            en: "has_contract_data looks like an already-initialized guard, and the contract exports __constructor. The remaining risk is front-running of that stage: Medium, not High.",
          },
        ],
      ],
      note: { pt: "", en: "" },
    },
    fund_escrow: {
      on: ["auth", "event", "call"],
      miss: [],
      cls: "ok",
      token: pt ? "sem achado" : "no finding",
      tokenStyle: tok(TEAL_INK, TEAL_T),
      title: { pt: "Assinatura no caminho antes de mover fundos", en: "A signature check on the way to moving funds" },
      lines: [
        [
          "P",
          {
            pt: "require_auth, contract_event e call são alcançáveis (caminhos possíveis).",
            en: "require_auth, contract_event and call are reachable (possible paths).",
          },
        ],
      ],
      note: {
        pt: "Nenhum achado. Alcançar não prova que a checagem sempre roda; por isso não vira afirmação tier A.",
        en: "No finding. Reaching does not prove the check always runs, so it is not stated as a tier A claim.",
      },
    },
    release_milestone_funds: {
      on: ["auth", "writes", "event", "call"],
      miss: [],
      cls: "ok",
      token: pt ? "sem achado" : "no finding",
      tokenStyle: tok(TEAL_INK, TEAL_T),
      title: { pt: "Libera pagamento com assinatura no caminho", en: "Releases payment with a signature check on the path" },
      lines: [
        ["P", { pt: "Os quatro botões são alcançáveis (caminhos possíveis).", en: "All four buttons are reachable (possible paths)." }],
      ],
      note: {
        pt: "Nenhum achado. O evento declarado no contrato vira o filtro que o monitor escuta.",
        en: "No finding. The event declared in the contract becomes the filter the monitor listens to.",
      },
    },
    __constructor: {
      on: [],
      miss: [],
      cls: "sup",
      token: pt ? "suprimida" : "suppressed",
      tokenStyle: tok(MUTED, "#FFFFFF", " box-shadow: inset 0 0 0 1.5px #AEB8B6;"),
      title: { pt: "Roda uma vez, no deploy", en: "Runs once, at deploy" },
      lines: [],
      note: {
        pt: "Não pode ser chamada depois (CAP-0058). Sai da lista de ameaças, mas fica registrada com o motivo: supressão nunca é silenciosa.",
        en: "It cannot be called afterwards (CAP-0058). It leaves the threat list but is recorded with its reason: suppression is never silent.",
      },
    },
    get_escrow: {
      on: [],
      miss: [],
      cls: "ro",
      token: pt ? "só leitura" : "read-only",
      tokenStyle: tok(MUTED, "#E9EDEC"),
      title: { pt: "Só leitura", en: "Read-only" },
      lines: [["A", { pt: "Não alcança nenhuma host function com efeito.", en: "Does not reach any host function with an effect." }]],
      note: { pt: "Não gera ameaça.", en: "No threat." },
    },
  };
  const DOT: Record<string, string> = {
    ok: "background: " + TEAL + ";",
    bad: "background: " + CORAL + ";",
    sup: "border: 1.5px dashed #8E9A98; box-sizing: border-box;",
    ro: "background: #B9C3C1;",
  };
  const fk = FN[state.fn] ? state.fn : "initialize_escrow";
  const fns = Object.keys(FN).map((name) => {
    const on = fk === name;
    return {
      name,
      pick: set("fn", name),
      pressed: on,
      dot: "flex: none; width: 9px; height: 9px; border-radius: 50%; " + DOT[FN[name].cls],
      style:
        "display: flex; justify-content: space-between; align-items: center; gap: 12px; width: 100%; min-height: 50px; padding: 0 14px; border: 0; border-radius: 16px; cursor: pointer; text-align: left; transition: background .18s ease, box-shadow .18s ease, color .18s ease; " +
        (on
          ? "background: #FFFFFF; color: " + INK + "; box-shadow: 0 1px 2px rgba(19,32,31,0.06), 0 6px 16px -10px rgba(19,52,50,0.25);"
          : "background: transparent; color: #4F5C5B;"),
    };
  });

  const f = FN[fk];
  const HOSTS: [string, string, string, string][] = [
    ["auth", "require_auth", t.hAuth, "M7 11V8a5 5 0 0 1 10 0v3 M5 11h14v9H5z"],
    [
      "writes",
      "put_contract_data",
      t.hWrite,
      "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3z M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6 M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
    ],
    ["event", "contract_event", t.hEvent, "M6 9a6 6 0 0 1 12 0c0 6 3 8 3 8H3s3-2 3-8 M10.3 21a1.9 1.9 0 0 0 3.4 0"],
    ["call", "call", t.hCall, "M7 17L17 7 M8 7h9v9"],
  ];
  const chips = HOSTS.map(([key, fn, sub, icon]) => {
    const on = f.on.indexOf(key) !== -1,
      miss = f.miss.indexOf(key) !== -1;
    const base =
      "display: flex; align-items: center; gap: 14px; min-height: 72px; padding: 12px 14px 12px 12px; box-sizing: border-box; border-radius: 20px; transition: background .22s ease, box-shadow .22s ease, color .22s ease; ";
    const wrap =
      "display: grid; place-items: center; flex: none; width: 44px; height: 44px; border-radius: 14px; transition: background .22s ease; ";
    const pill = "flex: none; padding: 5px 10px; border-radius: 999px; font-size: 13px; font-weight: 500; ";
    if (miss)
      return {
        fn,
        sub,
        icon,
        state: t.stMiss,
        style: base + "background: " + CORAL_T + "; color: " + CORAL_INK + "; box-shadow: inset 0 0 0 1px #F1CDBE;",
        iconWrap: wrap + "background: #FFFFFF; color: " + CORAL + ";",
        stateStyle: pill + "background: #FFFFFF; color: " + CORAL_INK + ";",
      };
    if (on)
      return {
        fn,
        sub,
        icon,
        state: t.stReach,
        style: base + "background: #EEF1F0; color: " + INK + ";",
        iconWrap: wrap + "background: #FFFFFF; color: " + INK + ";",
        stateStyle: pill + "background: #FFFFFF; color: #33403F;",
      };
    return {
      fn,
      sub,
      icon,
      state: t.stNot,
      style: base + "background: #FFFFFF; color: " + MUTED + "; box-shadow: inset 0 0 0 1px " + LINE + ";",
      iconWrap: wrap + "background: #F2F4F3; color: #7C8887;",
      stateStyle: pill + "background: transparent; color: " + MUTED + ";",
    };
  });

  const PANEL: Record<string, string> = { bad: "#FDF3EF", ok: "#F2F6F5", sup: "#F2F4F3", ro: "#F2F4F3" };
  const nOn = f.on.length;
  const cur = {
    name: fk,
    verb: nOn > 0 ? t.verbReach + " " + nOn + " " + t.of4 : t.verbNone,
    token: f.token,
    tokenStyle: f.tokenStyle,
    title: tx(f.title),
    note: tx(f.note),
    lines: f.lines.map(([tier, text]) => ({ tier: tier === "P" ? t.possible : tier, text: tx(text), tokenStyle: TIERTOK[tier] })),
    panel:
      "display: flex; flex-direction: column; gap: 12px; padding: 20px 22px; border-radius: 22px; min-height: 150px; box-sizing: border-box; transition: background .22s ease; background: " +
      PANEL[f.cls] +
      ";",
  };

  // ---------- evidence tiers ----------
  const TIERS: Record<string, TierDef> = {
    A: {
      k: "A",
      soft: TEAL_T,
      fg: TEAL_INK,
      name: { pt: "Fato do bytecode", en: "Bytecode fact" },
      desc: { pt: "Reproduzível por qualquer pessoa no mesmo WASM.", en: "Anyone gets the same result from the same WASM." },
      claim: { pt: "initialize_escrow não alcança require_auth.", en: "initialize_escrow does not reach require_auth." },
      why: {
        pt: "Nenhum caminho no grafo de chamadas do binário chega à checagem de assinatura, e uma negativa assim é prova. Se houver call_indirect no caminho, o grafo fica incompleto: a análise é marcada como aproximada e a afirmação é rebaixada.",
        en: "No path in the binary's call graph leads to the signature check, and a negative like that is proof. If call_indirect appears on the way, the graph is incomplete: the analysis is marked approximate and the claim is downgraded.",
      },
    },
    B: {
      k: "B",
      soft: AMBER_T,
      fg: AMBER_INK,
      name: { pt: "Observado na rede", en: "Observed on-chain" },
      desc: { pt: "Medido numa janela real. Pode mudar.", en: "Measured over a real window. It can change." },
      claim: {
        pt: "Em 120.662 ledgers (~186 h), o contrato emitiu 0 eventos.",
        en: "Over 120,662 ledgers (~186 h), the contract emitted 0 events.",
      },
      why: {
        pt: "É uma observação via getEvents, não algo que o bytecode garante. Outra janela pode dar outro número, e uma janela vazia é ausência de tráfego, não um perfil de tráfego.",
        en: "It is an observation through getEvents, not something the bytecode guarantees. Another window may give another number, and an empty window is absence of traffic, not a traffic profile.",
      },
    },
    C: {
      k: "C",
      soft: COBALT_T,
      fg: COBALT_INK,
      name: { pt: "Inferência", en: "Inference" },
      desc: { pt: "Raciocínio plausível. Precisa de confirmação.", en: "Plausible reasoning. Needs confirmation." },
      claim: {
        pt: "has_contract_data provavelmente é uma guarda de “já inicializado”.",
        en: "has_contract_data is likely an already-initialized guard.",
      },
      why: {
        pt: "O bytecode mostra que a checagem é alcançável, não a intenção por trás dela. A frase sai marcada como inferência para que alguém confirme antes de confiar.",
        en: "The bytecode shows the check is reachable, not the intent behind it. The sentence ships marked as inference so someone confirms it before relying on it.",
      },
    },
    L: {
      k: "?",
      soft: "#FFFFFF",
      fg: MUTED,
      name: { pt: "Lacuna", en: "Gap" },
      desc: { pt: "Sem evidência. Declarada em vez de inventada.", en: "No evidence. Declared instead of invented." },
      claim: {
        pt: "Spoofing: sem evidência no bytecode, declarado como lacuna (75 de 75 contratos).",
        en: "Spoofing: no bytecode evidence, declared as a gap (75 of 75 contracts).",
      },
      why: {
        pt: "Identidade não é observável no bytecode de um contrato. Em vez de texto genérico, o documento declara a lacuna e entrega uma planilha com a superfície concreta que a equipe precisa revisar.",
        en: "Identity is not observable in a contract's bytecode. Instead of boilerplate, the document declares the gap and hands over a worksheet with the concrete surface the team has to review.",
      },
    },
  };
  const badgeFor = (key: string, size: number): string =>
    "display: grid; place-items: center; flex: none; width: " +
    size +
    "px; height: " +
    size +
    "px; box-sizing: border-box; border-radius: " +
    Math.round(size * 0.32) +
    "px; font-family: 'Bricolage Grotesque', system-ui, sans-serif; font-size: " +
    Math.round(size * 0.46) +
    "px; font-weight: 700; color: " +
    TIERS[key].fg +
    "; background: " +
    TIERS[key].soft +
    ";" +
    (key === "L" ? " box-shadow: inset 0 0 0 1.5px #AEB8B6;" : "");
  const tk = TIERS[state.tier] ? state.tier : "A";
  const tiers = Object.keys(TIERS).map((key) => {
    const on = tk === key;
    return {
      k: TIERS[key].k,
      name: tx(TIERS[key].name),
      desc: tx(TIERS[key].desc),
      color: TIERLINE[key].color,
      dash: TIERLINE[key].dash,
      width: TIERLINE[key].width,
      badge: badgeFor(key, 44),
      pick: set("tier", key),
      pressed: on,
      style:
        "display: flex; align-items: center; gap: 16px; width: 100%; min-height: 84px; padding: 14px 18px 14px 16px; box-sizing: border-box; border: 0; border-radius: 22px; cursor: pointer; text-align: left; transition: background .18s ease, box-shadow .18s ease; " +
        (on
          ? "background: #FFFFFF; box-shadow: 0 1px 2px rgba(19,32,31,0.06), 0 10px 24px -16px rgba(19,52,50,0.30);"
          : "background: transparent;"),
    };
  });
  const ev = {
    k: TIERS[tk].k,
    claim: tx(TIERS[tk].claim),
    why: tx(TIERS[tk].why),
    color: TIERLINE[tk].color,
    dash: TIERLINE[tk].dash,
    width: TIERLINE[tk].width,
    badge: badgeFor(tk, 52),
  };

  // ---------- output: threats -> monitors (escrow CDZZ5HUO…742T5) ----------
  const tokFor = (key: string) => ({ label: key === "L" ? t.gap : key, style: TIERTOK[key] });
  const OUT: Record<string, OutDef> = {
    el1: {
      side: "tm",
      id: "Elevation.1 · Medium",
      sub: { pt: "Inicialização sem autorização", en: "Initialization without authorization" },
      toks: ["A", "C"],
      token: "Elevation.1 → Elevation.1.M.1",
      tokenStyle: tok(TEAL_INK, TEAL_T),
      cls: "ok",
      title: { pt: "Inicialização sem autorização", en: "Initialization without authorization" },
      what: {
        pt: "initialize_escrow grava estado sem pedir assinatura. O risco que sobra é alguém fazer essa etapa antes do dono (front-running).",
        en: "initialize_escrow writes state without asking for a signature. The remaining risk is someone running that step before the owner (front-running).",
      },
      watch: {
        pt: "Cada evento tw_init deste contrato. O tópico vem do próprio WASM e já sai como filtro de getEvents, pronto para rodar.",
        en: "Every tw_init event from this contract. The topic comes from the WASM itself and ships as a getEvents filter, ready to run.",
      },
      lines: [
        ["A", { pt: "initialize_escrow não alcança require_auth.", en: "initialize_escrow does not reach require_auth." }],
        [
          "A",
          {
            pt: "initialize_escrow alcança contract_event em 1 salto; o tópico tw_init está declarado no WASM.",
            en: "initialize_escrow reaches contract_event in 1 hop; the tw_init topic is declared in the WASM.",
          },
        ],
        [
          "C",
          {
            pt: "A ligação entre o evento e a função é feita pelo nome.",
            en: "The link between the event and the function is made by name.",
          },
        ],
        [
          "B",
          {
            pt: "Baseline: 0 eventos em 120.662 ledgers (~186 h). Ausência de tráfego, não um perfil de tráfego.",
            en: "Baseline: 0 events over 120,662 ledgers (~186 h). Absence of traffic, not a traffic profile.",
          },
        ],
      ],
      todo: [
        {
          pt: "dono e canal de notificação do alerta. Nenhum dos dois aparece no binário.",
          en: "an owner and a notification channel for the alert. Neither appears in the binary.",
        },
      ],
    },
    spoof: {
      side: "tm",
      id: "Spoofing",
      sub: { pt: "Lacuna declarada", en: "Declared gap" },
      toks: ["L"],
      token: t.gap,
      tokenStyle: TIERTOK.L,
      cls: "sup",
      title: { pt: "Spoofing: sem evidência no bytecode", en: "Spoofing: no evidence in the bytecode" },
      what: {
        pt: "Identidade não é observável no bytecode de um contrato. Em vez de inventar uma ameaça, o documento declara a lacuna.",
        en: "Identity is not observable in a contract's bytecode. Instead of inventing a threat, the document declares the gap.",
      },
      watch: {
        pt: "Nada. Sem ameaça não há alerta: o plano não cria monitor para o que não tem evidência.",
        en: "Nothing. No threat, no alert: the plan does not create a monitor for what has no evidence.",
      },
      lines: [
        ["L", { pt: "Declarada como lacuna em 75 de 75 contratos do corpus.", en: "Declared as a gap in 75 of 75 corpus contracts." }],
      ],
      todo: [
        {
          pt: "o template exige ao menos uma ameaça por letra STRIDE. A planilha da lacuna lista a superfície concreta a revisar, como quais funções afirmam identidade.",
          en: "the template requires at least one threat per STRIDE letter. The gap worksheet lists the concrete surface to review, such as which functions assert identity.",
        },
      ],
    },
    gaps: {
      side: "tm",
      id: "Tampering · Repudiation · Info · DoS",
      sub: { pt: "4 lacunas declaradas", en: "4 declared gaps" },
      toks: ["L"],
      token: t.gap,
      tokenStyle: TIERTOK.L,
      cls: "sup",
      title: { pt: "As outras letras STRIDE vazias", en: "The other empty STRIDE letters" },
      what: {
        pt: "O mesmo tratamento para cada letra que o bytecode não sustenta: lacuna declarada, com planilha, nunca texto genérico.",
        en: "The same treatment for every letter the bytecode cannot support: a declared gap, with a worksheet, never boilerplate.",
      },
      watch: { pt: "Nada, pelo mesmo motivo: sem ameaça, sem monitor.", en: "Nothing, for the same reason: no threat, no monitor." },
      lines: [],
      todo: [
        {
          pt: "preencher Tamper, Repudiate, Info e DoS pela planilha de cada lacuna. Com a seção 1 e o Spoof, são os 6 itens do modelo.",
          en: "fill Tamper, Repudiate, Info and DoS from each gap's worksheet. With section 1 and Spoof, those are the model's 6 items.",
        },
      ],
    },
    m1: {
      side: "mp",
      id: "Elevation.1.M.1",
      sub: { pt: "evento tw_init emitido", en: "tw_init event emitted" },
      toks: ["A", "B"],
      link: "el1",
    },
    orphan: {
      side: "mp",
      id: "?.M.1",
      sub: { pt: "exemplo: monitor órfão", en: "example: orphan monitor" },
      toks: [],
      token: pt ? "recusado" : "rejected",
      tokenStyle: tok(CORAL_INK, CORAL_T),
      cls: "bad",
      title: { pt: "Monitor órfão: sem ameaça por trás", en: "Orphan monitor: no threat behind it" },
      what: {
        pt: "Um alerta que não aponta para nenhuma ameaça do modelo. Este é só um exemplo; o soroguard não gera monitor assim.",
        en: "An alert that points to no threat in the model. This one is only an example; soroguard does not generate monitors like it.",
      },
      watch: {
        pt: "A validação recusa. NÃO SUBMETÍVEL fica reservado para falhas da própria ferramenta: uma afirmação sem base, um monitor órfão, um baseline inventado.",
        en: "Validation rejects it. NOT SUBMITTABLE is reserved for the tool's own failures: a claim it cannot back, an orphan monitor, an invented baseline.",
      },
      lines: [],
      todo: [],
    },
  };
  const okey = OUT[state.out] ? OUT[state.out].link || state.out : "el1";
  const O = OUT[okey] as OutDetail;
  const outRow = (key: string) => {
    const r = OUT[key];
    const on = okey === key || (key === "m1" && okey === "el1");
    const bad = on && key === "orphan";
    const ghost = key === "orphan" && !on;
    return {
      id: r.id,
      sub: tx(r.sub),
      toks: r.toks.map(tokFor),
      pick: set("out", key),
      pressed: on,
      style:
        "display: flex; align-items: center; gap: 12px; width: 100%; height: 60px; padding: 0 14px; box-sizing: border-box; border: 0; border-radius: 16px; cursor: pointer; text-align: left; color: " +
        INK +
        "; " +
        (bad
          ? "background: " + CORAL_T + "; box-shadow: inset 0 0 0 1.5px #F1CDBE;"
          : on
            ? "background: #FFFFFF; box-shadow: 0 1px 2px rgba(19,32,31,0.06), 0 6px 16px -10px rgba(19,52,50,0.25), inset 3px 0 0 " +
              (O.cls === "ok" ? TEAL : "#AEB8B6") +
              ";"
            : ghost
              ? "background: transparent; box-shadow: inset 0 0 0 1.5px #D5DCDA; color: " + MUTED + "; border: 0;"
              : "background: transparent;"),
    };
  };
  const tmRows = ["el1", "spoof", "gaps"].map(outRow);
  const mpRows = ["m1", "orphan"].map(outRow);
  // connector geometry: row centers at y = 94, 158, 222 (8 pad + 56 header + i*64 + 30)
  const X_GLYPH = (cx: number, cy: number): string => "M" + (cx - 4) + " " + (cy - 4) + "l8 8M" + (cx + 4) + " " + (cy - 4) + "l-8 8";
  const Q_GLYPH = (cx: number, cy: number): string => "M" + (cx - 3.5) + " " + cy + "h7";
  let wires: Wire[] = [],
    marks: Mark[] = [],
    labels: Label[] = [];
  const base = { d: "M2 94 H112", len: "110", cls: "", color: "#A9B4B2", width: "1.5", dash: "none", marker: "" };
  if (okey === "el1") {
    wires = [base, { d: "M2 94 H112", len: "1", cls: "sg-draw", color: TEAL, width: "2.4", dash: "1 1", marker: "url(#out-arr)" }];
    labels = [{ y: "80", text: t.oSameId, color: TEAL_INK }];
  } else if (okey === "spoof" || okey === "gaps") {
    const y = okey === "spoof" ? 158 : 222;
    wires = [base, { d: "M2 " + y + " H48", len: "46", cls: "sg-fade", color: "#8E9A98", width: "1.6", dash: "3 5", marker: "" }];
    marks = [{ cx: "60", cy: String(y), fill: "#FFFFFF", stroke: "#8E9A98", glyph: Q_GLYPH(60, y) }];
    labels = [{ y: String(y + 28), text: t.oNoMon, color: MUTED }];
  } else if (okey === "orphan") {
    wires = [base, { d: "M118 158 H72", len: "46", cls: "sg-fade", color: CORAL, width: "1.6", dash: "3 5", marker: "" }];
    marks = [{ cx: "60", cy: "158", fill: CORAL_T, stroke: CORAL, glyph: X_GLYPH(60, 158) }];
    labels = [{ y: "186", text: t.oNoThreat, color: CORAL_INK }];
  }
  const OPANEL: Record<string, string> = { ok: "#F2F6F5", sup: "#F2F4F3", bad: "#FDF3EF" };
  const od = {
    token: O.token,
    tokenStyle: O.tokenStyle,
    title: tx(O.title),
    what: tx(O.what),
    watch: tx(O.watch),
    lines: O.lines.map(([tier, text]) => ({ tier: tier === "L" ? t.gap : tier, text: tx(text), tokenStyle: TIERTOK[tier] })),
    todo: O.todo.map((x) => ({ text: tx(x) })),
    panel:
      "display: flex; flex-direction: column; gap: 14px; padding: 20px 22px; border-radius: 22px; min-height: 220px; box-sizing: border-box; transition: background .22s ease; background: " +
      OPANEL[O.cls] +
      ";",
  };
  const verdicts = [{ text: t.oVerdTm }, { text: t.oVerdMp }];

  // ---------- how it works ----------
  const steps = [
    {
      n: "1",
      title: { pt: "Você passa o endereço", en: "You pass the address" },
      body: {
        pt: "Um contract ID (C…, 56 caracteres) ou um .wasm local. Não precisa do código-fonte.",
        en: "A contract ID (C…, 56 chars) or a local .wasm. No source code needed.",
      },
      code: "CDZZ5HUO…742T5",
    },
    {
      n: "2",
      title: { pt: "Ele busca o binário na rede", en: "It fetches the binary on-chain" },
      body: {
        pt: "Baixa o WASM publicado e lê o que ele declara: funções, erros, eventos e a versão do SDK. Na rede, consulta o que o contrato emitiu de verdade.",
        en: "It downloads the deployed WASM and reads what it declares: functions, errors, events and the SDK version. On the network, it checks what the contract actually emitted.",
      },
      code: "getContractWasmByContractId · getEvents",
    },
    {
      n: "3",
      title: { pt: "Mapeia o que cada função alcança", en: "It maps what each function reaches" },
      body: {
        pt: "Monta o grafo de chamadas e marca quais host functions cada função pública pode chamar: exigir assinatura, gravar estado, emitir evento, chamar outro contrato.",
        en: "It builds the call graph and marks which host functions each public function can call: require a signature, write state, emit an event, call another contract.",
      },
      code: "a.0 = require_auth",
    },
    {
      n: "4",
      title: { pt: "Escreve dois documentos", en: "It writes two documents" },
      body: {
        pt: "O modelo de ameaças e o plano de monitoramento, nos templates oficiais da Stellar, conferidos contra o checklist de cada template.",
        en: "The threat model and the monitoring plan, in the official Stellar templates, checked against each template's checklist.",
      },
      code: "threat-model.md · monitoring-plan.md",
    },
  ].map((x) => ({ n: x.n, title: tx(x.title), body: tx(x.body), code: x.code }));

  // ---------- get started ----------
  const cmdS = "color: " + INK + ";";
  const comS = "color: " + MUTED + ";";
  const C = (text: string): CodeLine => ({ pre: "$", preStyle: "color: " + TEAL + "; user-select: none;", text, textStyle: cmdS });
  const H = (text: string): CodeLine => ({ pre: "#", preStyle: comS + " user-select: none;", text, textStyle: comS });
  const TABS: Record<string, TabDef> = {
    cli: {
      label: "CLI",
      lines: [
        H(pt ? "<target> = contract id (C…, 56 caracteres) ou um .wasm local" : "<target> = contract id (C…, 56 chars) or a local .wasm"),
        C("npx soroguard inspect  <target>"),
        C("npx soroguard analyze  <target> --network testnet"),
        C("npx soroguard artifact <target> --lang pt"),
      ],
      note: pt
        ? "O npx funciona quando o pacote estiver no npm. De um clone, sem etapa de build: node src/cli.ts <comando> <target>."
        : "The npx form works once the package is on npm. From a clone, with no build step: node src/cli.ts <command> <target>.",
    },
    mcp: {
      label: "MCP",
      lines: [H(pt ? "servidor MCP via stdio" : "stdio MCP server"), C("claude mcp add soroguard -- npx -y soroguard-mcp")],
      note: pt
        ? "Três ferramentas: soroguard_inspect, soroguard_analyze e soroguard_sdk_advisories."
        : "Three tools: soroguard_inspect, soroguard_analyze and soroguard_sdk_advisories.",
    },
    src: {
      label: t.sFrom,
      lines: [C("git clone https://github.com/r4topunk/soroguard"), C("cd soroguard && pnpm install && pnpm test")],
      note: pt ? "Node ≥ 22.18, sem etapa de build. 161 testes." : "Node ≥ 22.18, no build step. 161 tests.",
    },
  };
  const bk = TABS[state.tab] ? state.tab : "cli";
  const tabs = Object.keys(TABS).map((k) => ({
    label: TABS[k].label,
    pick: set("tab", k),
    pressed: bk === k,
    style: seg(bk === k, 20).replace("border-radius: 999px", "border-radius: 18px"),
  }));
  const tab = { lines: TABS[bk].lines, note: TABS[bk].note };

  return {
    t,
    langs,
    steps,
    pickCopy: actions.pickCopy,
    capsule,
    copyKey,
    outKey: okey,
    copyIcon: copied ? "M5 12.5l4.5 4.5L19 7.5" : "M9 9h10v10H9z M5 15V5h10",
    copyLabel: copied ? t.copied : t.copy,
    copyAria: copied ? t.copiedAria : t.copyAria,
    fns,
    chips,
    cur,
    tiers,
    ev,
    tmRows,
    mpRows,
    wires,
    marks,
    labels,
    od,
    verdicts,
    tabs,
    tab,
  };
}

export type Vals = ReturnType<typeof computeVals>;
