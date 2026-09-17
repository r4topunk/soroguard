/**
 * Idioma da saída. `en` é o padrão: os templates da Stellar e os revisores do SCF
 * são em inglês. `pt` fica disponível por flag.
 *
 * Cada módulo que emite texto declara a própria tabela com `msgs({ en, pt })` e lê
 * `M.chave`. A tabela é um Proxy: a chave é resolvida no momento da leitura, então
 * `setLang` feito pelo CLI/MCP antes de renderizar vale para todos os módulos sem
 * passar o idioma por parâmetro. Quando o `ArtifactContext` carrega `lang`, o pipeline
 * chama `setLang(ctx.lang)` antes de renderizar — a saída continua determinística.
 */
export type Lang = "en" | "pt";

let current: Lang = "en";

export function setLang(l: Lang): void {
  current = l;
}

export function lang(): Lang {
  return current;
}

export function parseLang(v: unknown): Lang {
  if (v === "pt" || v === "pt-BR" || v === "pt-br") return "pt";
  return "en";
}

/**
 * Tabela de mensagens por idioma. As duas tabelas precisam ter as mesmas chaves —
 * o tipo garante isso em compile time. Chaves podem ser strings ou funções de
 * formatação `(…args) => string`.
 */
export function msgs<T extends Record<string, string | ((...a: any[]) => string)>>(table: { en: T; pt: T }): T {
  return new Proxy(table.en, {
    get(_t, key) {
      const v = (table[current] as any)[key];
      return v === undefined ? (table.en as any)[key] : v;
    },
  }) as T;
}

/** Plural mínimo: `plural(n, "monitor", "monitors")`. */
export function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}
