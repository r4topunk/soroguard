/** Helpers de texto compartilhados pelos renderizadores. Saída é só em inglês. */

/** `plural(n, "monitor", "monitors")`. */
export function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

/** Junta com vírgulas e "and": `["a","b","c"]` → `a, b and c`. */
export function listAnd(items: readonly string[]): string {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}
