# Log de calibração

> **Os números correntes não moram neste arquivo.** Eles são gerados por
> `node scripts/stats.mjs` (que por sua vez roda a suíte e os detectores) e publicados no
> bloco `stats:start`/`stats:end` do `README.md` e do `docs/HANDOFF.md`. Este documento é o
> **log histórico** de como se chegou neles: cada tabela abaixo está datada e vale para o
> estado do código naquela data, não para o de hoje.

Corpus: **75 contratos** de mainnet com wasm distinto, descobertos por varredura de
`getEvents` (só contratos ativos nas últimas ~24h). A contagem de entrypoints do corpus é
**1.767** (`node scripts/calibrate.mjs`), 0 falhas de parse. *(Uma versão anterior deste
arquivo dizia 1.263 três linhas depois de dizer 1.767: o 1.263 era de um corpus parcial, de
antes do fetch terminar, e foi removido.)*

## O loop que removeu o slop

> **Snapshot histórico — dia 1 (2026-09-16), corpus de 39 a 75 contratos conforme a iteração.**
> Os valores por iteração são de código que não existe mais; ficam pelo raciocínio.

| Iteração | Achados/contrato | O que estava errado | Correção |
|---|---|---|---|
| 1 | **15,0** | `archival-risk` e `auth-after-write` disparando em `__constructor`; exceção de ciclo de vida só valia para alguns detectores | exceção aplicada ao entrypoint inteiro |
| 2 | **11,7** | `trust-boundary-crossing` = 41% de tudo. Não é ameaça, é insumo do data-flow | removido dos achados, virou `fronteiras()` para o DFD |
| 3 | **9,8** | `archival-risk` avaliado por entrypoint: basta **um** caminho renovar TTL para o estado sobreviver | promovido a escopo de contrato — 30 achados → 2 |
| 4 | **4,1** | `silent-mutation` = 114 achados soterrando os 52 que importam | agregado em uma linha por contrato |
| 5 | 4,5 | ⚠ ver abaixo | severidade passou a refletir a força da evidência |
| 6 | **2,9** | `auth-after-write` linearizava ordem entre funções — afirmação que ninguém consegue conferir | trocado por `write-before-auth` **intraprocedural**, comparando offsets de bytecode no mesmo corpo: 16 achados → **3** |

## O erro conceitual que a verificação pegou

A amostragem manual mostrou `estimate_deposit`, `estimate_swap` e `estimate_swap_strict_receive` marcados **Critical**. São funções de estimativa, read-only. Elas *alcançam* `put_contract_data` porque chamam um helper compartilhado de carga de estado que **tem** um ramo de escrita — ramo que elas nunca executam.

Isso quebra uma afirmação que eu tinha escrito em `PROBLEMA.md`: que alcançabilidade dá fato nível A. **Só dá para a negativa.**

```
NÃO alcança require_auth  →  prova de que nunca chama        (sólido)
alcança put_contract_data →  pode escrever, em algum ramo    (super-aproximado)
```

O detector `escreve && !autentica` combina uma positiva fraca com uma negativa forte. O resultado só vale se a escrita for real.

**Correção adotada — tornar a imprecisão visível em vez de escondê-la:**

1. A linguagem mudou de "grava estado" para "**alcança** escrita de estado".
2. Toda afirmação positiva carrega o **número de saltos** do export até a host function.
3. Caminho com mais de 2 saltos ganha um aviso explícito de nível C: *"o caminho provavelmente passa por helper compartilhado; a escrita pode estar num ramo que este entrypoint nunca executa. Confirmar antes de tratar como achado."*
4. A severidade passou a refletir a força da evidência, não só a gravidade hipotética.

Resultado na classe de autorização (102 achados) — *snapshot de 2026-09-16, corpus de 39 contratos:*

| Severidade | n | Significado |
|---|---|---|
| Critical | **5** | caminho direto até a escrita, ≤2 saltos — alta confiança |
| High | 12 | inicialização sem auth |
| Medium | 85 | via helper — **marcado para revisão humana**, não afirmado |

Cinco achados de alta confiança em 39 contratos é um número que eu defendo. Oitenta e cinco "Critical" teria sido slop.

## Precisão do call graph

*Snapshot de 2026-09-16, corpus parcial de 39 contratos. No corpus completo de 75 são **24 (32%)** — ver o bloco gerado no README.*

**12 de 39 contratos (31%) têm `call_indirect`** — bem acima do 0/8 que eu havia medido no protótipo com uma amostra pequena e um decodificador mais raso. Nesses, nem a negativa é sólida, e o campo `soundness` do módulo passa a `approximate`. A afirmação vai rebaixada em vez de omitida.

## Distribuição por classe (39 contratos) — snapshot de 2026-09-16

```
76  unauthenticated-state-mutation   (5 Critical, 85 Medium com aviso)
29  silent-mutation                  (agregado, 1 por contrato)
28  privilege-delegation
26  initialization-front-running
16  auth-after-write
 2  archival-risk                    (escopo de contrato)
```

Lacunas declaradas com honestidade: **Spoof e Info não são deriváveis do bytecode em nenhum dos 39 contratos.** Vão para o artefato como lacuna explícita exigindo análise manual — não preenchidas com genérico.


## Estado atual — regenerado em 2026-09-16 (fim do dia), sobre 75 contratos

> ⚠️ **2026-09-17:** 4 contratos foram retirados do corpus público por estarem sob disclosure privado (`SECURITY.md`). Os números vivos são os de `node scripts/stats.mjs`, sobre 71; os desta seção são o snapshot de 75.

Saída de `node scripts/calibrate.mjs`, não transcrita de memória. A tabela anterior desta
seção listava `privilege-delegation`, classe que deixou de emitir achado (virou inventário do
DFD), e não listava `vulnerable-sdk` nem `host-prng-in-value-path`.

```
 50  silent-mutation                (agregado, 1 por contrato)
 35  vulnerable-sdk                 (34 CVE-2026-26267 + 1 GHSA-x2hw)
 33  initialization-front-running
 27  unauthenticated-state-mutation
 10  archival-risk                  (escopo de contrato)
  4  host-prng-in-value-path        (agregado por call site)
  3  write-before-auth              (intraprocedural)
───
162  achados · 2,2 por contrato
```

| Severidade | n |
|---|---|
| Critical | **10** |
| High | 43 |
| Medium | 70 |
| Low | 39 |

**147 com call graph completo · 15 com evidência rebaixada** (`call_indirect` no módulo). A
ferramenta diz explicitamente de qual lado cada achado está.

## Uma limitação estrutural que vale declarar de frente

**Spoof e Info deram zero achados deriváveis nos 75 contratos.** Não é bug de detector: essas duas letras do STRIDE dependem de identidade e de exposição de dados, que não são observáveis no bytecode de um contrato. O artefato vai sempre declará-las como lacuna exigindo análise manual do fluxo off-chain.

Isso é bom, não ruim: o template exige ≥1 issue por letra, e um documento que preenchesse Spoof com genérico seria descartado pelo primeiro revisor competente. Declarar a fronteira da ferramenta é o que a torna confiável dentro dela.

## Testes

> A contagem de testes **não** é escrita aqui: sai de `node scripts/stats.mjs`, que roda a
> suíte de verdade. A lista abaixo é dos testes de aceitação do dia 1 e não é exaustiva.

```
✔ catálogo de host functions resolve as chaves que os detectores dependem
✔ todo WASM do corpus parseia sem exceção            (75 contratos)
✔ exceções de ciclo de vida nunca viram achado        ← teste de aceitação do Dia 1
✔ achado de autorização implica ausência real de require_auth no alcance
✔ toda afirmação de nível A é acompanhada de evidência não vazia
✔ IDs seguem o padrão do template oficial
```

---

# Rodada 2 — validação externa da taxonomia

Um agente de pesquisa confrontou as 9 classes hipotetizadas contra auditorias reais (Code4rena/Reflector V3, OpenZeppelin stellar-contracts, detectores do CoinFabrik Scout), CAPs e medição direta nos 75 WASMs. Resultado em `docs/TAXONOMIA-VALIDACAO.md`. Três consequências.

## 1. A classe que faltava é a que prova a tese

**CVE-2026-26267 / GHSA-4chv-4c6w-w254** (High) — bypass de autorização no `soroban-sdk-macros`. A versão do SDK usada na compilação fica gravada na custom section `contractmetav0`, chave `rssdkver`.

Medido por nós, nos 75 contratos: **41 declaram a versão, e 34 deles (83%) estão em faixa afetada.**

```
22.0.7×7  22.0.8×5  22.0.6×5  20.5.0×4  21.7.7×3  23.4.0×2  20.2.0×2
21.6.0×1  21.7.6×1  22.0.5×1  23.3.0×1  22.0.3×1  21.1.1×1   ← afetadas
23.5.3×3  22.0.11×2  25.3.1×1  26.0.0×1                      ← corrigidas
```

É a única classe que é, ao mesmo tempo, classificada como High por advisory oficial e dependente de um dado que só o artefato deployado tem: o fonte mostra a colisão de nomes que dispara o bug; o que só o artefato mostra é qual SDK compilou o binário no ledger (o repo pode ter sido atualizado depois do deploy). Exposição (versão na faixa) é nível A e sai como achado **Low**; explorabilidade é nível C. Exatamente o argumento de existir da ferramenta — e não estava na minha tabela.

Depois disso os 34 foram verificados um a um contra o fonte (`docs/CVE-2026-26267-VERIFICACAO.md`):
**0 confirmados vulneráveis, 20 verificados NÃO afetados, 14 sem fonte pública.** É o resultado que
justifica o achado sair como Low: a exposição é fato de bytecode, a colisão que dispara o bug só
aparece no fonte, e onde o fonte existe ela não estava lá.

## 2. Minha regra de exceção estava conceitualmente errada

O host não isenta dois nomes: ele recusa **qualquer** função com prefixo `__` (`RESERVED_CONTRACT_FN_PREFIX` em `rs-soroban-env`, normatizado no CAP-0058). Minha lista estava empiricamente completa no corpus de hoje, mas o predicado por prefixo é o que o host garante.

## 3. Duas famílias de falso positivo que eu não via

Medidas sobre as 157 ocorrências brutas do detector de auth: **read-shaped 31,8%** e **crank permissionless 8,9%**. Minha exceção cobria só 20,4%.

Para calibrar contra o estado da arte: a CoinFabrik mediu o detector de fonte equivalente (`set-contract-storage`) em 71 contratos e reportou **59,41% de falso positivo**. O meu, sem essas duas famílias, estava em ~84% — **pior que a análise de fonte.**

### Efeito das correções

Medido em 2026-09-16, no corpus de 75, com `node scripts/calibrate.mjs`. A coluna "depois" é
o estado corrente; o bloco gerado do README é a fonte que não envelhece.

| | antes | depois |
|---|---|---|
| `unauthenticated-state-mutation` | 89 | **27** |
| supressões declaradas | 0 | **115** (52 read-shaped · 50 reservadas `__` · 13 crank) |
| rebaixamentos declarados (não supressão) | 0 | **10** (alcança `call`/`try_call`: auth pode viver no callee, severidade limitada a High) |
| classes | 6 | 7 (+ `vulnerable-sdk`: 35 achados em 34 contratos — 34 CVE-2026-26267 + 1 GHSA-x2hw) |

Uma versão anterior desta tabela registrava `89 → 27` com 112 supressões (49 read-shaped).
Entre as duas medições o `READ_SHAPED` deixou de ser ancorado no início do nome, o que passou
a cobrir `gauges_get_reward_info` (3 contratos): o 27 continua 27 por coincidência de duas
mudanças de sinal oposto — sem a supressão de `gauges_*` seriam 30. Por isso o número mora em
`stats.mjs`, não aqui.

### Última rodada de detectores (2026-09-16, fim do dia): 173 → 162

| Mudança | Efeito no total |
|---|---|
| `READ_SHAPED` deixa de ancorar no início do nome ⇒ `gauges_get_reward_info` suprimido (3 contratos) | −3 em `unauthenticated-state-mutation` (30 → 27) |
| `host-prng-in-value-path` agregado por call site quando o fan-out passa de 3 entrypoints | −8 (12 → 4) |
| cross-call: achado que alcança `call`/`try_call` é **rebaixado**, com teto de High, em vez de suprimido | 0 no total, 10 achados com severidade limitada |
| **total** | **173 → 162** (2,3 → 2,2 por contrato) |

A terceira linha é a que importa de desenho: quando a autorização pode estar delegada ao
callee, a resposta certa não é esconder o achado — é reportá-lo dizendo que a negativa não
vale além da fronteira do módulo.

Supressão **nunca é silenciosa**: cada uma entra em `suppressed` com motivo, e um teste falha se um entrypoint for suprimido e reportado ao mesmo tempo. "Cobrimos tudo" quando não se cobriu é a forma mais cara de slop.

## Testes

Contagem corrente: `node scripts/stats.mjs` (bloco gerado no `README.md`). Nesta rodada foram
adicionados testes de `wasm.ts` (input malformado, opcodes, LEB128), de `pathTo` contra BFS
independente e de i18n.
