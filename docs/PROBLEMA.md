# O problema, definido

Escrito depois de construir o suficiente para descobrir o que eu não sabia. Três coisas mudaram o desenho.

---

## Descoberta 1 — dá para saber, não só adivinhar

As host functions do Soroban são **imports do módulo WASM**, com nomes de um caractere (`a.0`, `l.6`, `x.1`). O mapa canônico está em `rs-soroban-env/soroban-env-common/env.json`: 11 módulos, ~200 funções.

```
a.0  require_auth                     l.6  update_current_contract_wasm
a._  require_auth_for_args            l.3  create_contract
a.3  authorize_as_curr_contract       l._  put_contract_data
x.1  contract_event                   l.7  extend_contract_data_ttl
d._  call          d.0  try_call      c.*  verificação de assinatura
```

As funções do contrato são **exports**. Então dá para construir o call graph a partir da code section e responder, **por entrypoint exportado**, quais host functions são alcançáveis.

Isso troca heurística de nome por fato de bytecode:

| Pergunta | Antes (nome) | Agora (bytecode) |
|---|---|---|
| essa função exige autorização? | `withdraw` parece que sim | alcança `require_auth`: sim/não |
| escreve estado? | tem `set_` no nome | alcança `put_contract_data`: sim/não |
| emite evento? | não dá pra saber | alcança `contract_event`: sim/não |
| pode trocar o próprio código? | tem `upgrade` no nome | alcança `update_current_contract_wasm`: sim/não |
| cruza fronteira de confiança? | não dá pra saber | alcança `call`/`try_call`: sim/não |
| estende TTL? | não dá pra saber | alcança `extend_contract_data_ttl`: sim/não |

**Medido em 8 contratos de mainnet: nenhum usa `call_indirect`.** O call graph é completo e preciso nos 8. A imprecisão que eu temia não se materializa na prática — contratos Soroban em Rust compilam sem dispatch indireto. Quando houver, marcamos a análise como degradada em vez de mentir.

> ⚠️ **Correção posterior, medida no corpus completo.** A amostra de 8 estava errada por ser pequena
> (e o decodificador daquele protótipo era mais raso). Em **75 contratos de mainnet são 24 (32%)** com
> `call_indirect` no módulo — `node scripts/calibrate.mjs`. Ou seja: em quase um terço do corpus o call
> graph **não** é completo, e nesses casos nem a afirmação negativa ("não alcança `require_auth`") é
> prova. O rebaixamento para `approximate` não é uma salvaguarda teórica que quase nunca dispara; ele
> é o que sustenta a honestidade do documento em 24 de 75 casos. A frase original fica visível porque
> o erro — generalizar de n=8 — é exatamente o que a calibração existe para pegar.

## Descoberta 2 — o achado real aparece sozinho

Rodando num escrow da Trustless Work vivo em mainnet:

```
initialize_escrow     auth=NÃO  escreve=sim  evento=sim
                      host fns: put_contract_data, contract_event, extend_contract_data_ttl, call
```

Escreve estado e emite evento sem nenhum caminho até `require_auth`. É a classe de bug mais comum do Soroban. Detectado sem uma linha de código-fonte.

## Descoberta 3 — e é aqui que nasce o slop

Nos mesmos 8 contratos, **6 têm "escritor de estado sem auth"**. Mas:

| Entrypoint | Ocorrências | É achado? |
|---|---|---|
| `__constructor` | 2 | ❌ **não** — roda uma vez, atomicamente no deploy |
| `__check_auth` | 1 | ❌ **não** — é a *implementação* de auth de uma smart account; exigir `require_auth` ali é circular |
| `initialize*` | 3 | ✅ **sim**, mas de outra classe: front-running / re-inicialização, não missing-auth |

**Um detector ingênuo erra 50% aqui.** E errar para mais é pior que não detectar: um relatório com falso positivo óbvio faz o revisor descartar o documento inteiro. É exatamente assim que a ferramenta viraria slop.

---

## O que estamos entregando

Dois documentos, nos formatos oficiais, acoplados por ID de ameaça, **defensáveis diante de um revisor humano**.

O critério não é "gerou um markdown bonito". É: **um revisor de tranche do SCF lê e não consegue derrubar nenhuma afirmação.**

### Os três níveis de evidência

Cada afirmação no documento carrega seu nível. A regra que não se quebra: **nunca apresentar C como A.**

| Nível | O que é | Verificável por | Exemplo |
|---|---|---|---|
| **A — fato de bytecode** | alcançabilidade no call graph do WASM deployado | qualquer um, redeterminístico | `initialize_escrow` não alcança `require_auth` |

> ⚠️ **Correção posterior, aprendida na calibração.** O nível A vale para a afirmação **negativa**. A positiva ("alcança `put_contract_data`") é super-aproximada: a travessia atravessa helpers compartilhados. Medimos ~84% de falso positivo no predicado nu — pior que o detector de fonte equivalente da CoinFabrik (59,41%). Por isso toda positiva sai com o caminho e o número de saltos, e três famílias de exceção foram adicionadas. O mesmo vale para `alcança require_auth`: a positiva é igualmente super-aproximada — o caminho pode atravessar um helper cujo ramo de `require_auth` este entrypoint nunca executa —, por isso o DFD marca os saltos de auth com †. Ver `CALIBRACAO.md` e `TAXONOMIA-VALIDACAO.md`.
| **B — fato observado on-chain** | eventos realmente emitidos, frequência, endereços, janela | qualquer um, via RPC | `tw_withdraw` disparou 412×/7 dias, p95 = 3/hora |
| **C — inferência** | classe de ameaça, severidade, remediação sugerida | só revisão humana | "isso permite front-running se o deploy não for atômico" |

Nível A responde *o que o contrato faz*. Nível B responde *o que ele fez*. Nível C é a única parte que opina — e vai marcada como opinião.

### A saída que isso permite

```
Elevation.1  [A+C]  initialize_escrow permite tomada de controle antes do dono legítimo
  Evidência (A): export `initialize_escrow`, alcançabilidade no call graph →
                 {put_contract_data, contract_event, extend_contract_data_ttl, call}.
                 Nenhum caminho alcança require_auth nem require_auth_for_args.
                 Call graph completo (0 call_indirect no módulo).
  Inferência (C): se o deploy e a inicialização não ocorrerem na mesma transação,
                 qualquer endereço pode inicializar primeiro.
  Monitor derivado: Elevation.1.M.1 — alertar em qualquer evento com topic
                 ["tw_init"] cujo emissor não esteja na allowlist de deploy.
                 Baseline (B): 1 emissão em 30 dias.
```

Compare com o que um gerador de texto produziria: *"Elevation.1 — um atacante pode obter privilégios elevados."* Verdadeiro para qualquer sistema, útil para nenhum.

---

## Onde isso se posiciona

Fui verificar o que já existe antes de assumir vazio.

| Ferramenta | Analisa | Entrega |
|---|---|---|
| **Scout** (CoinFabrik, ~$240k em SCF) | código-fonte Rust | lints de vulnerabilidade |
| **Guard-CLI** (SorobanGuard) | código-fonte Rust — *"at the source level, before `stellar contract deploy` ever runs"* | lints (missing require_auth, reentrancy, admin desprotegido) |
| **Persist** (`cargo persist-audit`) | código-fonte Rust | lints de ciclo de vida de storage (TTL/archival) |
| **Komet** | modelo formal | verificação formal |
| **soroguard** | **WASM deployado + estado on-chain** | **os dois artefatos exigidos pelo tranche #2** |

Duas diferenças estruturais, não cosméticas:

1. **Input.** Todas as outras precisam do código-fonte. Nós lemos o que está de fato deployado. Isso importa porque (a) você pode analisar contratos de terceiros que você integra, sem pedir o repo, e (b) fonte e deploy divergem — é literalmente por isso que a RFP de *Contract Source Verification* existe.
2. **Output.** Elas são linters: apontam bug. Nós somos gerador de artefato: produzimos os dois documentos no formato que o SCF exige. Um linter não resolve o tranche #2 de ninguém.

Não competimos com elas. Se alguém tem o fonte, deveria rodar Scout **e** Persist **e** soroguard.

---

## As classes de ameaça específicas do Soroban

> A tabela abaixo é a hipótese original. Ela foi confrontada com ~40 relatórios de auditoria
> (Veridise, OtterSec, Certora, Runtime Verification, Code4rena, OpenZeppelin) e substituída
> pela taxonomia de 16 classes em **`TAXONOMIA-VALIDACAO.md` §E**, que é a referência atual.
> Fica aqui como registro de como o raciocínio começou.

Genérico é inútil. Esta é a taxonomia que a ferramenta precisa conhecer para não produzir ruído — cada uma com o sinal que a detecta:

| Classe | Sinal (nível A) | Exceções que evitam falso positivo |
|---|---|---|
| Entrypoint muta estado sem autorização | escreve `put_contract_data`/`del_contract_data`, não alcança `require_auth*` | `__constructor`, `__check_auth` |
| Re-inicialização / front-running de init | nome `init*` + escreve + sem auth | se houver guard de "já inicializado" — precisa de nível C |
| Upgrade sem controle | alcança `update_current_contract_wasm` sem `require_auth*` | — |
| Delegação de privilégio | alcança `authorize_as_curr_contract` | uso legítimo em padrões de conta |
| Fronteira de confiança não declarada | alcança `call`/`try_call` para contrato não listado | — |
| Mutação silenciosa | escreve estado e **não** alcança `contract_event` | getters |
| Archival de estado | escreve storage e nunca alcança `extend_contract_data_ttl` | storage temporário por design |
| Repúdio | ação privilegiada sem evento correspondente | — |
| Auth depois da escrita | ordem de `require_auth` vs `put_contract_data` no corpo | exige análise de ordem, não só alcançabilidade |

Ponto cego conhecido, herdado do ecossistema: `storage.update(&key, |v| …)` lê-transforma-escreve numa chamada só. No bytecode ela ainda vira `get_contract_data` + `put_contract_data`, então **nossa análise a enxerga** — enquanto as ferramentas de fonte relatam esse caso como falso negativo. É uma vantagem real do nível do bytecode, e vale medir.

---

## O que faria isso virar slop

Riscos, na ordem em que realmente aparecem:

1. **Reportar exceção legítima como vulnerabilidade.** Mitigação: lista de exceções do ciclo de vida, e todo falso positivo vira caso de teste.
2. **Ameaça genérica preenchendo a tabela para cumprir "≥1 por letra de STRIDE".** O template exige uma issue para cada S-T-R-I-D-E. Se o bytecode não sustenta uma de Repúdio, o certo é declarar *"nenhuma ameaça de Repúdio derivável do bytecode; requer análise manual do fluxo off-chain"* — não inventar. Um campo honestamente vazio é mais credível que um preenchido com enchimento.
3. **Baseline inventado.** A seção 4 do template exige baseline. Se não houver dado observado suficiente, o campo diz "janela insuficiente: N ledgers", não um número plausível.
4. **Diagrama de data-flow decorativo.** O DFD tem que sair da análise: processos = entrypoints, data stores = chaves de storage, fronteiras de confiança = onde `require_auth` acontece e onde `call` cruza para outro contrato. Se for desenho genérico, some.
5. **Remediação copiada de checklist.** Remediação é nível C e deve citar a função específica.

---

## Como saberemos que ficou bom

| Teste de aceitação | Medida |
|---|---|
| Precisão em achados de auth | zero falso positivo em `__constructor`/`__check_auth` num corpus de ≥50 contratos de mainnet |
| Rastreabilidade | 100% das afirmações de nível A reproduzíveis por um comando que imprime o caminho no call graph |
| Honestidade | toda seção sem evidência aparece declarada como lacuna, nunca preenchida com genérico |
| Utilidade real | os dois artefatos gerados para ≥3 protocolos conhecidos do ecossistema, revisados por alguém que não é nós |
| Aceitação | um artefato gerado é aceito numa review de tranche real do SCF |

O último é o único que conta de verdade. Os outros quatro são o caminho até ele.
