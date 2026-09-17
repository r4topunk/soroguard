# Validação da taxonomia de ameaças Soroban

Stress-test das 9 classes hipotetizadas em `PROBLEMA.md` contra achados reais de auditoria, detectores publicados, CAPs, código do host e **medição direta em 75 WASMs de mainnet** do corpus local (`corpus/*.wasm`, desassemblados com `wasm-dis`).

Data da pesquisa: 2026-09-16.

**Convenção de evidência** (a mesma de `PROBLEMA.md`): **A** = fato de bytecode, **B** = fato observado on-chain, **C** = inferência. Toda afirmação empírica abaixo marcada `[medido]` é nível A reproduzível sobre o corpus.

---

## Sumário executivo

| | Contagem |
|---|---|
| Classes confirmadas por achado real (várias com Critical) | **5 de 9** |
| Classes reais mas com predicado ou severidade errados | **2 de 9** |
| Classes que são ruído (base rate alta demais, ou o sinal não detecta o bug) | **2 de 9** |
| Classes novas, ausentes da tabela original | **11** |
| Taxonomia revisada | **16 linhas** |

Base: ~40 relatórios públicos de Veridise, OtterSec, Certora, Runtime Verification, Code4rena, CoinFabrik e OpenZeppelin; os 36 detectores do Scout; CAP-0046-11, CAP-0058 e CAP-0066; o código de `rs-soroban-env`; e medição direta no corpus.

**A classe mais importante que faltava:** *versão do `soroban-sdk` gravada no WASM deployado com CVE conhecido de bypass de autorização* (CVE-2026-26267). **34 dos 75 contratos de mainnet do corpus (45%) foram compilados com SDK em faixa afetada — 83% dos 41 que declaram a versão** `[medido]`. É a única classe encontrada que (a) é classificada como *High* por um advisory oficial e (b) depende de um dado que só o artefato deployado tem: o fonte mostra a colisão de nomes que dispara o bug, mas o que só o binário mostra é qual SDK compilou o que está no ledger. Exposição (versão na faixa) é nível A; explorabilidade é nível C. É exatamente a tese do soroguard, e não estava na tabela.

**Sobre a lista de exceções:** `__constructor` + `__check_auth` está **empiricamente completa mas conceitualmente errada**. A regra correta é o *prefixo* `__`, imposta pelo host (`RESERVED_CONTRACT_FN_PREFIX`). E a lista está **incompleta na direção que importa**: ela cobre 20% dos falsos positivos medidos; os outros 80% vêm de três famílias que ela não menciona.

**Onde eu me enganei e corrigi:** a primeira versão desta análise concluiu que o CAP-0066 tinha esvaziado a classe de archival/TTL. Está errado — há um **High** e cinco outros achados posteriores ao Protocol 23. A seção §C.4 traz a correção e o predicado substituto. Registro isso porque o mesmo erro (ler um CAP e presumir que ele fecha uma classe inteira) é o tipo de coisa que um revisor de tranche encontra.

---

## 0. O número que deveria assustar antes de tudo

Rodei o detector exato da tabela linha 1 (*"alcança `put_contract_data`/`del_contract_data` e não alcança `require_auth*`"*) sobre os 75 WASMs do corpus, com reachability path-insensitive no call graph — a mesma análise descrita em `PROBLEMA.md`.

**Resultado: 157 ocorrências, 74 nomes de export distintos** `[medido]`.

| Família | Ocorrências | % | É achado? |
|---|---|---|---|
| **read-shaped** (`get_*`, `estimate_*`, `balance`, `price`, `lastprice`, `get_reserves`, `get_virtual_price`…) | 50 | **31,8%** | ❌ não — over-approximação de reachability |
| `init*` (`initialize`, `init_admin`, `initialize_escrow`, `init_pools_plane`…) | 36 | 22,9% | ✅ sim, mas de outra classe |
| **reservado `__`** (`__constructor` 30×, `__check_auth` 2×) | 32 | 20,4% | ❌ não — não invocável pelo host |
| restante (`deposit`, `withdraw`, `swap`, `claim`, `submit`, `settle_round`, `update_signer`…) | 25 | 15,9% | ⚠️ candidato |
| **crank permissionless** (`sync`, `gulp`, `gulp_emissions`, `poke_oracle`, `observe`, `new_auction`, `bad_debt`, `update_interest`, `snapshot_cumulatives_inside`, `backfill_plane_data`, `refresh_boosted_underlying`) | 14 | 8,9% | ❌ não — permissionless **por design** |

**Precisão máxima teórica do detector ingênuo: ≤ 16%.** A lista de exceções de `PROBLEMA.md` remove 20,4% do ruído. Sobram 40,7% de ruído que ela não cobre (read-shaped + crank).

Para calibrar: a CoinFabrik mediu o seu detector de fonte equivalente (`set-contract-storage`) em **71 contratos de 18 projetos Soroban públicos** e reportou **478 alarmes, 284 falsos positivos → 59,41% de FP**, o pior detector do conjunto. Fonte: <https://coinfabrik.github.io/scout-soroban/docs/precision-and-recall/first-iteration>. O FP global da ferramenta foi 34,24% (290/847).

Ou seja: **a análise de bytecode é hoje pior que a de fonte nessa classe** (≈84% FP vs 59%), porque reachability sem sensibilidade a caminho atravessa helpers de storage compartilhados. Verifiquei o mecanismo num contrato concreto (`CA6PUJLBYKZK…`): 22 funções internas chamam `put_contract_data` diretamente, e o helper mais central é alcançável a partir de **20 dos 76 exports** `[medido]`. Um `get_reserves` "alcança" `put_contract_data` porque compartilha um helper monomorfizado com um `swap`.

> **Consequência de desenho, não opinião:** o veredito da linha 1 tem que ser `alcança` + **caminho concreto impresso** + heurística de viabilidade. Sem isso, o relatório sai com 5 achados falsos para cada verdadeiro e é descartado inteiro — o cenário de slop descrito no próprio `PROBLEMA.md`.

---

## A. Confirmação — o que sobrevive ao contato com achados reais

### A.1 — Entrypoint muta estado sem autorização ✅ **CONFIRMADA, severidade alta**

Esta é a única classe da tabela com um achado *High* público, em produção, num protocolo vivo do ecossistema:

Esta é, com folga, a classe mais corroborada de todas — e os dois achados mais fortes são **Critical**:

- **Veridise / Phoenix DeFi Hub**, `V-PHX-VUL-001` — **Critical**, *"Incorrect access control when updating pool configuration"*. A descrição é a definição exata da classe, verbatim:
  > *"the critical flaw here is that `sender` is derived from a parameter passed to the function, rather than validating that the admin saved in the storage has authorized the contract invocation"*
  
  O código vulnerável é `if sender != utils::get_admin(&env) { panic!(...) }` — comparação em vez de `require_auth()`.
  <https://veridise.com/wp-content/uploads/2025/02/VAR_MoonBite_240103_OfficialR.pdf>
- **Veridise / Wombat Exchange**, `V-WOM-VUL-004` — **Critical**, *"Missing authorization check in `set_latest_price()` function"*. Papel checado, `require_auth` ausente.
  <https://veridise.com/wp-content/uploads/2025/04/VAR-Wombat-240902-WombatExchange-V2.pdf>
- **Veridise / Wombat**, `V-WOM-VUL-001` — **Critical**, *"Unauthorized Contract Upgrade Possible Due to Insufficient Access Control"*: `admin.require_auth(); has_operator_role(e, admin);` — **o retorno booleano é descartado**, e `admin` vem por parâmetro. Variante cruel: `require_auth` *está lá* e mesmo assim não protege.
- **Code4rena / Reflector V3** (o oráculo principal do Stellar), relatório 2026-02-02:
  **`[H-01] set_invocation_costs_config() fails to authorize admin allowing anyone to set invocation costs`** — numa função cujo próprio doc-comment diz "Requires admin authorization".
  <https://code4rena.com/reports/2025-10-reflector-v3>
- **OtterSec / Blend v1**, `OS-BCL-SUG-04.2` — `pool::initialize` sem `admin.require_auth()`.
  <https://github.com/blend-capital/blend-contracts/blob/main/audits/blend_capital_final.pdf>
- **CoinFabrik Scout**, três detectores distintos cobrem a classe, todos *Critical*:
  - `set-contract-storage` — <https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/set-contract-storage>
  - `unprotected-mapping-operation` — *"warns you if a mapping operation (`insert`, `take`, `remove`) function is called with a user-given `key` field"*; o exemplo remediado é literalmente adicionar `address.require_auth()`. <https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/unprotected-mapping-operation>
  - `missing-new-admin-auth` (Medium) — o novo admin tem que assinar antes de ser gravado. <https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/missing-new-admin-auth>
- **OpenZeppelin, auditoria da própria stellar-contracts v0.5.0**: `C-01 Unbounded Inflation via Self-Recovery in recovery_address` — a função **não tinha autorização nenhuma**, e self-recovery (`lost_wallet == new_wallet`) dobrava saldo exponencialmente. <https://github.com/OpenZeppelin/stellar-contracts/tree/main/audits>
- A mesma auditoria publica um catálogo de "Candidate Detectors for Static Analysis Tools" cujo primeiro item é `missing-auth-check`.

**Mas:** ver seção 0. A classe está certa; o *sinal* proposto para ela não sustenta a precisão exigida.

### A.2 — Re-inicialização / front-running de init ✅ **CONFIRMADA, com fonte normativa**

Não é folclore: está na motivação de um CAP aprovado.

- **CAP-0058 "Constructors for Soroban contracts"** (Final, Protocol 22), verbatim:
  > *"Using constructors makes it harder for developers to accidentally make their contracts prone to **front-running the initialization** (in case if factory is not being used), thus improving security."*
  > Security Concerns: *"deployed contract can't have their initialization to be frontrun."*
  <https://github.com/stellar/stellar-protocol/blob/master/core/cap-0058.md>
- CAP-58 também derruba a defesa "mas eu uso factory": *"factory contracts don't provide a guarantee that every contract instance has been initialized via a factory."*
Achados reais, todos anteriores ou contemporâneos ao CAP-58:
- **Runtime Verification / Soroswap Aggregator**, `A1` *"Adapters Can Be Hijacked By Third-Parties"*, com a explicação da causa raiz: *"Stellar-Soroban does not allow constructors into their contracts, meaning that the deployment and initialization function calls will be submitted… as two different transactions."*
- **Certora / Huma**, `L-01` *"Initialize can be front-run"* — o writeup de referência: *"These functions are not authorized, but they can only be run once… **During an upgrade this risk might be higher**… an active contract might be unrecoverable."*
- **Veridise / Wombat**, `V-WOM-VUL-005` — **High**, *"Token can be re-initialized"*.
- **Veridise / Scaffold Stellar**, `V-AHA-VUL-005`; **Veridise / HOT Bridge**, `V-HOTB-VUL-011` *"Bridge init call front-running risk"*.
- Variante irmã, **front-running do salt de deploy** (mesmo `salt`, `admin` diferente): OtterSec Blend `ADV-03`, Certora Spectra `L-04`, Certora Aquarius `L-03`, Veridise `V-PHX-VUL-005` *"Deployment of pools can be front-runned"* (High).

- **Medido:** 36 das 157 ocorrências são `init*`; e **41 dos 75 contratos exportam `__constructor`, 12 ainda exportam `initialize`** `[medido]`. O padrão legado continua vivo em mainnet, inclusive em contratos compilados com SDK ≥ 22.

**Refinamento obrigatório:** não basta o nome começar com `init`. O sinal forte é **`initialize*` exportado E `__constructor` ausente** — porque se o contrato tem construtor, o host garante que ele rodou atomicamente (§D). Um contrato que tem os dois é um caso de *dois* caminhos de inicialização, o que é pior e merece nota própria.

### A.3 — Upgrade sem controle ✅ **CONFIRMADA, correspondência 1:1 com detector publicado**

- **Veridise / Wombat**, `V-WOM-VUL-001` — **Critical**, *"Unauthorized Contract Upgrade Possible Due to Insufficient Access Control"*. Achado real, em protocolo real, exatamente nesta forma.
- **Scout `unprotected-update-current-contract-wasm`** — Authorization / **Critical**. É o mesmo predicado, palavra por palavra: *"`update_current_contract_wasm` is called without access control"*. <https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/unprotected-update-current-contract-wasm>
- Doc oficial, com o padrão canônico e o porquê: <https://developers.stellar.org/docs/build/guides/conventions/upgrading-contracts> — *"the contract checks if the action is authorized by the `Admin` address. This is crucial to prevent unauthorized upgrades."*
- **OpenZeppelin `Upgradeable`**: o trait é só `fn upgrade(e, new_wasm_hash, operator)` e a doc diz explicitamente *"All access control and authorization checks are the **implementor's responsibility**."* A função de storage carrega *"**IMPORTANT**: This function lacks authorization checks"*. <https://github.com/OpenZeppelin/stellar-contracts/tree/main/packages/contract-utils/src/upgradeable>
- **Medido:** **46 dos 75 contratos (61%) importam `update_current_contract_wasm`** `[medido]`. É comum, mas *não* universal — o sinal discrimina.

Esta é a linha mais saudável da tabela: predicado exato, base rate moderada, corroboração direta.

### A.4 — Mutação silenciosa / Repúdio ⚠️ **CONFIRMADA, mas severidade muito menor do que a tabela sugere**

Existe, tem detector, e a doc oficial concorda com o princípio:

- Stellar docs, regra de design verbatim: *"Regular `ContractEvents` should convey information about state changes."* <https://developers.stellar.org/docs/build/guides/events/publish>
- **Scout `storage-change-events`** — mas classificado **Enhancement**, o *degrau mais baixo* da escala de 4 níveis deles (Critical / Medium / Minor / Enhancement). <https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/storage-change-events>
- **Scout `token-interface-events`** (Medium) é a versão que importa: funções da interface de token **têm** que emitir evento, porque SEP-41 exige. <https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/token-interface-events>
- SEP-41 é normativo aqui: *"The only requirement is for `mint` and `clawback` events to be emitted during minting and clawback actions."* <https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md>

**Correção a uma versão anterior deste documento:** achados de evento **existem e são numerosos** — o que não existe é achado de evento com severidade alta. Levantamento:

| Achado | Severidade |
|---|---|
| Veridise Phoenix `V-PHX-VUL-021` *Incorrect event topic when providing liquidity* | Warning |
| Veridise HiYield `V-HYD-VUL-031` | Warning |
| OZ stellar-contracts v0.7.0 `L-03` *`transfer_from` Emits a Non-SEP-41 Transfer Event Payload* | Low |
| Certora Reflector `L-02` | Low |
| Certora Aquarius `L-06` — operações de admin não emitem evento | Low |
| OtterSec Soroban Governor `SUG-00` *Failure To Emit Event* | Suggestion |
| OtterSec Rango `ADV-01` | Advisory |

**Sete achados em sete auditorias distintas, nenhum acima de Low.** A classe é real e de baixa severidade — que é precisamente o veredito de §C.3. Note que a única forma com severidade Medium é a normativa (payload que não bate com SEP-41), não a genérica ("mudou estado e não emitiu nada").

Ver §C.3 — as duas linhas (Mutação silenciosa e Repúdio) são a mesma classe e precisam ser fundidas e rebaixadas.

### A.5 — Fronteira de confiança não declarada (`call`/`try_call`) ⚠️ **SEM CORROBORAÇÃO DIRETA**

Nenhum auditor consultado (Veridise, CoinFabrik, Code4rena, OpenZeppelin) publica um detector ou uma classe de achado chamada "trust boundary não declarada". O mais próximo:

- A auditoria OZ v0.5.0 lista `unchecked-external-calls` e `malicious-contract-injection` entre os detectores candidatos — mas o alvo é *chamar endereço fornecido pelo usuário*, não *chamar qualquer outro contrato*.
- Achado real com essa forma, em OZ: `packages/tokens/src/rwa/compliance/modules/mod.rs` — *"Hook arguments — including `token` — are forgeable: any contract can call these methods directly with arbitrary values."*

**Medido: 62 dos 75 contratos (82%) importam `call`** `[medido]`. Um sinal que dispara em 4 de 5 contratos não é um achado — é uma descrição da arquitetura. Ver §C.2.

### A.6 — Delegação de privilégio (`authorize_as_curr_contract`) ❌ **NÃO CORROBORADA**

- **Existe exatamente um achado público** com essa forma, e é *Suggestion*, não corrigido: **OtterSec / Rango Exchange**, `OS-RNG-SUG-02` *"Flattened Auth Declarations Lose Invocation Structure"*, verbatim:
  > *"Passing both entries at the top level of the vector instead declares them as independent invocations, and the host then matches each `require_auth` against whichever entry fits, **without regard to the relationship between them**."*
  
  Repare que o bug **não é usar** `authorize_as_curr_contract` — é montar a *árvore* de `InvokerContractAuthEntry` achatada em vez de aninhada. Isso é estrutura de dados construída em runtime, **invisível no bytecode**.
- **Nenhum detector do Scout** (36 detectores Soroban) menciona `authorize_as_curr_contract`.
- **Não é documentado** em developers.stellar.org — a única fonte é CAP-0046-11 e `soroban-env-host/src/auth.rs`.
- OpenZeppelin **deliberadamente evita** o mecanismo: em `rwa/compliance/modules/mod.rs` rejeitam `Env::authorize_as_current_contract` e usam um dispatcher por token.
- **Medido: 13 dos 75 contratos (17%) importam `a.3`** `[medido]` — base rate alta demais para ser achado sozinho.

Ver §C.1.

### A.7 — Archival de estado ⚠️ **CONFIRMADA, mas o enquadramento está desatualizado por dois protocolos**

A classe existe, mas o predicado da tabela ("escreve storage e nunca alcança `extend_contract_data_ttl`") mira no risco errado desde o Protocol 23.

- **CAP-0066** (Protocol 23, ativo em mainnet desde 2025-09-03) introduziu **restauração automática de entradas persistentes arquivadas**: *"Whenever `InvokeHostFunctionOp` is applied, any archived state is automatically restored prior to host function invocation."* <https://github.com/stellar/stellar-protocol/blob/master/core/cap-0066.md>
- Consequência: para storage **Persistent** e **Instance**, "não estende TTL" deixou de ser perda de dados e virou custo + um requisito de *restore list* na transação. Caso concreto de um pesquisador que perdeu um falso-High exatamente por isso: <https://paragraph.com/@dan23rr/layerzero-finding>
- **Temporary continua irrecuperável.** CAP-0066: entradas temporárias *"will always return a state of `live` or `new`"* — não existe restore. Stellar docs: *"When a `Temporary` entry's TTL is 0, it is deleted from the ledger and is permanently inaccessible."* <https://developers.stellar.org/docs/learn/fundamentals/contract-development/storage/state-archival>
- **Scout `ineffective-extend-ttl`** (Medium) existe, mas mira outra coisa: `extend_ttl` chamado com argumentos iguais/menores. <https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/ineffective-extend-ttl>
- **Medido: 51/75 (68%) importam `extend_contract_data_ttl` e 41/75 (54%) importam `extend_current_contract_instance_and_code_ttl`** `[medido]`.

**Correção importante a uma versão anterior deste documento:** eu havia concluído que o CAP-0066 tinha praticamente eliminado a classe. **Está errado.** Auditorias posteriores ao Protocol 23 continuam reportando TTL, e uma delas é **High**:

| Achado | Sev | Substância |
|---|---|---|
| **OZ stellar-contracts v0.5.0 `H-01`** *TTL Mismatch Enables Duplicate Modules And Can Brick Removal* | **High** | Duas entradas persistentes representando **um** fato, só uma com TTL renovado na leitura → registro duplicado de módulo + entradas irremovíveis. Verbatim: *"persistent entries that expire are archived and can be recovered, but **they are not automatically restored**"* |
| Veridise Scaffold Stellar `V-AHA-VUL-003` | Medium | *"Storage items TTLs not updated in Registry contract"* |
| Certora Spectra Bridge `L-05` | Low | *Missing TTL extension for persistent storage `DataKey` entries can lead to DoS* |
| Certora Blend v2 `I-01` | Info | `set_reserve` também não estende TTL |
| OtterSec XAUm `SUG-03`, OtterSec Sollpay `SUG-03` | Sug | TTL de mint request / wallet não mantido |
| OZ v0.1.0 `L-04`, OZ v0.5.0 `M-02` | Low/Med | Instance TTL não atualizado em todas as operações |

Por que o CAP-0066 não resolve: a restauração automática só cobre entradas **declaradas na restore list** da transação (montada por simulação), e **não conserta dessincronização de TTL entre entradas pareadas** — que é o bug `H-01` da OZ. O CAP-0066 muda o custo e a UX; não torna TTL um não-problema.

**Uma sub-classe adicional que eu não tinha:** *erro na chamada de `extend_ttl` em si*, com quatro achados independentes:
- Veridise HOT Bridge `V-HOTB-VUL-004` — **ordem dos argumentos trocada**: `extend_ttl(INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD)` contra a assinatura `extend_ttl(threshold, extend_to)`.
- Runtime Verification / Band Protocol `A4` (Medium) — `relay` **sempre falha** quando `MaxTTL == max_entry_ttl`, porque o host rejeita `new_live_until > max_live_until` para durabilidade não-persistente. RV abriu issue com o time do Soroban.
- RV / Band `A7` (Medium) — usar `max_ttl` como *threshold* faz o bump disparar em toda invocação: **1000× o custo de escrita**.
- Scout `ineffective-extend-ttl` (Medium) — mesma família.
- RV / StellarBroker `B1.3` — *griefing* de custo: qualquer um pode forçar outro a pagar a extensão do instance TTL.

Ver §B.2, §B.8 e §C.4.

### A.8 — Auth depois da escrita ⚠️ **CONFIRMADA em espírito, ERRADA no par de funções**

A tabela pergunta a ordem de `require_auth` vs `put_contract_data`. Esse par **não importa em Soroban**: se `require_auth` falhar, o host aborta o frame e faz rollback do `RollbackPoint` (storage + eventos + auth). Escrever antes de autenticar é inócuo.

O par que **importa** está na doc oficial de autorização, verbatim:

> *"The only requirement for such cases to be handled correctly is to ensure that the `require_auth` calls for an `Address` happen **before** the corresponding sub-contract calls."*
> <https://developers.stellar.org/docs/learn/fundamentals/contract-development/authorization>

E o guia de auth explica o ataque concreto:

> *"Even though the invoking function may not require the `user`'s authorization, it's recommended to authorize the `user` at the entry point. **Without that, the authorized inner `add()` call can be front-run by anyone without being wrapped in `add_with()`.**"*
> <https://developers.stellar.org/docs/build/guides/auth/contract-authorization>

Auditores **de fato** reportam ordem de autorização, o que sustenta manter a linha (com o par corrigido):
- **Runtime Verification / EquitX**, `B1.1` — a autorização deve ser a **primeira** operação da função.
- **OZ stellar-contracts v0.7.0**, `M-06` *"Arbitrary External Calls Possible in `do_check_auth`"* — chamada externa dentro do próprio caminho de autenticação.

**Reescrita:** o sinal é a ordem de `a.0`/`a._` vs `d._`/`d.0` (`call`/`try_call`) no CFG — não vs `l._`. Continua sendo análise de ordem, continua sendo nível A, mas agora aponta para um ataque real e tem corroboração.

---

## B. Classes que você não previu

Ordenadas por (valor × detectabilidade). As três primeiras são as que justificam a existência do soroguard.

---

### B.1 — Versão do `soroban-sdk` com CVE de bypass de autorização · **DETECTÁVEL** 🥇

**O que é.** `CVE-2026-26267` / `GHSA-4chv-4c6w-w254`, **High**, publicado 2026-02-13 contra `soroban-sdk-macros`. Verbatim do advisory:

> *"The bug is that `#[contractimpl]` generates code that uses `MyContract::value()` style calls even when it's processing the trait version. This means if an inherent function is also defined with the same name, **the inherent function gets called instead of the trait function**. […] If the trait version contains important security checks, such as **verifying the caller is authorized**, that the inherent version does not, **those checks are bypassed**."*
>
> <https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-4chv-4c6w-w254>

Versões afetadas: `<= 22.0.9`, `23.0.0–23.5.1`, `25.0.0–25.1.0`. Patch: 22.0.10 / 23.5.2 / 25.1.1.

**Por que é específico de Soroban.** Não tem análogo em EVM: é a macro de dispatch do SDK escolhendo o símbolo errado em tempo de compilação. **O fonte parece correto numa leitura apressada.** Uma revisão do repositório lê o trait com `require_auth` e conclui que está protegido; o WASM deployado exporta a função inerente sem o check. A colisão de nomes está visível no fonte — o que o fonte não diz é com qual SDK o binário deployado foi compilado.

**Detectabilidade: DETECTÁVEL.** O WASM carrega a versão exata do SDK na custom section `contractmetav0`, chave `rssdkver`, como `<semver>#<git-sha40>`.

**Medido no corpus** `[medido]`:

```
41 / 75 contratos declaram rssdkver; 34 sem o metadado (análise degradada: ausência de dado, não de risco)
34 / 75 contratos (45%; 83% dos 41 que declaram) em faixa afetada
versões afetadas presentes: 20.2.0×2 20.5.0×4 21.1.1×1 21.6.0×1 21.7.6×1 21.7.7×3
                            22.0.3×1 22.0.5×1 22.0.6×5 22.0.7×7 22.0.8×5 23.3.0×1 23.4.0×2
versões corrigidas presentes: 22.0.11×2 23.5.3×3 25.3.1×1 26.0.0×1
```

**Enquadramento honesto de evidência.** SDK < patch é nível **A**. "Este contrato tem bypass de auth" é nível **C** — o CVE só dispara se houver colisão de nome entre um `impl Contract` inerente e um `impl Trait for Contract`, o que não se lê do bytecode. O achado correto é *"exposição confirmada, exploração não determinável do artefato"* — por isso o soroguard o emite com severidade **Low** e registra o *High* do advisory só na evidência A. O complemento com linters de fonte é direto: o fonte mostra a colisão; o artefato mostra **qual SDK realmente compilou o que está no ledger.**

Mesma técnica cobre os outros advisories com versão-alvo:
- `GHSA-x2hw-px52-wp4m` (soroban-sdk, Medium) — igualdade de `Fr` sem redução modular, com impacto declarado de *"incorrect authorization decisions or validation bypasses"*. Patch 22.0.11 / 23.5.3 / 25.3.0. Faixa efetiva começa em **22.0.0**: `crypto::bls12_381::Fr` surge em soroban-sdk v22.0.0 (ausente em v21.7.7) e `crypto::bn254::Fr` em v25.0.0. O soroguard só emite o achado se o WASM importar alguma host function BLS12-381/BN254 (`c.4`–`c.o`, `c.r`–`c.z`) — filtro heurístico, declarado como nível C. Medido: 22 contratos na faixa de versão, **1** passa no filtro de import `[medido]`.
- `GHSA-96xm-fv9w-pf3f` (soroban-sdk, Medium) — overflow em `Bytes::slice` / `Vec::slice` / `gen_range`. Patch 25.0.1.
- `CVE-2026-24783` / `GHSA-x5m4-43jf-hh65` (`soroban-fixed-point-math`, **High**) — `mulDiv` ignora sinal do divisor. Patch 1.3.1 / 1.4.1. É a crate da Script3, dependência da família Blend.
- `CVE-2026-32129` (`soroban-poseidon`, High 8.7) — colisões por padding implícito. Patch 25.0.1.

Índice: <https://github.com/stellar/rs-soroban-sdk/security/advisories>

---

### B.2 — Tipo de storage errado para o dado (Temporary / Persistent / Instance) · **DETECTÁVEL** 🥈

**O que é.** Três durabilidades com semânticas irreconciliáveis, escolhidas por argumento numa chamada:
- **Temporary** — expira e é **apagado permanentemente**, sem restore possível.
- **Instance** — uma única ledger entry de **64 KiB** compartilhada com o code; cresce sem limite se você guardar coleção ali; todas as escritas serializam.
- **Persistent** — por chave, restaurável (CAP-0066).

**Por que é específico de Soroban.** Não existe em EVM. E a doc oficial trata como red flag de revisão, verbatim (<https://developers.stellar.org/docs/build/guides/storage/storage-strategies>):

> 🚩 *"**Funds-critical data in `temporary()`** — Expiry deletes it permanently; there is no restore."*
> 🚩 *"Unbounded `Map`/`Vec` under one key"* · 🚩 *"Hot mutable data in `instance()` with many independent writers"*

Achados reais de **dado crítico em Temporary**:
- **Veridise / Wombat**, `V-WOM-VUL-012` — Medium, *"Temporary storage usage for critical data in multi-step procedures"*, verbatim: *"according to Soroban documentation, temporary storage should only be used for non-critical information that can be easily reproduced if deleted… **if the data expires, the process cannot be completed, leading to loss of funds for users**."*
- **OtterSec / Soroban Governor**, `OS-SGR-ADV-02` — Medium, *"Insufficient TTL for Checkpoints"*: checkpoints em storage temporário com TTL de 8 dias contra um `vote_period + grace_period` que pode excedê-lo → `contract::close` aborta ou usa total supply errado. **O melhor caso público de expiração de TTL causando bug lógico.**
- **OtterSec / Matrixdock XAUm**, `SUG-02` *"Short-Lived Pending State Utilizes Instance Storage"*.

Corroboração externa:
- **Veridise**, sobre Soroban: *"Putting ever-growing data in instance storage can spike costs and risk DoS; even persistent storage needs careful design so entries don't grow unchecked."* <https://veridise.com/audits/soroban/>
- **Scout `dynamic-storage`** (Resource Management / Medium): *"Dynamic types in instance/persistent storage cause unnecessary growth or storage vulnerabilities."* <https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/dynamic-instance-storage>
- **CertiK**: <https://www.certik.com/blog/soroban-contract-state-management>
- **OpenZeppelin**: *"The library handles the TTL of only `temporary` and `persistent` storage entries declared by the library. The **`instance` TTL management is left to the implementor**."*

**Detectabilidade: DETECTÁVEL — e eu verifiquei.** `put_contract_data` é `l._(k: Val, v: Val, t: StorageType)`, e `StorageType` é `#[repr(u64)]` passada por marshalling direto: `Temporary=0`, `Persistent=1`, `Instance=2` (<https://docs.rs/soroban-env-common/latest/soroban_env_common/enum.StorageType.html>). No WASM ela aparece como o **terceiro argumento literal** da chamada.

**Medido no corpus** `[medido]`:

```
208 call sites de put_contract_data
190 (91%) com StorageType como (i64.const N) literal no call site
  → Instance 127 · Persistent 53 · Temporary 10
 18 ( 9%) com o argumento em local/computado → análise degradada nesses sites
```

O soroguard consegue dizer, por entrypoint e por call site: *"grava em Temporary"*, *"grava em Instance"*. Nenhuma ferramenta de fonte publicada reporta isso por call site do artefato deployado. **A predominância de Instance (127/190) é ela própria o achado que a Veridise descreve.**

---

### B.3 — `require_auth` presente, mas no endereço errado · **PARCIALMENTE DETECTÁVEL** 🥉

**O que é.** A função chama `require_auth`, mas no `Address` que o *atacante* passou como argumento, não no que está gravado no storage. O `require_auth` passa trivialmente (o atacante assina pelo próprio endereço) e a checagem não protege nada.

É o **falso negativo dominante** do detector de reachability: `a.0` é alcançável, logo a linha 1 não dispara.

Corroboração — é a forma mais citada no ecossistema:
- **Scout `unrestricted-transfer-from`** — Authorization / **Critical**: *"This argument (`from`) comes from a user-supplied argument."* <https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/unrestricted-transfer-from>
- **Scout `unprotected-mapping-operation`** — **Critical**, mesma forma com a *chave*.
- **Scout `unnecessary-admin-parameter`** — Authorization / Medium: admin vindo por parâmetro em vez de storage.
- **OpenZeppelin, auditoria v0.3.0, `H-01`** — o macro `#[has_role]` faz `ensure_role` **sem** `require_auth`, verbatim:
  > *"introduces security risks by **decoupling authentication (`require_auth()`) from authorization (`ensure_role`)**. It verifies that an arbitrary `Address` holds a role but does not authenticate the signature of this address. […] The macro's design creates a **false sense of security**."*
  
  O macro foi **mantido** mesmo depois do achado (porque `require_auth` duplicado no mesmo address causa panic em Soroban), então o footgun é permanente por design.
- **Valkyri**, lista de padrões observados: *"admin address taken as a user param instead of read from storage"*. <https://blog.valkyrisec.com/top-10-ways-soroban-contracts-get-hacked/>

**Detectabilidade: PARCIALMENTE.** A pergunta é dataflow intraprocedural sobre locals do WASM: o `Val` passado a `a.0` vem de um parâmetro do export, ou de um `l.1 get_contract_data`? Isso é decidível na maioria dos casos por use-def em SSA sobre a função de entrada, e é **muito** mais barato que reachability interprocedural. Marco PARCIALMENTE porque (a) casos legítimos existem (`transfer(from, …)` autoriza `from`, que é parâmetro — e está correto), e (b) quando o endereço passa por um helper monomorfizado a origem se perde. O discriminante útil é *"o endereço autorizado é parâmetro **e** o entrypoint também escreve numa chave derivada de outro parâmetro"*.

---

### B.4 — Auto-autorização do contrato invocador direto · **NÃO DETECTÁVEL**

**O que é.** Em Soroban, se o contrato A chama o contrato B e B faz `require_auth(A)`, **passa automaticamente, sem assinatura nenhuma**. Doc verbatim:

> *"all the `require_auth` calls made on behalf of the **direct** invoker contract `Address` are considered to be authorized (but not any calls on behalf of the contract deeper down the stack)."*
> <https://developers.stellar.org/docs/learn/fundamentals/contract-development/authorization>

CAP-0046-11 acrescenta que a prioridade é do invoker: uma `SorobanAuthorizationEntry` assinada para A *"will stay non-matched and non-exhausted"* — ou seja, uma assinatura pode ficar silenciosamente não consumida.

**Por que é específico de Soroban.** É o oposto do EVM, onde `msg.sender` sendo um contrato não confere privilégio nenhum. E casa exatamente com o aviso da OZ: *"Soroban's invoker auth is single-level by default — the token contract that triggered the operation is not the direct caller of the module hook, so `token.require_auth()` does not succeed out of the box."*

**Detectabilidade: NÃO DETECTÁVEL.** A conclusão depende de *quem chama*, que não está no bytecode do chamado. Pode virar **nível B**: observar on-chain se as invocações desse entrypoint vêm de contratos (`Address::Contract`) ou de contas. É um monitor legítimo, não um detector estático.

---

### B.5 — Construtor do novo WASM nunca roda no upgrade · **PARCIALMENTE DETECTÁVEL**

**O que é.** CAP-0058, verbatim: *"When the contract has its code updated it is **not** considered created and thus constructor won't be called."* Logo, se o WASM novo introduz chaves de storage que o seu `__constructor` inicializaria, elas ficam **não inicializadas** depois do upgrade. O próprio guia oficial demonstra o trap num teste: *"New contract version requires the `NewAdmin` key to be initialized, but since the constructor hasn't been called, it is not initialized, thus calling `try_upgrade` won't work."* <https://developers.stellar.org/docs/build/guides/conventions/upgrading-contracts>

A invariante derivada: **o protocolo garante que rodou o construtor do WASM *inicial*, não o do WASM *atual*.**

Agravante de forma de dado: mudar a contagem de campos de um `#[contracttype]` entre versões **trapa no host** e é irrecuperável:
> *"This traps with `Error(Object, UnexpectedSize)`. […] **There is no way to catch or recover from the mismatch at the contract level.**"*
> <https://developers.stellar.org/docs/build/guides/storage/migrate-contract-storage>

OpenZeppelin avisa das três faces disso no header do módulo `Upgradeable`:
> *"it does NOT perform deeper checks: Ensuring that the new contract does not include a constructor, **as it will not be invoked**; Verifying that the new contract includes an upgradability mechanism, preventing an **unintended loss of further upgradability capacity**; Checking for storage consistency."*

A OZ removeu o trait `Migratable` inteiro por isso (PR #585, commit `e7722e4`, 2026-02-26) e passou a documentar padrões de schema version.

**Detectabilidade: PARCIALMENTE.** Do WASM deployado dá para ver, tudo nível A: (i) exporta `__constructor` **e** `update_current_contract_wasm` é alcançável → risco de construtor órfão pós-upgrade; (ii) exporta `upgrade`-like mas **não** exporta nenhum `migrate`/`handle_upgrade`/`set_schema_version` → nenhum caminho de migração; (iii) **não** alcança `update_current_contract_wasm` num contrato que foi deployado por upgrade → perda de upgradability. O que **não** dá é comparar shapes de storage entre versões a partir de um único WASM. Nível B ajuda: o host emite um evento `SYSTEM` com `topics = ["executable_update", old, new]` em todo upgrade, então o histórico de upgrades é observável.

---

### B.6 — PRNG do host usado em decisão com valor · **DETECTÁVEL**

**O que é.** `p._ prng_reseed`, `p.0 prng_bytes_new`, `p.1 prng_u64_in_inclusive_range`, `p.2 prng_vec_shuffle`. O PRNG é *frame-local*, semeado pelo ledger, e não é imprevisível para quem submete a transação.

- **Scout `insufficiently-random-values`** — Block Attributes / **Critical**: *"all random numbers are under validator control."* <https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/insufficiently-random-values>
- É uma das poucas classes que a CoinFabrik classifica como Critical.

**Detectabilidade: DETECTÁVEL.** Import do módulo `p` + alcançabilidade a partir de um entrypoint que também escreve estado ou cruza `call`.

**Medido: só 4 dos 75 contratos importam qualquer `p.*`** (3× `prng_u64_in_inclusive_range`, 1× `prng_bytes_new`) `[medido]`. Base rate de 5% → **quando dispara, é um achado de alta precisão**. O oposto de `call` a 82%.

---

### B.7 — Aritmética sem `overflow-checks` no perfil de release · **PARCIALMENTE DETECTÁVEL**

**O que é.** Sem `overflow-checks = true` em `[profile.release]`, aritmética inteira **wrapa silenciosamente** no WASM de produção. O perfil recomendado oficialmente inclui a flag:

```toml
[profile.release]
opt-level = "z"
overflow-checks = true
debug = 0
strip = "symbols"
debug-assertions = false
panic = "abort"
codegen-units = 1
lto = true
```
<https://developers.stellar.org/docs/build/smart-contracts/getting-started/hello-world>

- **Scout `overflow-check`** — Arithmetic / **Critical**: *"Use `overflow-checks = true` in the `Cargo.toml` release profile."* <https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/overflow-check>
- **Scout `integer-overflow-or-underflow`** — Arithmetic / Critical.
- Relevante para Soroban em particular porque `i128` é aritmética **no guest**: o env expõe só conversões (`i.3 obj_from_u128_pieces`, `i.6 obj_from_i128_pieces`…), não as operações. O host não protege.

**Detectabilidade: PARCIALMENTE, e não validei.** Com a flag ligada, o rustc emite comparação + `br_if` + caminho de panic depois de cada operação; sem ela, a operação é nua. O padrão estrutural é reconhecível mas exige matching de CFG que eu não implementei nem testei.
O atalho por string **não serve**: procurei as mensagens do rustc (`attempt to add with overflow` etc.) e **só 10 dos 75 contratos as têm** `[medido]` — porque `panic = "abort"` + `strip = "symbols"` + `opt-level = "z"` eliminam as mensagens. Ausência de string não é ausência de check.
**UNKNOWN:** não encontrei nenhuma ferramenta pública que faça essa detecção a partir do WASM. Se for implementar, precisa de um par de contratos de controle compilados com e sem a flag para calibrar.

---

### B.8 — Dado não-limitado em Instance storage → DoS · **PARCIALMENTE DETECTÁVEL**

**Esta é, em volume de achados, a classe Soroban-específica mais reportada que existe** — e eu a tinha como um subitem de "tipo de storage". Ela merece linha própria.

Instance storage é **uma única ledger entry**, carregada inteira a cada invocação, limitada a 64 KiB (o limite de entrada; alguns relatórios citam 128 KiB, que é o limite de WASM — a doc do Protocol 27 diz **entrada ≤ 65.536 B**). Guardar coleção que cresce com o número de usuários ali é DoS garantido.

| Achado | Sev | Protocolo |
|---|---|---|
| **OtterSec `OS-SWP-ADV-00`** *Incorrect Use Of Instance Storage* — *"As the instance storage reaches its capacity (64 KB), disruptions of legitimate operations of SoroswapFactory may occur"* | **High** | Soroswap |
| **Veridise `V-PHX-VUL-003`** *Unbounded instance storage* | **High** | Phoenix |
| **Veridise `V-HYD-VUL-002`** *Linked list is saved into instance storage* | **High** | HiYield |
| **Veridise `V-WOM-VUL-007`** *Unbounded User Data in Instance Storage Leads to Denial of Service* | **High** | Wombat |
| **RV `A10`** — *"Instance storage packs every key-value pair into a single ledger entry… The standard Soroban practice for unbounded per-user data is to use persistent storage"* | Medium | OctoLend |
| Veridise `V-OBT-VUL-010`; RV Soroswap Aggregator `B5` (**não corrigido**); Veridise `V-HYD-VUL-033` (papéis de access control deveriam ir para persistent) | Med/Warn | vários |
| **Veridise `V-GRP-VUL-007`** *Storing all project registrations in one ledger entry causes storage exhaustion* | High | GrantPicks |

**Quatro Highs em quatro protocolos independentes.** A remediação da OtterSec no Soroswap avisa ainda que *nem persistent resolve* se o valor for um vetor — o limite é por entrada, não por durabilidade.

**Detectabilidade: PARCIALMENTE.** Do bytecode: `put_contract_data` com `StorageType == 2` (Instance) num entrypoint cuja chave é derivada de um parâmetro `Address` (isto é, uma coleção por usuário) é a assinatura exata. O primeiro termo eu meço (§B.2: **127 dos 190 call sites literais são Instance**). O segundo precisa do dataflow de §B.3. Sem ele, o sinal tem base rate alta demais.

---

### B.9 — Injeção na árvore de autorização (auth-tree phishing) · **PARCIALMENTE DETECTÁVEL**

**O que é.** Um contrato malicioso insere entradas de autorização adicionais na árvore que o usuário assina. Como `require_auth` só verifica que *existe* um nó correspondente, e a árvore inteira é assinada de uma vez, o usuário aprova mais do que pretendia. É o ataque que o guia oficial de auth descreve como front-running de sub-chamada (§A.8), visto do outro lado.

- **OtterSec / Soroswap**, `OS-SWP-SUG-02` *"Authorization Required For Token Transfer"*, verbatim:
  > *"malicious contracts can insert harmful authorization objects into the authorization tree… **stealing the user's entire balance of any token**."*
- **Certora / Aquarius AMM**, `M-02` *"Lack of scam protection for AMM Users"* — cita explicitamente o achado da OtterSec no Soroswap e a issue aberta no soroban (#1092). <https://www.certora.com/reports/aquarius-amm-security>
- **Runtime Verification / Soroswap Aggregator**, `A3` — **High**, *"Subcontracts called from Aggregator have potential to call into malicious code"*.

**Por que é específico de Soroban.** É consequência direta do modelo de árvore de autorização: não existe equivalente em EVM, onde cada `approve` é uma transação separada e explícita.

**A defesa é exatamente o sinal da linha #10:** `require_auth` no entrypoint, **antes** da sub-chamada, para que a autorização interna não possa ser reaproveitada fora do wrapper. Logo esta classe e a de ordem são a mesma linha vista de dois ângulos, e eu as trato juntas em E#10.

**Detectabilidade: PARCIALMENTE** — o sinal (ordem `a.0` antes de `d._`) é nível A; a exploração depende de quem constrói a transação.

---

### B.10 — Cache obsoleto em read-compute-write com auto-aliasing · **PARCIALMENTE DETECTÁVEL**

**O que é.** O contrato lê estado para uma variável local, opera, e grava de volta — mas duas referências ao *mesmo* registro coexistem no frame (ex.: liquidante == liquidado, remetente == destinatário), e a segunda escrita sobrescreve a primeira. **Três Criticals independentes:**

- **OtterSec / Blend v1**, `OS-BCL-ADV-00` — **Critical**, *"Incorrect Implementation Of Self Liquidation"*: `user_state` em memória fica obsoleto quando o preenchedor é o próprio liquidado.
- **OtterSec / Soroban Governor**, `OS-SGR-ADV-00` — **Critical**, *"Balance Cache Inconsistency"* (self-transfer).
- **OpenZeppelin stellar-contracts v0.5.0**, `C-01` — **Critical**, *"Unbounded Inflation via Self-Recovery in `recovery_address`"*: `lost_wallet == new_wallet` dobrava saldo exponencialmente (`b → 2b → 4b → 8b`).
- Também: RV EquitX `A4`; Certora Blend `BLRC-002`, que recomenda um *drop-guard* como remediação estrutural.

**Relevância direta:** `PROBLEMA.md` já identifica `storage.update(&key, |v| …)` como ponto cego herdado, e observa que no bytecode ele vira `get_contract_data` + `put_contract_data` — *"nossa análise a enxerga"*. **Está certo, e esta é a classe de bug que isso caça.** Vale mais do que o documento original sugere: é a única família com três Criticals.

**Detectabilidade: PARCIALMENTE.** O padrão `l.1 get_contract_data(k1)` … `l.1 get_contract_data(k2)` … `l._ put(k1)` … `l._ put(k2)` dentro de um entrypoint, onde `k1` e `k2` derivam de **dois parâmetros `Address` distintos**, é estrutural e detectável. O que não é detectável é se o contrato compara os dois antes. Um detector honesto reporta *"entrypoint com duas chaves derivadas de parâmetros distintos em read-modify-write; verificar aliasing"* — nível A no padrão, nível C na conclusão.

---

### B.11 — Fluxos que estouram o limite de recursos do ledger · **PARCIALMENTE DETECTÁVEL**

**O que é.** Não é "gas caro". É **funcionalidade que se torna impossível de executar** quando o estado do usuário cresce — em protocolos de empréstimo, isso significa posições que não podem ser liquidadas.

- **Certora / Blend v1**, `BL-001` — **CRITICAL**, verbatim: *"under specific flows and given certain user states… the Soroban resource limit is invariably hit"* → usuários com muitos ativos ficam **inliquidáveis**. A mitigação recomendada é reutilizável: definir um *high watermark* de 80–90% do limite de recursos e perfilar todos os testes unitários contra ele.
- **Certora / Slender**, `C-3` — **Critical**: *"will revert as soon as the number of reserves… is sufficiently large (e.g., **more than ~5**)"*.
- **Veridise / Phoenix**, `V-PHX-VUL-011` — *"Soroban Storage DoS Pattern in Factory contract"*, com a melhor explicação pública de contenção de footprint: *"Soroban transactions include something called the Footprint… in order to execute `create_liquidity_pool` the footprint must include the Ledger Key associated with this vector"* → serializa toda criação de pool.
- Red flag oficial: *"**A loop that updates every user** — It dies at the 200-writes-per-transaction cap."* Limites do Protocol 27: 400 entradas de footprint, **200 entradas escritas**, 400M instruções, entrada ≤ 64 KiB, chave ≤ 250 B, WASM ≤ 128 KiB, **eventos + retorno ≤ 16.384 B**. <https://developers.stellar.org/docs/build/guides/storage/storage-strategies>
- **Scout `dos-unbounded-operation`** (DoS / Medium), `dos-unexpected-revert-with-storage` (DoS / Medium).

**Dois Criticals.** Esta é, junto com Instance storage, a classe de DoS que importa em Soroban — e nenhuma das duas estava na tabela.

**Detectabilidade: PARCIALMENTE.** `put_contract_data` dominado por um back-edge do CFG é estrutural e detectável. O *bound* do loop não é. Também detectável: contagem estática de call sites de `l._` num caminho de entrypoint como proxy do teto de 200 escritas.

---

### B.12 — Expiração de TTL usada como prazo de segurança · **NÃO DETECTÁVEL**

Incluo porque é contra-intuitivo e derruba um padrão inteiro. Verbatim, doc oficial:

> *"**Anyone can extend any entry's TTL.** `ExtendFootprintTTLOp` has no access control, so **expiry is never a security boundary**: if your logic assumes an authorization lapses when its entry expires, a bad actor can keep that entry alive indefinitely."*
> *"It is also unsafe to rely on an entry expiring. […] **Temporary storage is a cost optimization, it's not a mechanism of enforcing any time-based invariants.**"*
> <https://developers.stellar.org/docs/build/guides/storage/storage-strategies> · <https://developers.stellar.org/docs/build/guides/storage/choosing-the-right-storage>

O padrão correto (exemplo de leilão da própria doc) é gravar `expiration_ledger_seq` **dentro do valor** e checar na leitura.

**NÃO DETECTÁVEL.** É semântica de intenção. Vale como item de checklist manual no documento de threat model, marcado nível C, nunca como achado automático.

---

### B.13 — O que realmente causou perda de dinheiro (e por que não é detectável)

Honestidade intelectual obriga: nenhuma das classes acima causou os incidentes reais de Soroban.

| Incidente | Data | Perda | Causa raiz | Detectável do WASM? |
|---|---|---|---|---|
| **YieldBlox** (pool no Blend V2) | 2026-02-22 | **US$ 10,97 M** | Configuração de oráculo: USTRY listado como colateral, precificado por VWAP do Reflector sobre um book SDEX com <US$1/hora de volume. Sem deviation check, sem piso de liquidez, sem circuit breaker. | **NÃO** — é config + profundidade de mercado, nem contrato é |
| **Comet AMM** (BLND-USDC) | ~2026-08-26 | ~US$ 717 k | O pool aceitava swap com `token_in == token_out`, corrompendo as reservas; loop ~36× com flash loans do Blend. TVL DeFi do Stellar caiu ~60% em um dia. | **NÃO** — invariante de negócio |
| **Arquivamento de estado** (mainnet, bug do próprio host) | 2025-09-04 → 10-23 | 0 (integridade) | CAP-0062: o scan de eviction não carregava a versão mais recente da entrada. **478 entradas corrompidas, 84 permanentemente.** | N/A — bug do host, não do contrato |

Fontes: <https://rekt.news/yieldblox-rekt> · <https://blocksec.com/blog/yieldblox-dao-incident-on-stellar-oracle-misconfiguration-enabled-a-10m-drain> · <https://github.com/CometDEX/comet-contracts-v1/pull/12> (fix "reject same-token swaps", merged 2026-09-02, release v1.1.0) · <https://stellar.org/blog/foundation-news/state-archival-issue-post-mortem>

E o mesmo padrão aparece na maior auditoria competitiva do ecossistema. **Code4rena Blend V2** (US$ 125 k, fev–mar 2025, 27k LoC, com verificação formal da Certora): 3 High + 18 Medium, e **nenhum High ou Medium** é de missing-auth, tipo de storage ou evento. São `d_supply` incorreto após flash loan, roubo de emissions, ratio de utilização >100%, duplicate reserves em auction, divisão antes de multiplicação, inflation attack em vault. A única aparição das nossas classes é `I-01` (Info): `set_reserve` não estende TTL. <https://code4rena.com/reports/2025-02-blend-v2-audit-certora-formal-verification>

Vale a contra-evidência, porém: na **Blend v1** o achado mais grave da Certora foi `BL-001` **Critical** — limite de recursos do ledger (§B.11) — e o da OtterSec foi `OS-BCL-ADV-00` **Critical** — cache obsoleto em self-liquidation (§B.10). **As duas são classes específicas de plataforma e as duas estão na taxonomia revisada.** A conclusão correta não é “análise estática não acha nada que importa”. É: *o que importa se divide entre **invariante econômica** (não detectável) e **padrão estrutural de plataforma** (parcialmente detectável) — e a tabela original não cobria nenhum dos dois.* É por isso que a taxonomia revisada cresce de 9 para 16 linhas em vez de encolher.

> **A conclusão que isso impõe ao posicionamento do soroguard:** a taxonomia da tabela é a taxonomia dos bugs *detectáveis por lint*, não a dos bugs que *custam dinheiro*. Isso não invalida a ferramenta — o entregável do tranche #2 é um threat model + monitoring plan, não uma auditoria. Mas o documento gerado **não pode** insinuar cobertura de risco econômico. A frase honesta é: *"esta análise cobre a superfície de controle de acesso e ciclo de vida de estado derivável do artefato deployado; não cobre invariantes econômicas nem configuração de oráculo, que são a origem de 100% das perdas públicas do ecossistema até 2026-09."* Dizer isso **aumenta** a credibilidade diante de um revisor de tranche.

### Não-classe: reentrância clássica ❌ **FOLCLORE DE EVM, NÃO SE APLICA**

Não está na sua tabela — correto. Registro para que não entre depois.

Fonte primária, `soroban-env-host/src/host/frame.rs`:

```rust
/// Determines the re-entry mode for calling a contract.
pub(crate) enum ContractReentryMode {
    Prohibited,   // Re-entry is completely prohibited.
    SelfAllowed,  // only directly into the same contract
    Allowed,      // #[allow(dead_code)] — nunca construído no repo
}
```

`call_n_internal` varre a **pilha inteira** de contextos (`reentry_distance`) e devolve `"Contract re-entry is not allowed"`. Tanto `call` quanto `try_call` usam `Prohibited`. A única exceção é self-reentry de `__check_auth`, especificada em CAP-0046-11: *"Only self-reentrancy is allowed, i.e. re-entering any other contract than A in the example is not still not allowed."*

Corroboração pelo lado das ferramentas: **o Scout tem `reentrancy` na taxonomia mas os detectores `reentrancy-1`/`reentrancy-2` existem só para ink!, não para Soroban.** Não há incidente nem advisory de reentrância em Soroban.

Checks-effects-interactions **não é** controle de reentrância aqui.

---

## C. Classes suas que provavelmente são ruído

### C.1 — "Delegação de privilégio" (`authorize_as_curr_contract`) — **REBAIXAR; o sinal escolhido não detecta o bug real**

Argumento em três pernas:

1. **Base rate: 13/75 = 17% dos contratos de mainnet importam `a.3`** `[medido]`. Um sinal presente em 1 de cada 6 contratos não separa nada.
2. **Um único achado público em ~40 relatórios lidos**, e é *Suggestion*: OtterSec Rango `SUG-02` (§A.6). Zero dos 36 detectores Soroban do Scout cobrem o mecanismo.
3. **O sinal proposto não detecta esse bug.** O achado da Rango é sobre a árvore de `InvokerContractAuthEntry` ser montada **achatada em vez de aninhada** — estrutura de dados construída em runtime. "Importa `a.3`" é igualmente verdadeiro no uso correto e no incorreto.
4. **O mecanismo é o remédio, não a doença.** CAP-0046-11 define `authorize_as_curr_contract` como a forma *correta* de um contrato autorizar sub-invocações que ele mesmo faz, limitada à **próxima e única próxima** chamada: *"allows A to specify authorizations on calls that `B.f` performs"*. Um contrato que faz composição e **não** usa `a.3` frequentemente está pior, não melhor — é o caso que a OZ descreve, em que `token.require_auth()` simplesmente não funciona porque a invoker auth é single-level.

**Mantenha como fato de inventário** no DFD ("este entrypoint delega autoridade do contrato para a próxima chamada"), **não como issue de STRIDE.** O único bug real conhecido (Rango `SUG-02`) é sobre a *forma da árvore*, que não é derivável do bytecode — nem o import de `a.3` nem sua ausência dizem nada sobre ele.

### C.2 — "Fronteira de confiança não declarada" (`call`/`try_call`) — **REBAIXAR de ameaça para elemento do DFD**

**62/75 = 82% dos contratos importam `call`** `[medido]`. Composabilidade é o modo normal de operação do Soroban, não um desvio.

Nenhum auditor publica "trust boundary não declarada" como classe de achado. O que existe é o caso estreito e **diferente**: chamar um endereço *fornecido pelo usuário* (`malicious-contract-injection` na lista de detectores candidatos da OZ).

Esta linha, porém, é **exatamente** o que o `PROBLEMA.md` diz que o DFD precisa: *"fronteiras de confiança = onde `require_auth` acontece e onde `call` cruza para outro contrato."* Ela é ouro como **estrutura do diagrama** e lixo como **linha do registro de ameaças**. Mover de tabela.

### C.3 — "Mutação silenciosa" + "Repúdio" — **FUNDIR e rebaixar**

São a mesma proposição (*"muda estado e não emite evento"*) escrita duas vezes para preencher duas letras do STRIDE. Isso é precisamente o antipadrão nº 2 da seção "O que faria isso virar slop".

Evidência de que é baixa severidade:
- Scout classifica `storage-change-events` como **Enhancement** — o degrau mais baixo dos quatro.
- Há **sete** achados de evento em sete auditorias distintas (tabela em §A.4) e **nenhum passa de Low**. A classe existe; a severidade, não.
- **O upgrade já emite evento sozinho.** O host publica um `SYSTEM` event com `topics = ["executable_update", old_executable, new_executable]` em todo `update_current_contract_wasm`. Um detector que reportasse "upgrade sem evento" seria falso 100% das vezes.
- **61/75 (81%) já alcançam `contract_event`** `[medido]`.

**Onde sobrevive com força:** função da interface de token que não emite o evento exigido por SEP-41 (`transfer`/`mint`/`burn`/`clawback`/`approve`). Aí é normativo, o Scout dá **Medium** (`token-interface-events`), e é detectável — o spec no WASM dá as assinaturas, e `x.1` dá a emissão.

**Ação:** uma linha só, chamada *"Ação com efeito externo sem evento correspondente"*, severidade baixa por padrão, **elevada a Medium só quando a assinatura bate com SEP-41**. E se não houver ameaça de Repúdio sustentada pelo bytecode, declarar a lacuna — como o próprio `PROBLEMA.md` manda.

### C.4 — "Archival de estado" como está escrita — **REESCREVER**

⚠️ **Esta é a única seção em que a minha primeira conclusão estava errada, e eu a corrijo aqui.** Escrevi inicialmente que o CAP-0066 tinha esvaziado a classe. Não tinha: há um **High** (OZ v0.5.0 `H-01`) e cinco outros achados posteriores ao Protocol 23 (tabela em §A.7). **A classe fica.**

O que está errado é o **predicado**, por três motivos:

1. **Genérico demais.** Não distingue durabilidade — e para Persistent/Instance o CAP-0066 transformou o risco em custo + restore list, não em perda de dados. Doc verbatim: *"there is no reason to write code in your contract to handle archived entries"*.
2. **Erra o bug de maior severidade.** O `H-01` da OZ não é "esqueceu de estender"; é **duas entradas pareadas com TTL dessincronizado**, uma renovada na leitura e a outra não. O sinal para isso é outro predicado.
3. **Ignora a direção inversa**, que a doc trata como mais perigosa: estender TTL **não protege nada**, porque qualquer um pode estender qualquer entrada (§B.12).

**Ação:** aposentar o predicado genérico e substituir por três específicos, todos nível A:
- *"grava dado com valor em `Temporary`"* (§B.2 — medido, literal no call site);
- *"grava em `Instance` chave derivada de parâmetro"* (§B.8 — quatro Highs);
- *"duas chaves escritas no mesmo entrypoint, só uma com `extend_contract_data_ttl`"* (o caso `H-01`).

### C.5 — "Auth depois da escrita" — **CORRIGIR o par de host functions**

Já argumentado em §A.8. O par atual (`require_auth` vs `put_contract_data`) é inócuo porque o panic faz rollback. O par que importa é `require_auth` vs `call`/`try_call`, e esse tem fonte normativa. Não remover; consertar.

---

## D. Exceções de ciclo de vida — a lista está incompleta

### D.1 — A regra certa não é uma lista de dois nomes, é o prefixo `__`

O host **recusa** qualquer invocação direta de função com prefixo `__`. Fonte primária, `rs-soroban-env/soroban-env-host/src/host/frame.rs`:

```rust
/// All the contract functions starting with double underscore are considered
/// to be reserved by the Soroban host and can't be directly called by another
/// contracts.
const RESERVED_CONTRACT_FN_PREFIX: &str = "__";
```

e em `call_n_internal`:

```rust
if !call_params.internal_host_call
    && SymbolStr::try_from_val(self, &func)?.to_string().as_str()
        .starts_with(RESERVED_CONTRACT_FN_PREFIX)
{
    return Err(self.err(ScErrorType::Context, ScErrorCode::InvalidAction,
                        "can't invoke a reserved function directly", &[func.to_val()]));
}
```

<https://github.com/stellar/rs-soroban-env/blob/main/soroban-env-host/src/host/frame.rs>

CAP-0058 diz o mesmo em prosa normativa: *"any contract function that has name starting with double `_`), i.e. it can be exported, but can not be invoked"* e *"Reserve a new special contract function `__constructor` that **may only be called by the Soroban host environment**."*

**Veredito:** a exceção deve ser `export.startsWith("__")`, não `["__constructor", "__check_auth"]`. Sua lista está **empiricamente completa hoje** — medi os 75 WASMs e os únicos exports de função com `__` são `__constructor` (41) e `__check_auth` (9) `[medido]` — mas o predicado por prefixo é o que o host garante, é à prova de futuro, e é uma linha de código a menos.

⚠️ **Cuidado de implementação:** `__heap_base` e `__data_end` também aparecem como exports (37× cada) mas são **globals**, não funções. Filtre por `(export … (func …))`, não por nome.

### D.2 — `__constructor`: a exceção é correta, e o motivo é mais forte do que você escreveu

`PROBLEMA.md` justifica com *"roda uma vez, atomicamente no deploy"*. Confirmado, e com garantias adicionais que valem citar no relatório gerado:

| Propriedade | Fonte |
|---|---|
| Roda **imediatamente após** criar a instance entry, *"without returning control to the caller"* | CAP-0058 |
| Falha → *"creation function fails and **all the changes are rolled back**"* | CAP-0058 |
| Roda **exatamente uma vez**: *"Every contract may only be created just once"* | CAP-0058 |
| **Não roda de novo no upgrade** (ver §B.5) | CAP-0058 |
| Protocol **22**; gated pela env version do **WASM**, não do ledger: WASM pré-22 *"are considered to not have any constructor, **even past protocol 22**"* | CAP-0058 |
| `require_auth` **funciona** dentro dele, mas num frame de auth diferente (`CREATE_CONTRACT_V2_HOST_FN`, não `CONTRACT_FN`) | CAP-0058 + `host/lifecycle.rs` |
| Roda com `ContractReentryMode::Prohibited` | `host/lifecycle.rs` |
| Deve retornar `Val::VOID`; qualquer outra coisa aborta a criação | CAP-0058 |

<https://github.com/stellar/stellar-protocol/blob/master/core/cap-0058.md>

### D.3 — `__check_auth`: a exceção é correta, e o argumento "circular" é literalmente verdade no host

Confirmado em CAP-0046-11: `__check_auth` é o único ponto do host onde self-reentrancy é permitida, justamente porque `require_auth(A)` de dentro de A resultaria em chamar `A.__check_auth` de novo. `account_contract.rs:166` é o único site do repositório inteiro que usa `ContractReentryMode::SelfAllowed`, com o comentário *"Allow self reentry for this function in order to be able to do wallet admin ops using the auth framework itself."*

Doc oficial: *"It is a reserved function, and it is invoked automatically by the Host … **It cannot be called manually.**"*

### D.4 — SEP-41 **não** adiciona exceções (mas quase)

Verifiquei método a método contra o SEP e contra a implementação do Stellar Asset Contract (`rs-soroban-env/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs`):

| Método | Muta? | `require_auth` em |
|---|---|---|
| `allowance`, `balance`, `decimals`, `name`, `symbol` | não | — |
| `approve(from, spender, …)` | sim | `from` |
| `transfer(from, to, amount)` | sim | `from` |
| **`transfer_from(spender, from, to, amount)`** | sim — **debita `from`** | **`spender` só** |
| `burn(from, amount)` | sim | `from` |
| **`burn_from(spender, from, amount)`** | sim — **queima de `from`** | **`spender` só** |
| `mint`, `clawback`, `set_authorized`, `set_admin` (SAC, fora do SEP-41) | sim | `admin` |
| `init_asset` (SAC, fora do SEP-41) | sim | **nenhum** — protegido por `has_asset_info()` one-shot + checagem de derivação do contract id |

<https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0041.md>

**Conclusão para o detector:** nenhum método SEP-41 muta estado sem *algum* `require_auth`, então o detector de reachability **não** dispara falso neles. Não precisa de exceção.

**Mas há uma armadilha na direção oposta:** `transfer_from` e `burn_from` mutam o saldo de `from` autenticando apenas `spender`. O consentimento de `from` mora inteiramente na allowance — que o SEP-41 avisa não ser reserva (*"An allowance is a spending limit, **not a reservation**. It does not lock any of `from`'s balance and **may exceed it**"*) e que a OZ guarda em storage **temporary**. É a classe B.3 em forma canônica, e o Scout dedica um detector Critical a ela (`unrestricted-transfer-from`).

### D.5 — **Exceções que faltam na sua lista** (as que realmente geram FP)

Medidas no corpus, em ordem de volume:

**(a) Exports read-shaped que "alcançam" escrita — 50/157 = 31,8% do ruído** `[medido]`
`balance`, `price`, `prices`, `lastprice`, `get_reserves`, `get_virtual_price`, `get_exchange_rate`, `estimate_swap`, `estimate_deposit`, `get_user_balance`, `get_total_underlying`, `get_rewards_info`, … 28 nomes distintos.
**Não é uma exceção semântica — é um defeito da análise.** Causa raiz verificada: helpers de storage monomorfizados compartilhados entre caminhos de leitura e escrita. Mitigação: sensibilidade a caminho, ou no mínimo imprimir o caminho e penalizar caminhos que passam por helpers com fan-in alto (medido: um helper alcançável de 20/76 exports).

**(b) Cranks permissionless — 14/157 = 8,9%** `[medido]`
`sync`, `gulp`, `gulp_emissions`, `poke_oracle`, `poke_oracle_with_hints`, `observe`, `observe_single`, `update_interest`, `snapshot_cumulatives_inside`, `refresh_boosted_underlying`, `backfill_plane_data`, `new_auction`, `del_auction`, `bad_debt`.
São **permissionless por design**: qualquer um pode acumular juros, tirar snapshot, iniciar leilão. Doc do Blend: *"Anyone can fill auctions conducted by the Blend protocol"*; os três tipos são *"interest, liquidations, and bad debt"*. <https://docs.blend.capital/users/auctions>
Reportar `bad_debt` como "escreve sem auth" é exatamente o falso positivo que faz o revisor descartar o relatório.
**Não dá para exemptar por nome** (a lista não é fechada). O discriminante defensável é: escreve **e não** move valor **e não** altera papel privilegiado. Do bytecode: não alcança `call` para um token, e não escreve numa chave que também é escrita por um entrypoint autenticado. É heurística → **nível C**, e tem que ir marcada como tal.

**(c) Contratos internos de protocolo, chamados só por um router**
`deposit`, `withdraw`, `swap`, `submit` sem `require_auth` podem ser legítimos se o contrato só é invocado por um roteador que já autenticou. A auto-autorização do invoker direto (§B.4) torna isso um padrão viável. **Indecidível do bytecode do chamado.** Resolve-se com nível B: observar quem invoca on-chain.

**(d) `__constructor` + `initialize` coexistindo**
41 contratos exportam `__constructor` e 12 exportam `initialize` `[medido]`. Onde os dois existem, a presença do construtor **não** exempta o `initialize` — ele continua invocável externamente e continua front-runnable. Não exemptar.

**(e) OpenZeppelin: entrypoints que legitimamente não têm auth na biblioteca**
`Base::mint`, `Base::sequential_mint`, `consecutive::batch_mint`, `set_metadata`, `set_owner`, `set_admin`, `set_schema_version`, `upgrade`, os 13 no-auth de `governance/src/governor/storage.rs`, e tudo com sufixo `_no_auth` — todos carregam `⚠️ SECURITY RISK: This function has NO AUTHORIZATION CONTROLS ⚠️` ou `**IMPORTANT**: This function bypasses authorization checks`.
**A intenção é que o integrador ponha `#[only_owner]`/`#[only_role]` por cima.** Quando ele não põe, é achado verdadeiro, não exceção. O quickstart de NFT da própria OZ ainda publica um mint público sem guarda, com um comentário `// access control might be needed` no lugar do check.
<https://docs.openzeppelin.com/stellar-contracts/> · <https://github.com/OpenZeppelin/stellar-contracts>

### D.6 — Veredito da seção D

| Pergunta | Resposta |
|---|---|
| `__constructor` e `__check_auth` estão corretos como exceção? | **Sim**, com fonte normativa forte. |
| A lista está completa? | **Como lista de nomes `__`, sim** (verificado em 75 WASMs). **Como lista de exceções de ciclo de vida, não** — cobre 20,4% do ruído medido; faltam três famílias que somam ~41%. |
| A regra está bem formulada? | **Não.** Deve ser o prefixo `__` sobre *exports de função*, que é o que o host impõe. |
| Há outros entrypoints que legitimamente mutam estado sem `require_auth`? | **Sim**: cranks permissionless, contratos internos atrás de router, e `init_asset` do SAC. Nenhum é exemptável por nome; exigem nível B ou heurística marcada como nível C. |

---

## E. Veredito — taxonomia revisada

Legenda de detectabilidade **a partir do WASM deployado + spec + eventos on-chain**:
**D** = detectável (nível A puro) · **P** = parcialmente (precisa de dataflow, ordem, ou nível B) · **N** = não detectável.

| # | Classe | Sinal | Det. | Exceções / calibração | Δ |
|---|---|---|---|---|---|
| 1 | **Entrypoint muta estado sem autorização** | alcança `l._`/`l.2`, não alcança `a.0`/`a._` — **com caminho concreto impresso** | **P** | exports `__*`; read-shaped por helper compartilhado; crank permissionless; contrato interno atrás de router. Precisão medida do predicado nu: **≤16%** | reescrita |
| 2 | **`require_auth` no endereço errado** | `Address` passado a `a.0` origina-se de parâmetro do export, não de `l.1` | **P** | `transfer(from,…)` é legítimo. Casa com Scout `unrestricted-transfer-from` / `unprotected-mapping-operation`, ambos Critical | 🆕 |
| 3 | **SDK deployado com CVE de bypass de auth** | `contractmetav0`/`rssdkver` < 22.0.10 / 23.5.2 / 25.1.1 | **D** | nenhuma. **34/75 (45%) do corpus exposto** (83% dos 41 que declaram versão). Exposição = A; exploração = C | 🆕 |
| 4 | **Upgrade sem controle** | alcança `l.6` sem alcançar `a.0`/`a._` | **D** | — (evento SYSTEM é automático, não é sinal) | mantida |
| 5 | **Construtor órfão / migração ausente pós-upgrade** | exporta `__constructor` **e** alcança `l.6`; ou alcança `l.6` sem export de migração/schema | **P** | contrato imutável por design. Histórico via evento SYSTEM `executable_update` | 🆕 |
| 6 | **Re-inicialização / front-running de init** | export `init*` que escreve **e** `__constructor` ausente | **D** | contrato com os dois = risco maior, não menor. CAP-0058 é a fonte | refinada |
| 7 | **Dado com valor em storage Temporary** | 3º argumento literal de `l._` == `0` (Temporary) num entrypoint que move valor | **D** | cache/nonce/allowance por design. **91% dos call sites têm o literal** | 🆕 |
| 8 | **Erro no uso de `extend_ttl`** | ordem de argumentos; threshold == max; durabilidade incompatível | **P** | Veridise `V-HOTB-VUL-004`, RV Band `A4`/`A7`, Scout `ineffective-extend-ttl` | 🆕 |
| 9 | **PRNG do host em decisão com valor** | importa `p.*` e alcança a partir de entrypoint que escreve/chama | **D** | shuffle cosmético. Base rate **4/75** → alta precisão | 🆕 |
| 10 | **`require_auth` depois da sub-chamada / injeção na árvore de auth** | ordem de `a.0`/`a._` vs `d._`/`d.0` no CFG | **P** | fonte normativa na doc de auth; OtterSec Soroswap `SUG-02`, Certora Aquarius `M-02`, RV Aggregator `A3` (High), RV EquitX `B1.1`. *(era "auth depois da escrita" — par errado)* | corrigida + fundida com B.9 |
| 11 | **Dado não-limitado em Instance storage** | literal `2` em `l._` com chave derivada de parâmetro `Address` | **P** | config pequena é o uso correto. **4 Highs** (Soroswap, Phoenix, HiYield, Wombat); Instance domina 127/190 sites | 🆕 |
| 12 | **Fluxo que estoura o limite de recursos** | `l._` dominado por back-edge do CFG; contagem estática de escritas por caminho vs teto de 200; entrada >64 KiB; chave >250 B | **P** | loop com bound constante. **2 Criticals** (Certora Blend `BL-001`, Slender `C-3`) | 🆕 |
| 13 | **Read-modify-write com auto-aliasing** | duas chaves derivadas de parâmetros `Address` distintos em `get`…`put` no mesmo frame | **P** | contrato que compara os dois antes. **3 Criticals** (Blend, Governor, OZ). É o alvo do ponto cego de `storage.update` já citado em `PROBLEMA.md` | 🆕 |
| 14 | **TTL dessincronizado entre chaves pareadas** | duas chaves escritas juntas, só uma alcança `l.7` | **P** | entradas com ciclos de vida deliberadamente distintos. OZ v0.5.0 `H-01` (**High**) | 🆕 |
| 15 | **Sem `overflow-checks` no release** | padrão estrutural de branch pós-aritmética ausente | **P** | **não validado.** Proxy por string não serve (10/75) | 🆕 |
| 16 | **Ação com efeito externo sem evento** | escreve/move valor e não alcança `x.1` | **D** | getters; upgrade (evento automático). Severidade **baixa** (7 achados, nenhum acima de Low); sobe a Medium só em assinatura SEP-41 | fundida (6+8), rebaixada |
| — | ~~Delegação de privilégio (`a.3`)~~ | — | — | **rebaixada a inventário do DFD** — 17% de base rate; 1 achado público (Suggestion) cujo bug é a *forma da árvore*, que o import de `a.3` não revela | ⬇️ |
| — | ~~Fronteira de confiança (`call`)~~ | — | — | **movida para o DFD** — 82% de base rate; é estrutura, não ameaça | ➡️ |
| — | ~~Archival (não estende TTL)~~ | — | — | **decomposta em #7, #8, #11 e #14** — a classe é real (1 High pós-P23), o predicado genérico é que não serve | ➡️ |
| — | ~~Repúdio (linha separada)~~ | — | — | **fundida em #16** — era a mesma proposição, duplicada para preencher STRIDE | ➡️ |
| — | ~~Reentrância~~ | — | — | **nunca adicionar** — `ContractReentryMode::Prohibited` no host; Scout não tem detector Soroban | ⛔ |

### Contagem

| | |
|---|---|
| Classes originais confirmadas sem mudança | **2** (#4 upgrade, #6 init — esta com refinamento) |
| Confirmadas mas reescritas / com predicado corrigido | **3** (#1 auth, #10 ordem, #16 eventos) |
| Removidas ou rebaixadas a elemento do DFD | **2** (delegação `a.3`, fronteira de confiança `call`) |
| Decompostas em predicados específicos | **2** (archival → #7/#8/#11/#14; repúdio → fundido em #16) |
| Novas | **11** (#2, #3, #5, #7, #8, #9, #11, #12, #13, #14, #15) |
| **Total revisado** | **16 linhas** |

Severidade máxima observada nas classes novas, por achado público real: **Critical** em #13 (3×) e #12 (2×); **High** em #3 (CVE), #11 (4×); **Medium** em #7, #8, #9.

### Cobertura STRIDE do conjunto revisado

| Letra | Sustentada pelo bytecode? |
|---|---|
| **S** poofing | #2, #3 |
| **T** ampering | #1, #7, #11, #13, #14 |
| **R** epudiation | #16 — **fraca**; se não houver caso concreto, declarar lacuna em vez de preencher |
| **I** nformation disclosure | **nenhuma derivável do bytecode.** Declarar lacuna: requer análise de o que é gravado, não de onde |
| **D** enial of service | #8, #11, #12, #14 |
| **E** levation of privilege | #1, #2, #3, #4, #5, #6, #9, #10 |

Duas letras (R, I) ficam fracas ou vazias. Pelo critério do próprio `PROBLEMA.md`, o certo é declarar a lacuna — *"nenhuma ameaça de Divulgação de Informação derivável do bytecode; requer análise manual do conteúdo gravado"* — e não inventar linha.

---

## Apêndice — método das medições

Todas as linhas marcadas `[medido]` são reproduzíveis sobre `corpus/*.wasm` (75 contratos de mainnet, coletados por `scripts/fetch-corpus.mjs`):

- **Desassembly:** `wasm-dis` (binaryen).
- **Call graph:** imports resolvidos por `(import "<mod>" "<fn>" (func $N))` contra `src/hostfns.json` (mapa canônico de `rs-soroban-env/soroban-env-common/env.json`); arestas extraídas de `(call $X)` por corpo de função; alcançabilidade por DFS a partir de cada `(export "name" (func $N))`.
- **StorageType:** terceiro argumento posicional do call site de `l._`, aceito só quando é `(i64.const N)` literal no nível de indentação do argumento.
- **Versão do SDK:** regex sobre os bytes do módulo, `rssdkver` seguido de `<semver>#<sha40>`, com fallback para caminhos `soroban-sdk-<semver>/src/`.
- **Limitação conhecida:** a reachability é **path-insensitive e context-insensitive**. Ela over-approxima (é a causa dos 31,8% de FP read-shaped) e portanto é *sound* para "não alcança" e *unsound* para "escreve". Um veredito de "não alcança `require_auth`" é confiável; um de "escreve estado" não é, sem o caminho.

## Apêndice B — índice canônico de auditorias (útil para o repo)

A página do Audit Bank renderiza só 12 entradas, mas o CMS por trás dela é aberto e devolve **77 auditorias** com protocolo, auditor, data e URL direta do relatório:

```sh
curl -sG "https://e2r40yh6.apicdn.sanity.io/v2023-01-01/data/query/production-i18n" \
  --data-urlencode 'query=*[_type=="audit" && language=="en"]|order(date desc){title,date,auditType,"url":cta.href}'
```

**57 têm link público** (reconferido em 2026-09-16: HTTP 200, 77 auditorias, 57 com `url`).
Sem o prefixo `query=` o endpoint devolve erro — a forma anterior deste comando não rodava. Vale cachear em `corpus/` como índice de corpus de validação. Página: <https://stellar.org/audit-bank/projects>

Repositórios que hospedam os PDFs junto do código (mais estáveis que os sites dos auditores):
`blend-capital/blend-contracts/audits/`, `blend-capital/blend-contracts-v2/audits/`, `soroswap/core/audits/`, `reflector-network/reflector-contract/audits/`, `OpenZeppelin/stellar-contracts/audits/`, `Phoenix-Protocol-Group/phoenix-contracts/docs/`, `CoinFabrik/coinfabrik-audit-reports/Aquarius/`.

**Resultados negativos verificados:**
- **Trail of Bits: zero relatórios Soroban.** `trailofbits/publications` tem 450 arquivos sob `reviews/`; busca por `stel|soro|lumen|sdf|komet` → 0 ocorrências; o índice de 145 KB do README tem 0 ocorrências de "stellar"/"soroban".
- **CoinFabrik: um** relatório Soroban (Aquarius AMM, março/2024). Dele vem uma classe que não aparece em nenhum outro lugar: `EN-04`/`EN-05`, **condição de corrida de autorização** — árvores de auth pré-assinadas invalidadas quando um valor dependente de estado muda entre a montagem e a execução da transação. Não detectável do bytecode; é propriedade do fluxo de assinatura off-chain.
- `github.com/otter-sec/audits` redireciona para conteúdo só de NEAR; os PDFs Soroban da OtterSec vivem em `osec.io/reports/<uuid>` e nos repos dos protocolos.

## Lacunas declaradas

- **UNKNOWN:** não encontrei nenhuma ferramenta pública que detecte ausência de `overflow-checks` a partir do WASM. Procurei em Scout, Certora Sunbeam, OZ Soroban Security Detector SDK e nos relatórios da Veridise. O detector `overflow-check` do Scout lê o `Cargo.toml`, não o binário.
- **UNKNOWN:** o relatório por achado do Code4rena Blend V2 estava acessível, mas o da competição Cantina do Aquarius (US$ 110 k, 696 submissões) não publica breakdown de severidade. <https://cantina.xyz/competitions/990ce947-05da-443e-b397-be38a65f0bff>
- **Correção de premissa:** não existe incidente de segurança do Aquarius/AQUA. Procurei em rekt.news, DeFiHackLabs, Immunefi, HackerOne/Stellar e nos anúncios da SDF. O que existe é bug bounty + competição de auditoria. Provável confusão com YieldBlox/Blend.
- **Não existe página oficial de "Soroban security best practices".** `developers.stellar.org/docs/build/security-docs` é threat modeling + segurança Web2 (TLS, CSP, CSRF); `project-security` retorna 404. O substituto mais próximo é a lista "🚩 Red flags in review" em `guides/storage/storage-strategies`.
- **`authorize_as_curr_contract` e reentrância não são documentados** em developers.stellar.org. As únicas fontes são CAP-0046-11 e o código de `rs-soroban-env`.
- **Eventos são efêmeros:** *"RPC providers typically only keep short chunks (less than a week) of history around."* Isso limita diretamente o baseline de nível B do monitoring plan — a janela observável é de dias, não meses, salvo indexador próprio. <https://developers.stellar.org/docs/build/guides/events/publish>
