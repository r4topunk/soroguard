# Handoff — soroguard

Contexto para quem pega este projeto com a sessão zerada. Escrito para ser lido inteiro antes de mexer em qualquer coisa. Documento interno: fica em português de propósito; o que é público (`README.md`, saída da ferramenta, `examples/`) é em inglês.

---

## 1. O que é, em um parágrafo

Uma ferramenta que lê o **WASM deployado** de um contrato Soroban (Stellar), sem precisar do código-fonte, e gera os **dois artefatos que o SCF exige no tranche #2** de todo award Build: um threat model STRIDE e um monitoring plan on-chain, nos templates oficiais da Stellar. Toda afirmação nos documentos carrega um nível de evidência, e o que não é derivável do binário sai declarado como lacuna em vez de preenchido com texto genérico.

## 2. Por que existe

Desde a rodada #44 do SCF, **todo** projeto Build precisa entregar esses dois documentos para liberar o tranche #2 (30% do award). São ~35 equipes por rodada. A Stellar publicou os templates e nenhuma ferramenta.

A diferença para o que já existe (Scout/CoinFabrik, Guard-CLI, Persist, Komet) é estrutural, não cosmética: **todos analisam código-fonte Rust**. Nós lemos o binário que está em produção — ou seja, o que está de fato vivo. Isso permite auditar contrato de terceiro sem pedir o repo, e pega uma classe que uma ferramenta de fonte não vê porque o repo já foi corrigido depois do deploy (ver §4.1).

## 3. Estado atual — o que é fato

Os números correntes são **gerados**, nunca escritos à mão. `node scripts/stats.mjs --write` reescreve o bloco abaixo e o equivalente no `README.md`. Rodar isso antes de qualquer commit é parte do fluxo (§12).

<!-- stats:start -->
<!-- Gerado por `node scripts/stats.mjs --write` — não editar à mão. -->

| Medida | Valor |
|---|---|
| Testes (`pnpm test`) | **208 passando** de 208 |
| Corpus (`corpus/*.wasm`) | **71 contratos de mainnet**, 1,726 entrypoints, 0 falhas de parse |
| Achados | **164** no total · **2.3 por contrato** |
| Por classe | 48 `silent-mutation` · 38 `vulnerable-sdk` · 35 `initialization-front-running` · 13 `self-implemented-signature-verification` · 10 `unauthenticated-state-mutation` · 9 `archival-risk` · 7 `third-party-state-tampering` · 3 `host-prng-in-value-path` · 1 `write-before-auth` |
| `call_indirect` (análise rebaixada) | **22 de 71** (31%) |
| Supressões declaradas | **111**<br>52 — read-shaped name: the write probably comes from a shared helper, not from this path<br>46 — reserved `__` function, not directly invocable (CAP-0058)<br>13 — permissionless crank by design (protocol maintenance pattern) |
| Rebaixamentos (reportados, não suprimidos) | **4**<br>4 — reaches call/try_call — authorization may live in the callee, severity capped at High |
| Versão de SDK declarada (`rssdkver`) | **69 de 71** |
| Em faixa afetada pelo CVE-2026-26267 (High) | **37 dos 69** que declaram versão |
| Linhas (`src` + `test`) | 13,546 em 31 arquivos |
<!-- stats:end -->

| | |
|---|---|
| Corpus | 75 contratos de mainnet em `corpus/*.wasm`, **commitados** (não são build artifact; o sha256 de cada arquivo é o wasm hash on-chain) |
| Idioma da saída | **inglês, só.** Templates e revisores do SCF são em inglês |
| Empacotamento | `bin` `soroguard` e `soroguard-mcp`, `files`, `prepublishOnly` com build + testes. `npx soroguard` funciona a partir do tarball |
| Tempo de construção | **41 minutos** de relógio na sessão inicial (`docs/CRONOMETRO.md`), com 3 subagentes e 1 workflow de 10 agentes, mais uma rodada de revisão/endurecimento |
| Publicado | **não.** Sem npm, sem repo remoto. O repo está pronto para o primeiro commit; `soroguard` continua livre no registry |

```fish
pnpm install
node src/cli.ts inspect  <contractId|arquivo.wasm>   # spec: funções, erros, eventos + prefixTopics
node src/cli.ts analyze  <target>                    # call graph, achados, supressões, lacunas
node src/cli.ts artifact <target> [--offline]        # os dois documentos + validação
node src/mcp.ts                                      # MCP server (stdio), 3 tools
pnpm test
node scripts/calibrate.mjs                           # roda a taxonomia no corpus e mostra a triagem
node scripts/stats.mjs [--write]                     # regenera todo número publicado
```

Exemplos gerados de contratos reais estão em `examples/`.

## 4. Os quatro achados técnicos que sustentam o projeto

### 4.1 O binário registra qual SDK compilou o que está no ledger

As host functions do Soroban são **imports do módulo WASM** com nomes de um caractere (`a.0` = `require_auth`, `l.6` = `update_current_contract_wasm`, `x.1` = `contract_event`). O mapa canônico está em `rs-soroban-env/soroban-env-common/env.json`, vendorizado em `src/hostfns.json` (199 funções, 11 módulos).

Além disso, a custom section `contractmetav0` grava a versão do `soroban-sdk` usada na compilação, sob a chave `rssdkver`.

**O enquadramento correto — usar este texto em todo lugar, inclusive no pitch:**

> 41 de 75 contratos de mainnet declaram a versão do SDK; **34 foram compilados com uma faixa afetada pelo CVE-2026-26267 (High)**. Dos 20 cujo fonte é público, **nenhum** tem a colisão de nomes (`impl Trait` × `impl C`) que dispara o bug; os outros 14 ficaram sem conclusão (11 sem fonte público, 3 com fonte provável não confirmada); **0 confirmados vulneráveis** (`docs/CVE-2026-26267-VERIFICACAO.md`). Exposição é fato de bytecode (nível A), explorabilidade exige o fonte (nível C) — por isso o achado sai como **Low**, com o High do advisory na evidência, não na severidade. O que só o artefato mostra é qual SDK compilou o binário que está no ledger; o repositório pode ter sido atualizado depois do deploy.

Duas frases que estavam aqui e **não podem voltar**: "83% está vulnerável" (o código recusa afirmar isso: `detect.ts` emite Low, e há teste garantindo que o achado não herda a severidade do advisory) e "impossível de ver no fonte" (é o inverso — o gatilho **só** aparece no fonte; o que só o binário tem é a versão).

O caso concreto que carrega o argumento não é o CVE, é o padrão de instâncias deployadas anteriores a um fix de autorização upstream: uma ferramenta de fonte olhando o repo hoje não vê nada; o WASM deployado mostra a ausência da checagem. Detalhe, nomes e ids só depois do disclosure privado (material em `../soroguard-private/`). Nem a forma do caso vai para o repo público: combinada com o corpus e o detector, ela identifica os contratos.

⚠️ **Disclosure não enviado.** Os rascunhos de aviso privado e a triagem nominal foram movidos para `../soroguard-private/docs/` (fora do repo, fora do git). Enquanto o disclosure não for concluído, **não nomear projetos nem contract ids em material público** — o README e `docs/PRECISION.md` descrevem a classe genericamente.

### 4.2 O call graph responde o que cada entrypoint realmente alcança

Parseando a code section dá para responder, por entrypoint exportado, quais host functions são alcançáveis. Isso troca heurística de nome por fato de bytecode: `withdraw` *parece* exigir auth vs `withdraw` *alcança* `require_auth`, sim ou não.

### 4.3 A assimetria de solidez — leia isto antes de mexer em detector

```
NÃO alcança require_auth   →  PROVA de que nunca chama    (sólido)
alcança put_contract_data  →  pode escrever, em algum ramo (super-aproximado)
```

A negativa é sólida. **A positiva não** — e isso vale igualmente para `alcança require_auth`, por isso o DFD marca os saltos de auth com `†`. Descobri na calibração: `estimate_swap`, read-only, aparecia como Critical porque compartilha um helper de carga de estado que tem um ramo de escrita — ramo que ela nunca executa.

Consequência de desenho: toda afirmação positiva sai com **o número de saltos** (distância BFS, não o primeiro caminho que a travessia achar), e caminho com mais de 2 saltos ganha aviso explícito de revisão. Quando há `call_indirect` no subgrafo (24 de 75 contratos, 32%), **nem a negativa vale** e o módulo é marcado `approximate`.

### 4.4 `prefixTopics` é a ponte do spec para o monitoramento executável

O contract spec declara, por evento, os tópicos que ele emite on-chain (`tw_withdraw`, `tw_dispute`). Esse é o filtro de uma chamada `getEvents`. A ponte entre "evento declarado no contrato" e "regra de monitoramento executável" já está dentro do binário — **para os 18 de 75 contratos que declaram evento**; os outros 57 não têm como render baseline de nível B (§9).

## 5. O contrato de qualidade — regras que não se quebram

Estão em `docs/PROBLEMA.md`. Resumo operacional:

**Três níveis de evidência, e nunca apresentar um com força maior do que tem.**

| | O que é |
|---|---|
| **A** | fato de bytecode — redeterminístico, qualquer um confere |
| **B** | fato observado on-chain via `getEvents` — única origem legítima de baseline |
| **C** | inferência — severidade, classe de ameaça, remediação. Vai marcada como opinião |

**Seção sem evidência sai declarada como lacuna.** O template exige ≥1 issue por letra do STRIDE. Se o bytecode não sustenta uma de Repúdio, o documento diz que não sustenta. Um campo honestamente vazio é verificável; um preenchido com genérico não é, e o primeiro revisor competente descarta o documento inteiro.

**Supressão nunca é silenciosa.** Todo entrypoint filtrado entra em `suppressed` com motivo, e um teste falha se algo for suprimido e reportado ao mesmo tempo. Rebaixamento (achado que alcança `call`/`try_call`, com teto de High) **não** é supressão: o achado continua no documento.

**Baseline nunca é inventado.** Sem janela de observação suficiente, o campo diz "janela insuficiente", não um número plausível. Coleta que **falhou** não pode sair igual a `--offline`: o CLI imprime o motivo e sai com código 2.

## 6. Precisão — o número honesto

O detector de autorização nu tem **≤16% de precisão** — limite superior derivado por forma de nome, não por ground truth humano. Para calibrar: a CoinFabrik mediu o detector de fonte equivalente (`set-contract-storage`) em 71 contratos e reportou **59,41% de falso positivo**. São quantidades diferentes (a deles é contra rótulo humano) e dizer isso é mais persuasivo que comparar como se fossem a mesma coisa.

O que corrige o nu são três famílias de exceção, medidas sobre 157 ocorrências brutas:

| Família | % do ruído | Por quê |
|---|---|---|
| exports `__*` | 20,4% | o host recusa invocação direta (`RESERVED_CONTRACT_FN_PREFIX`, CAP-0058) |
| read-shaped (`get_*`, `estimate_*`, `price`, `*_get_*`…) | 31,8% | a alcançabilidade atravessa helper compartilhado |
| crank permissionless (`sync`, `gulp`, `poke_*`…) | 8,9% | são sem permissão **por desenho** |

Com elas, `unauthenticated-state-mutation` caiu de 89 para 27 achados no corpus.

**A única medida contra fonte que existe** (`docs/PRECISION.md`; detalhe nominal em `../soroguard-private/docs/triagem-unauth/`): 30 achados triados um a um, **9 mutações sem auth reais (30%)**, 21 permissionless por desenho, **0 bugs de detector**, 0 com perda de fundos hoje. As 30 negativas ("não alcança `require_auth`") bateram todas com o fonte. Medido **antes** das mudanças desta semana (supressão de `gauges_get_reward_info`, teto de High no cross-call), que só removem achado — então 30% é piso do código atual, não descrição dele.

⚠️ **O que ainda NÃO foi medido: recall.** Não há ground truth rotulado, então não há número para o que a ferramenta deixa passar. É a primeira pergunta que um revisor vai fazer. O CMS do Audit Bank é aberto e devolve **77 auditorias, 57 com URL pública** (reconferido; ver `docs/TAXONOMIA-VALIDACAO.md` Apêndice B) — é o corpus que resolve isso, e é o entregável da tranche #2.

## 7. Arquitetura

```
src/
  wasm.ts         parser de módulo WASM (sections, call graph, consts) — zero dependência
                  FAIL-CLOSED: seção além do fim, LEB128 truncado, element sem terminador e
                  opcode desconhecido são erro ou `incomplete`, nunca folha silenciosa
  hostfns.{ts,json}  catálogo das 199 host functions, categorizadas
  analyze.ts      alcançabilidade por entrypoint (BFS: `pathTo` é distância mínima, não
                  primeiro caminho) + ordem intraprocedural auth×escrita
  detect.ts       os detectores (7 classes ativas) + supressões e rebaixamentos declarados
  sdkver.ts       lê rssdkver e confronta com advisories (parse de versão ESTRITO)
  storagekeys.ts  infere chaves de storage da data section
  spec.ts         contract spec (funções, erros, eventos + prefixTopics)
  events.ts       ingestão nível B via getEvents + baseline
  text.ts         helpers de texto (`plural`, `listAnd`) compartilhados pelos renderizadores
  artifact.ts     ⚠️ CONTRATO CONGELADO entre os módulos — não editar sem alinhar
  pipeline.ts     monta o ArtifactContext na ordem certa
  render/dfd.ts           data-flow diagram em Mermaid
  render/threatmodel.ts   template STRIDE oficial
  render/monitoring.ts    template de monitoring plan oficial (6 seções)
  monitors.ts     deriva monitores com ID <ThreatID>.M.<n> + filtros executáveis
  validate.ts     valida os dois checklists "Did we do a good job?"
  mcp.ts          MCP server stdio, JSON-RPC escrito à mão
  cli.ts          commander
```

**O acoplamento por ID entre os dois documentos é o valor central.** O threat model gera `Elevation.1`; o monitoring plan carrega esse ID e deriva `Elevation.1.M.1`. Hoje as equipes escrevem os dois à mão e eles divergem.

**`validate.ts` é a fonte única dos dois checklists.** O veredito que o CLI imprime e a §6 renderizada saem do mesmo objeto — há teste garantindo isso. Se precisar mudar um critério de submissibilidade, é lá, e em nenhum outro lugar.

**Cada módulo declara sua tabela `M`.** Qualquer string que o usuário lê passa por ela; a saída é só em inglês. Nome de flag, de comando, de rede e chave de JSON são identificadores e ficam de fora.

## 8. Decisões que parecem estranhas e têm motivo

- **Zero dependência de runtime** além de `@stellar/stellar-sdk` e `commander`. O MCP server é JSON-RPC na mão em vez do SDK oficial: uma ferramenta de segurança que arrasta árvore de dependência contradiz o próprio pitch.
- **Node ≥22.18 com type-stripping nativo**, sem passo de build em dev.
- **`archival-risk` é escopo de contrato, não de entrypoint.** Basta um caminho renovar TTL para o estado sobreviver; avaliar por entrypoint gerava 30 achados falsos.
- **`silent-mutation` é agregado em uma linha por contrato.** Por entrypoint eram 114 achados soterrando os que importavam. Mesmo tratamento para `host-prng-in-value-path` quando o mesmo call site faz fan-out para mais de 3 entrypoints.
- **`trust-boundary-crossing` e `privilege-delegation` foram rebaixados de achado para inventário do DFD.** Base rate de 82% e 17% respectivamente — é estrutura, não ameaça.
- **Renderizadores não leem relógio.** A data entra por `ArtifactContext.generatedAt` para que a saída seja reprodutível em teste.
- **O corpus é commitado.** Sem ele um clone fresco não roda os testes nem reproduz um único número do pitch.

## 9. Limites conhecidos — não são bugs, são fronteiras

- **Spoof e Info dão zero em 100% dos 75 contratos.** Dependem de identidade e exposição de dados, que não são observáveis no bytecode. O documento sempre vai declarar essas duas como lacuna exigindo análise manual.
- **57 de 75 contratos não declaram evento no spec.** Para esses, baseline de nível B é impossível por construção: não há filtro de tópico para observar. `#[contractevent]` é recente e a maioria do que está deployado é anterior.
- **O monitoring plan passa o próprio checklist, com rede ligada e sem input humano, em ~1 de 75 contratos.** Hoje a metade submetível é o threat model; o monitoring plan sai como esqueleto com a evidência que existir. Monitoramento por state-diff via `getLedgerEntries` — o que os 57 sem evento precisam — não está construído.
- **Durabilidade e TTL de storage não são legíveis do bytecode** no caso geral: o argumento de durabilidade quase nunca é literal imediato no call site.
- **Endereços de contratos chamados não são deriváveis** — são argumentos de runtime. O inventário do monitoring plan diz isso em vez de inventar.
- **41% dos contratos não rendem chave de storage.** Declarado como lacuna.
- **Contratos sem `contractspecv0` (SACs) não são suportados.** Detecta e imprime uma linha dizendo isso — não estoura mais com stack.
- **Detectores #7, #11, #12, #13, #14 da taxonomia não existem.** Precisam de dataflow real, não alcançabilidade. São **2 Criticals e 4 Highs** em auditorias reais — é o trabalho mais valioso que sobrou.

## 10. Estado da decisão de submissão

- **Trilha para o #46 (deadline 2026-11-08): Open Track.** Não há RFP aberta que case; o handbook roteia tooling fora de RFP para "wait for a future RFP", e Integration exige métrica on-chain que um CLI não produz.
- **Orçamento 100% forward-looking.** O handbook diz que reembolso de trabalho passado é inelegível. A ferramenta pronta entra como contribuída ao ecossistema sem custo ao SCF; o budget financia só o que falta (§9). Pedido-alvo ~US$96k.
- **Disclosure de IA explícito**, exigido no Open Track e coerente com o pitch. Está no README, seção "How this was built".

**Duas jogadas de maior alavancagem, e as duas são desta semana** (`docs/REVISAO-SCF.md` §4):

1. **Criar a RFP que queremos responder.** A governança é trimestral: delegates compilam novas RFPs em t−5 (~4 out) e publicam em t−3 (~18 out). O handbook manda explicitamente propor na página Stellarlight Ideas e discutir no Dev Discord. Comparáveis de RFP para tooling sem tração: US$73,5k–120k, contra US$53k de quem submeteu fora de RFP. Se sair uma RFP compatível em ~18 out, trocar de trilha antes de 8 nov — mesmo deadline.
2. **Perguntar à SDF se isto está no roadmap deles.** "SDF constrói internamente" é o risco alto registrado desde o início e nunca foi checado. Custa uma mensagem. Se a resposta for "não, e queremos revisar os artefatos", é o melhor endosso disponível e entra citado na submissão.

**Plano acordado:** fechar os blockers de `docs/REVISAO-SCF.md` §2, primeiro commit, e submeter Open Track no #46 enquanto a RFP é empurrada em paralelo.

## 11. Onde está documentado o resto

| | |
|---|---|
| `docs/PROBLEMA.md` | o contrato de qualidade e o que faria isto virar slop |
| `docs/CALIBRACAO.md` | log iteração-a-iteração de remoção de falso positivo, com números datados |
| `docs/TAXONOMIA-VALIDACAO.md` | 16 classes confrontadas com ~40 auditorias (Veridise, Certora, OtterSec, Runtime Verification, Code4rena, OpenZeppelin), 56 URLs |
| `docs/REVISAO-SCF.md` | a revisão pré-submissão: blockers, achados por severidade, estratégia de trilha |
| `docs/CVE-2026-26267-VERIFICACAO.md` | verificação de fonte dos 34 contratos expostos |
| `docs/PRECISION.md` | a triagem de 30 achados contra o fonte, resumida por forma (nominal em `../soroguard-private/`) |
| `docs/CRONOMETRO.md` | marcos de tempo |
| `../SCF-BUILD-AWARD.md` e vizinhos | a pesquisa sobre o próprio SCF que originou o projeto |

## 12. Primeiras coisas a fazer

1. `pnpm install && pnpm test` — a contagem esperada é a do bloco gerado em §3, não um número decorado.
2. Ler `docs/PROBLEMA.md` inteiro. É o contrato que todo o resto obedece.
3. `node src/cli.ts artifact corpus/<qualquer>.wasm --offline` e **ler a saída inteira** procurando qualquer frase insustentável. Foi assim que os últimos defeitos apareceram.
4. Se for mexer em detector: `node scripts/calibrate.mjs` **antes e depois**. Achados por contrato subindo é sinal de regressão, não de cobertura.
5. ⚠️ **Disclosure privado pendente.** Os documentos nominais estão em `../soroguard-private/docs/` (fora do git). Enviar os avisos aos projetos antes de citar qualquer nome em material público, vídeo ou submissão.
6. **Antes de qualquer commit: `node scripts/stats.mjs --write`.** Ele reexecuta a suíte e os detectores e reescreve o bloco deste arquivo e o do README. Número escrito à mão em documento é como este projeto já se contradisse quatro vezes.
