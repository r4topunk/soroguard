# Revisão pré-submissão SCF — soroguard

Data: 2026-09-16. Escopo: o projeto inteiro, com a pergunta "o que um delegate do SCF, um auditor ou um core dev da Stellar encontra, e isso derruba a submissão?". Cinco frentes independentes (claims, motor, artefatos, ship, encaixe no SCF) e verificação adversarial de cada achado grave, reproduzindo comandos e lendo código. Achados que o verificador refutou ou rebaixou aparecem com a severidade ajustada.

---

## TL;DR

**A substância aguenta. A casca não.** O motor de análise, o contrato de qualidade (níveis A/B/C, lacunas declaradas, supressão auditável) e a afirmação central sobre o CVE-2026-26267 sobrevivem a verificação externa. O que derruba a submissão hoje está em três lugares que o delegate toca primeiro:

1. **O artefato gerado é em português.** O produto que o pitch vende é um documento que o revisor do SCF não consegue ler.
2. **Um clone fresco não roda.** `corpus/*.wasm` está no `.gitignore`: 14 de 43 testes falham e `calibrate.mjs` imprime zero. Nenhum número do pitch é reproduzível a partir do repo.
3. **A trilha RFP rejeita automaticamente hoje**, e a janela para criar a RFP que você quer responder fecha em ~2 semanas.

Além disso, o próprio material interno contradiz a disciplina que vende: quatro contagens de testes diferentes (25/29/6/9) contra 43 reais, "83% está vulnerável" no HANDOFF quando o código emite Low por desenho, e `PROBLEMA.md` ainda afirma que nenhum contrato usa `call_indirect` quando são 32%.

**Decisão recomendada:** não submeter o #46 sem fechar os blockers da seção 2 (um a dois dias de trabalho). Submeter Open Track no #46 como primeira tentativa, e em paralelo abrir a RFP para Q1/2027, que é a versão desta submissão que de fato recebe funding.

---

## 1. O que sobrevive à verificação e deve ficar no pitch

| Afirmação | Verificado como |
|---|---|
| CVE-2026-26267 é real, High (CVSS 7.5), `soroban-sdk-macros`, faixas afetadas `<=22.0.9`, `23.0.0–23.5.1`, `25.0.0–25.1.0` | GHSA-4chv-4c6w-w254 buscado ao vivo. `src/sdkver.ts` codifica as faixas e a lista de patched **exatamente** |
| 41 de 75 declaram versão, 34 (82,9%) em faixa afetada | Rederivado independentemente sobre `corpus/*.wasm`; histograma por versão bate elemento a elemento com `CALIBRACAO.md` |
| CoinFabrik 59,41% FP em 71 contratos | Fonte buscada ao vivo; os cinco números citados batem |
| 199 host functions, 11 módulos; 75 contratos; 1.767 entrypoints; 0 falhas de parse; 2,3 achados/contrato; 112 supressões; 24/75 com `call_indirect` | `node scripts/calibrate.mjs` reproduz cada um; `corpus/calibration.json` é gerado e está correto |
| Parser: 42.478 arestas de call decodificadas, 0 alvos fora de faixa; imports contados corretamente no espaço de índices | Script independente sobre o corpus |
| Soundness é por entrypoint onde importa e por módulo só para achados de escopo de contrato | `detect.ts:92` vs `:187/:207`, com teste em `dfd.test.ts` |
| Fidelidade estrutural aos dois templates oficiais e acoplamento por ID entre documentos | Templates buscados ao vivo; `validate.ts:669` bloqueia monitor órfão |
| `validate.ts` não é carimbo: falha de cinco formas distintas e passa uma vez (online) | Reproduzido em 4 contratos |
| Determinismo: única leitura de relógio em `cli.ts:137`, data injetada nos testes | grep + reexecução byte-estável |
| Framing do MCP stdio (newline-delimited) está correto | Driver enviando initialize/tools/list/tools/call |
| Zero segredos, zero `.env`, zero dependência de runtime além de `@stellar/stellar-sdk` e `commander` | grep |

Duas coisas que os agentes destacaram como o ativo mais legível para um delegate: a ferramenta **recusa certificar a própria saída** (`NÃO submetível` com motivo nomeado), e a taxonomia confrontada com ~40 auditorias (`TAXONOMIA-VALIDACAO.md`) é exatamente o "deep, proven domain knowledge" que o Open Track pede no lugar de tração.

---

## 2. Blockers pré-submissão (fazer antes de tocar no formulário)

Ordenados por custo/retorno. Todos cabem em um a dois dias.

| # | O quê | Evidência | Fix |
|---|---|---|---|
| B1 | **Saída em inglês por padrão.** Corpo 100% PT-BR sob headings em inglês do template; sem flag de idioma | `examples/*`, `out/*`, `render/*.ts`, `validate.ts`, `cli.ts`, `mcp.ts`, `package.json:description` | Extrair strings de `render/threatmodel.ts`, `render/monitoring.ts`, `render/dfd.ts`, `monitors.ts`, `validate.ts`, `detect.ts` para tabela de mensagens; `--lang en` default, `pt` opcional. Regenerar `examples/`. Teste que falha se marcador PT aparecer no render |
| B2 | **Commitar o corpus.** 2,4 MB, 75 arquivos. Sem ele, clone fresco: `tests 43 / pass 29 / fail 14`, `calibrate.mjs` imprime `0 contratos`, `média NaN` | `.gitignore:5-6`; reproduzido em clone simulado | Remover `corpus/*.wasm` e `corpus/index.json` do `.gitignore`; `corpus/README.md` com data de fetch e comando de regeneração |
| B3 | **`npx soroguard` quebrado por construção.** `bin` aponta para `dist/` ignorado; sem `files`, sem `prepublishOnly`. Tarball de árvore limpa: 0 arquivos em `dist/`; npm silenciosamente não linka o bin | `package.json`, `.gitignore:2`, `npm pack` de clone limpo | `"files": ["dist","README.md","LICENSE"]`, `"prepublishOnly": "rm -rf dist && pnpm build && pnpm test"`, `build` com `rm -rf dist` (hoje `dist/_reach.js`, `_scan.js`, `_r.js` são órfãos) |
| B4 | **Sem arquivo LICENSE** apesar de `Apache-2.0` em dois lugares | `find -iname 'license*'` vazio | Adicionar texto Apache-2.0 + NOTICE |
| B5 | **Números internos corrigidos e gerados, não escritos à mão.** Testes: 43 (HANDOFF diz 29 duas vezes, README 25, CALIBRACAO 6 e 9). Achados/contrato: 2,3 (HANDOFF 2,7, CALIBRACAO 2,9). Linhas: 6.657 (HANDOFF 6.432). Entrypoints em CALIBRACAO: 1.767 e 1.263 três linhas apart. Tabela "Resultado final" de CALIBRACAO lista classes que não existem mais e `89→27` quando é `89→30` | `pnpm test`, `calibrate.mjs`, `wc -l` | `scripts/stats.mjs` que emite bloco entre marcadores no README/HANDOFF; regenerar CALIBRACAO "Resultado final" de `calibration.json`; datar snapshots históricos |
| B6 | **"83% está vulnerável" no HANDOFF §4.1** afirma o que o código recusa afirmar (`detect.ts:233-237` emite Low; teste `achado de exposição de SDK nunca herda a severidade do advisory`). Também "impossível de ver no fonte" é o inverso: o gatilho (colisão de nome `impl Trait`/`impl C`) só aparece no fonte | HANDOFF:42,48,50 vs README:26 (correto) | Usar o texto do README em todo lugar: "34 estão em faixa afetada; exposição é fato A, explorabilidade exige fonte, sai como Low com o High na evidência". Trocar "impossível de ver no fonte" por "o binário é o único lugar que registra qual SDK compilou o que está no ledger" |
| B7 | **`PROBLEMA.md:32`** afirma "nenhum contrato usa `call_indirect`" (n=8) sem o bloco de correção que o mesmo arquivo usa na linha 73 | calibrate: 24/75 | Bloco `> ⚠ Correção posterior` sob a linha 32, mantendo o erro original visível: demonstra o loop de calibração |
| B8 | **Limpeza do primeiro commit:** 23 arquivos em `.rev/` (`rev_attack3.mjs`, `run5.mjs`, `events.ts.bak`), `PLANO-3-DIAS.md`, `scripts/prototipos/`. Todos entram no tarball npm hoje | `git add -A -n` | `.gitignore` ou deletar; mover HANDOFF/PLANO para `docs/` |
| B9 | **Disclosure de IA.** Open Track exige. Hoje só HANDOFF menciona "41 minutos, 3 subagentes, 1 workflow" | grep no README/docs: zero | Seção "How this was built" no README em inglês, nomeando o que foi verificado por humano (corpus, calibração, ~40 auditorias) e a lacuna não medida (ground truth) |
| B10 | **`package.json` sem `repository`, `author`, `keywords`, `homepage`, `bugs`;** descrição em PT; sem remote; sem CI | `node -e` sobre package.json | Preencher; primeiro commit; push público; GitHub Action rodando os 43 testes |

---

## 3. Achados no produto, por severidade ajustada

Severidade após verificação adversarial. "Refutado" significa que o mecanismo existe mas a consequência alegada não se sustenta.

### Alto

| ID | Achado | Evidência | Fix |
|---|---|---|---|
| AE-3 | **`pathTo` é documentado como caminho mais curto mas é DFS-primeiro-encontrado.** 244 de 1.088 pares entrypoint→escrita reportam caminho mais longo que o mínimo; 116 cruzam o limiar `viaHelper = hops > 2`; 6 achados emitidos flipam de Critical para Medium por isso (ex.: `CDZPLSD4 initialize` reporta 3 saltos, real é 1, e o documento imprime `escrita 3† via helper compartilhado`). Hop count é apresentado como nível A e é o único input do rebaixamento de severidade | `analyze.ts:33` (doc) vs `:69-99` (DFS com `visited` compartilhado); BFS de referência em tmp | Trocar `walk` por BFS com mapa de distâncias; escolher a host fn de escrita **mais próxima**, não a primeira do Set; teste de regressão hops == distância BFS; remover a chamada duplicada de `walk` em `:105-106` |
| AQ-2 | **`examples/` estão stale** e carregam frase que o código já retirou ("são literalmente o filtro do `getEvents`", hoje hedgeada em `render/monitoring.ts:226-229`) e `Last reviewed: 2026-09-17`, que afirma revisão humana que o código atual recusa (`nunca revisado — gerado em`) | diff examples vs out | Regenerar de HEAD; teste que assere `examples/*.md` byte-idêntico ao render de fixture (renderers já são determinísticos) |
| AQ-3 | **`host-prng-in-value-path` viola a assimetria.** Emite positivas nível A sem hop count nem aviso de helper compartilhado; em CDZVUPNQ produz 9 achados byte-idênticos (Tamper.1–9) cobrindo `upgrade`, `approve`, `reset_bls_key`. É o modo de falha do `estimate_swap` que o HANDOFF diz já ter aprendido | `detect.ts:203-225` vs `:94-120` | Reusar `wpath/hops/viaHelper`; colapsar em um achado de escopo de contrato quando o mesmo call site fan-out para >3 entrypoints |
| SHIP-05 | **Falha de RPC é engolida em silêncio.** `catch {}` vazio; artefato online-que-falhou é byte-idêntico ao `--offline`; documento afirma "nenhuma janela de observação foi coletada", que é falso quando a janela era coletável. Observado ao vivo: 1 de 5 runs idênticos saiu sem baseline | `pipeline.ts:49-51`; injeção de throw | `ctx.observationError`; render distinto "coleta nível B FALHOU: <motivo>" vs "janela coletada, 0 ocorrências"; linha `⚠` no CLI; exit code |
| SHIP-06 | **Todo caminho de erro dá stack trace bruto**, inclusive SAC. README diz "detecta e diz que não suporta"; na prática `triggerUncaughtException` + dump `{code: 400, ...}`. `-n futurenet` dá `TypeError: Invalid URL`. Reproduzido nesta revisão | `cli.ts:172` sem try/catch | Envolver `parseAsync`; detectar SAC (código 400 do SDK) e imprimir a mensagem documentada; validar id com `StrKey.isValidContract`; validar `-n`; `--debug` para stack |
| SHIP-07 | **MCP: tool desconhecida executa `analyze` silenciosamente** (reproduzido: `name: "nao_existe"` devolve análise completa). `ping` não implementado; `protocolVersion` hardcoded `2024-11-05`; `serverInfo.version` `0.1.0` vs package `0.0.1`; JSON inválido descartado sem `-32700` | `mcp.ts:59-100` | `switch` com `default` que devolve `-32602`; `ping`; versão do package.json; `bin` `soroguard-mcp`; snippet de config no README; `test/mcp.test.ts` |
| SCF-4 | **O monitoring plan é submetível para ~1 de 75 contratos com rede ligada.** Só 18 de 75 specs declaram eventos (24%, não 31%); dos 18 rodados online, 1 passa (o exemplo curado). Os outros 57 não podem ter baseline B por construção. README:3 diz "gera os dois artefatos" sem caveat. **Correção importante:** a história "RPC público só retém ~62h" foi **refutada** pelo verificador: `MIN_BASELINE_HOURS = 24`, janelas medidas de 60 a 186h, o gargalo é contrato dormente ou sem evento no spec, não retenção | sweep do corpus online nos 18 | Reformular o pitch: "threat model submetível + esqueleto do monitoring plan com evidência". Tornar o monitoramento para contratos sem evento (state-diff via `getLedgerEntries`) o entregável funded principal, não indexer de eventos |

### Médio

| ID | Achado | Fix |
|---|---|---|
| AE-1 | Cross-contract `call`/`try_call` nunca é tratado como caminho de autorização. 23 de 63 achados de auth (37%) alcançam `call`. **Rebaixado de Critical:** 19 dos 23 já saem Medium/High pelo hop count e carregam o blockquote "Este achado ainda não é um achado". Sobram 4 Critical (`update_status`, `report`, `settle_round`, `initialize_escrow`) com a linha C "Qualquer endereço pode invocar e alterar o estado" sem o caveat que dois outros renderers já emitem | Quando `callsOut(ep)`: trocar a linha C por "nenhum `require_auth` neste módulo; se a autorização for delegada ao callee (ex.: `require_auth` do token) ela é invisível aqui"; cap em High. **Não** suprimir: `swap` permissionless em par V2 é correto por desenho e vale como aceitação declarada |
| AE-4 | **Element section malformada trava o parser para sempre.** `while (wasm[q] !== 0x0b) q++` sem bound; módulo de 14 bytes trava `parseModule` e o CLI (`timeout` → 124, sem output). Sem nenhum teste de input malformado | `wasm.ts:191`: bound por `end`, throw explícito; `test/wasm.test.ts` com esse fixture |
| AE-5 | **Parser falha aberto em módulo incompleto.** Sem validação `p + len <= wasm.length`; function section não é parseada, logo corpo ausente vira folha sem calls. Módulo exportando `withdraw` sem code section devolve `soundness: sound`, `reaches: []`, `callGraphComplete: true`. WASM truncado a 99% ainda rende 14 entrypoints e 2 achados | Rejeitar seção além do fim; parsear function section e assertar `bodies.length === declared`; senão `incomplete: true` forçando `approximate` |
| AE-6 | Opcodes desconhecidos assumidos sem imediatos: `return_call` (0x12) some do call graph e dessincroniza o corpo; `table.init` lê 1 imediato de 2; alvos de call nunca validados. Não dispara no corpus atual | Tabela explícita de opcodes; desconhecido → `degraded: true` → `callGraphComplete = false`; 0x12/0x13 como arestas; assert de alvo em faixa |
| AE-7 | `cmp` de versão devolve "igual" em componente não numérico: `advisoriesFor('main')` e `'v26.0.0'` casam com o CVE High. Corpus atual é limpo (41/41 x.y.z) | Regex estrita; não parseável → lacuna declarada, nunca `cmp` |
| AE-8 | `write-before-auth` é comparação textual de offsets sem controle de fluxo, mas o título afirma ordem de execução. 3 contratos, todos `add_signer`/`__constructor` com idioma `current_contract_address().require_auth()` | Retitular para "ordem textual no bytecode, ramos não distinguidos", manter Low |
| AQ-1 | Baseline B em contrato com **zero eventos de qualquer tópico** na janela (o exemplo flagship). **Rebaixado:** a janela foi varrida de fato, 0 é medido, PROBLEMA §3 não é violado. O que sobra: o monitoring plan sozinho não distingue "0 deste tópico com contrato ativo" de "contrato morto", e o exemplo flagship é um contrato sem tráfego. Nota: `events.ts:362 baselineFor` é **código morto**; o caminho vivo é `monitors.ts:169-208` | Em `baselineDe`, quando `events.length === 0`: qualificador "ausência de tráfego, não perfil de tráfego", checklist `⚠` em vez de `✔`. Trocar o flagship por contrato com tráfego (ex.: AMM CBBMQBNH) |
| AQ-5 | 5 de 6 letras STRIDE como lacuna na mediana; template diz "at least one issue for each"; `validate.ts` aceita lacuna declarada e diz `submetível`. **Não verificado** (verificador falhou por erro de API) | Terceiro estado "submetível após preencher N letras" com worklist; pré-validar um artefato com alguém da SDF antes de submeter |
| AQ-6 | Com input `.wasm`, o path do arquivo vai para toda célula "On-chain address" | Extrair `C...` do basename se casar `/^C[A-Z2-7]{55}$/`; senão marcador "a definir" |
| AQ-7 | `inspect <arquivo.wasm>` crasha (`Invalid contract ID`), embora HANDOFF e README documentem essa invocação como primeiro comando | Mesma resolução de target de `analyze`/`artifact` |
| AQ-8 | Em `--offline` o monitoring plan **nunca** é submetível, e é o único demo sem rede | CLI: "NÃO submetível: 13 blockers, 13 por ausência de janela (rode sem --offline)"; README com o exemplo online como headline |
| SHIP-12 | 17–21 s de espera silenciosa contra `mainnet.sorobanrpc.com` (comunitário) hardcoded, sem timeout, sem progresso, sem env var | Linha de progresso; `--timeout`; `SOROGUARD_RPC_URL`; documentar rate limit |

### Baixo

AE-9 `READ_SHAPED` ancorado no início do nome deixa `gauges_get_reward_info` passar (3 contratos, 3º achado mais frequente na triagem). AE-10 `tableTargets` populado e nunca lido; `interfaceVersion` nunca decodificado, então não há checagem de env.json vs binário; zero testes diretos de `wasm.ts`. AQ-9 legenda do DFD diz "cada store é chave inferida" mesmo quando nenhuma foi; "1 chaves", "1 linhas". CLAIM-09 comparar "≤16% precisão" (limite teórico por forma de nome) com 59,41% da CoinFabrik (ground truth humano) sem dizer que são quantidades diferentes; a versão honesta é mais persuasiva. SHIP-13 invocação sem subcomando sai 0; data UTC estampa "amanhã" à noite em GMT-3.

---

## 4. Estratégia de submissão

### Decisões

- **Trilha para o #46 (deadline 2026-11-08): Open Track.** RFP tem exatamente duas abertas (LayerZero DVN, x402 Facilitator+Bazaar), nenhuma casa; o handbook diz literalmente "wait for a future RFP" para tooling fora de RFP. Integration exige métrica on-chain que CLI não produz.
- **Orçamento 100% forward-looking.** Handbook: "Reimbursement for past work" é inelegível. A ferramenta pronta entra como "contribuída ao ecossistema sem custo ao SCF; o budget financia só o que falta". Atenção: `IDEIA-TOOLKIT-SEGURANCA.md:141-145` ainda propõe tranches pagando o que já existe. Não reutilizar.
- **Pedir ~US$96k**, abaixo da mediana de US$98,5k, na faixa de Passkey UI (95k) e acima de Contract Source Verification (73,5k).
- **Disclosure de IA explícito e sem hedge.** Exigido no Open Track e coerente com o pitch de honestidade.
- **Licença: Apache-2.0** (o rascunho de um agente dizia MIT; ignorar, manter o que o package.json já declara).

### Ação de maior alavancagem, esta semana

**Criar a RFP que você quer responder.** Governança trimestral: Signal Intake em t−8 (~13 set, acabou de passar), "delegates compile new RFPs" em t−5 (~4 out), publicação em t−3 (~18 out). O handbook diz explicitamente: "add it on the Stellarlight Ideas page and discuss further in the Stellar Dev Discord". Comparáveis de RFP para tooling sem tração: US$73,5k–120k. Se uma RFP compatível sair em ~18 out, trocar para a trilha RFP antes de 8 nov, mesmo deadline.

**Perguntar à SDF se isto está no roadmap deles.** `IDEIA-TOOLKIT §6` já classificou "SDF constrói internamente" como risco alto e §7 fez disso o primeiro passo; HANDOFF §10 registrou a decisão de submeter sem perguntar. Custa uma mensagem. Se a resposta for "não, e queremos revisar os artefatos", é o melhor endosso disponível e entra citado na submissão.

### Tabela de tranches (rascunho)

| Tranche | % / US$ | Tema | Definition of done (checável em máquina no corpus público) |
|---|---|---|---|
| #0 | 10% / 9.600 | Já entregue antes da submissão, sem custo ao SCF | Repo público Apache-2.0 com CI, npm publicado, saída em inglês, corpus de 75 reproduzível offline |
| #1 | 20% / 19.200 | "Os documentos deixam de ser majoritariamente lacuna" | Detectores de dataflow #7, #11–14 (durabilidade/TTL de storage; 2 Criticals + 4 Highs em auditorias reais) + suporte a SAC. `calibrate.mjs` mostra ≥1 issue não-lacuna em ≥4 das 6 letras para ≥60% dos 75 (hoje: 4 letras são lacuna em 65–75 de 75); achados/contrato ≤4,0 (hoje 2,3); `artifact` completa em 10 SACs |
| #2 | 30% / 28.800 | "A precisão deixa de ser chute" | Ground truth rotulado a partir do Audit Bank (77 auditorias, 57 com URL pública, verificado ao vivo) mapeado sobre contratos do corpus; precisão/recall por classe publicados, sejam quais forem; monitoring plan completo com state-diff via `getLedgerEntries` para os 57/75 sem evento. DoD: ≥30 contratos rotulados, método open source e reexecutável; plano passa o próprio checklist em ≥20 de 75 sem input humano além de dono e canal (hoje ~1) |
| #3 | 40% / 38.400 | "Outros times usam" | Serviço hospedado (contract ID → dois documentos), release do MCP, docs versionados. DoD: ≥99% de sucesso em 100 contract IDs reais; ≥5 times do SCF Build usaram para os documentos que de fato submeteram, confirmado por escrito. Indicador stretch, fora do controle do time: ≥1 artefato aceito em revisão real de tranche |

Sustentabilidade pós-award: **Public Goods Award** (até US$50k/trimestre, invitation-only, é o caminho que a Scout usa há 4 trimestres consecutivos). Um delegate já sabe que a Scout é financiada recorrentemente na mesma categoria; a diferenciação tem que ser mais afiada que "lemos o binário".

### As três perguntas que o delegate vai fazer

1. **"Um time escreve esses docs em um dia."** Escreve, mas não os torna conferíveis em um dia. Documento à mão tem afirmações que só os autores verificam e os dois documentos divergem porque nada os amarra. Aqui toda afirmação carrega nível de evidência, a negativa de alcançabilidade é reproduzível por qualquer um a partir do hash do WASM, e o threat ID é a chave estrangeira que gera o monitor ID e o filtro `getEvents`. E o budget compra os detectores de dataflow e o número de precisão medido, não o preenchimento. **Reforço:** pegar um threat model de tranche 2 já aceito e colocar ao lado de um gerado, contando (a) afirmações que terceiro reverifica só do hash e (b) threat IDs que resolvem em monitor executável.
2. **"Qual é a taxa de falso positivo?"** Medida e publicada: predicado nu de autorização tem limite superior teórico de ≤16% (derivado por forma de nome, não por ground truth humano). Três famílias de exceção cortaram `unauthenticated-state-mutation` de 89 para 30. O que não foi medido é verdadeiro positivo contra rótulo humano, e esse é o entregável da tranche #2, contra as 77 auditorias do Audit Bank, publicado seja qual for o número. Spoof e Info dão zero em 75 de 75 porque identidade e exposição de dados não são observáveis no bytecode; o documento diz isso em vez de inventar issue.
3. **"Por que financiar uma ferramenta cujo único mercado é o processo do próprio SCF?"** O tranche 2 é a cunha, não o mercado. Ler o artefato deployado responde o que ferramentas de fonte não respondem: qual SDK compilou o que está vivo (41 de 75 declaram; 34 em faixa do CVE-2026-26267, High), e o que faz um contrato de terceiro que você integra, sem pedir o repo. Scout, Guard-CLI, Persist e Komet exigem fonte; nenhum produz os dois artefatos.

### O que é barato de conseguir antes de 8 nov

1. Repo público + CI + exemplos em inglês: 1 dia.
2. `npm publish`: 1 hora (nome livre, 404 confirmado no registry).
3. Gravação de 3 minutos: contract ID entra, dois documentos saem, validador visível: 2 horas.
4. Três times do ecossistema rodando no próprio contrato e uma frase citável: 1 semana de outreach. Trustless Work já está no corpus.
5. Código de referral via Ambassador Chapter. `INSTAAWARD.md` marca o lead do chapter Brasil como UNKNOWN. Resolver agora; é o gate do referral e do InstaAward.

---

## 5. Correções ao próprio material de pesquisa

- `TAXONOMIA-VALIDACAO.md:756`: o curl do Audit Bank falha como escrito (falta `query=`). Forma correta: `--data-urlencode 'query=*[_type=="audit" …]'`. Retorna 77 auditorias, 57 com URL pública.
- `IDEIA-TOOLKIT-SEGURANCA.md` cita "31% dos contratos com eventos no spec"; medido: 18 de 75 = 24%.
- `SCF-BUILD-AWARD.md` e a pesquisa não mencionam o **Public Goods Award**, que é a trilha de sustentabilidade e a que a concorrente já usa.
- O rascunho de tranches em `IDEIA-TOOLKIT §5` propõe métrica de tranche 3 "artefato aceito em revisão real" que o time não controla; manter como stretch, não como gate.

---

## 6. UNKNOWN

- Se a SDF tem algo assim no roadmap. Custa uma mensagem; não foi perguntado.
- Se um delegate aplicando o template literalmente rejeita um documento com 5 de 6 letras como lacuna declarada (AQ-5 ficou sem verificação adversarial). Mitigação: pré-validar um artefato com alguém da SDF.
- Quem é o lead do Ambassador Chapter Brasil (gate do referral).
- Verdadeiros positivos contra ground truth humano: não medido, e é a primeira pergunta de auditor.

---

## 7. Método desta revisão

29 agentes: 5 revisores (um por frente) + 23 verificadores céticos (um por achado high/critical, até 5 por frente) + 1 falha de API (AQ-5). 499 chamadas de ferramenta, ~21 minutos. Três achados graves ficaram sem verificador por limite de 5 por frente (SHIP-06, SHIP-07, SCF-6); SHIP-06 e SHIP-07 foram reproduzidos manualmente nesta revisão, SCF-6 é o mesmo fato de CLAIM-04 (verificado). Nenhum arquivo do projeto foi alterado além deste documento.

---

## 8. Estado após as correções (2026-09-17)

Tudo abaixo foi executado nesta sessão e verificado em simulação de clone limpo (só os arquivos que o git rastrearia, `node_modules` linkado): `pnpm build` ok, `pnpm test` 139/139, `calibrate.mjs` lê os 75 contratos, `npm pack --dry-run` inclui `dist/cli.js` e `dist/mcp.js` com shebang e nenhum arquivo de scratch.

| Item | Estado |
|---|---|
| B1 saída em inglês | ✅ `--lang en` padrão, `pt` opcional; `src/i18n.ts`; zero diacrítico nos dois documentos em 75/75 contratos; validador com contagens idênticas nos dois idiomas |
| B2 corpus commitável | ✅ `.gitignore` corrigido, `corpus/README.md`, sha256 == wasm hash conferido |
| B3 npm | ✅ `files`, `prepublishOnly`, `clean`, bin `soroguard` + `soroguard-mcp`, `packageManager` |
| B4 LICENSE/NOTICE | ✅ |
| B5 números gerados | ✅ `scripts/stats.mjs --write` entre marcadores em README e HANDOFF |
| B6/B7 overclaims em HANDOFF/PROBLEMA | ✅ reenquadrados; bloco de correção em PROBLEMA |
| B8 limpeza | ✅ `.rev/`, `PLANO-3-DIAS.md`, `scripts/prototipos/` movidos para `../soroguard-scratch/` |
| B9 disclosure de IA | ✅ seção "How this was built" no README |
| B10 metadados, CI | ✅ `package.json` completo, `.github/workflows/ci.yml` |
| AE-3 BFS | ✅ `pathTo` é caminho mínimo; 15 testes de parser |
| AE-4/5/6 parser fail-closed | ✅ loops limitados, seção além do fim rejeitada, module `incomplete`, opcodes desconhecidos rebaixam |
| AE-1 cross-call | ✅ teto High, linha C específica, rebaixamento visível na calibração |
| AE-7 sdkver estrito | ✅ |
| AQ-3 PRNG agregado | ✅ 12 → 4 |
| AQ-1 janela sem tráfego | ✅ qualificador + blocker |
| SHIP-05/06/07/12 | ✅ erro de RPC visível (exit 2), erros em uma linha, SAC detectado, MCP com switch explícito/ping/-32700, progresso e `--timeout`, `SOROGUARD_RPC_URL` |
| Exemplos | ✅ 3 contratos com tráfego real, regenerados por `scripts/regen-examples.mjs`, testados por `test/examples.test.ts` |
| 19 frases insustentáveis achadas na leitura dos exemplos | ✅ corrigidas na origem: getters fora de `silent-mutation`, init nunca Critical, "is proof" → "sound for this call graph", `has_contract_data` como fato A, blockers distinguem janela ausente / zero medido / fill-in, §4 e §6 do plano concordam, hash do WASM agora chega aos documentos (bug em `spec.ts` com `xdr.Hash`) |

**Reenquadramento do CVE.** GHSA/NVD confirmam que CVE-2026-26267 e CVE-2026-32322 existem e as faixas em `sdkver.ts` batem. A verificação por fonte (`docs/CVE-2026-26267-VERIFICACAO.md`) encontrou 0 vulneráveis em 20 verificáveis. O CVE virou inventário; o argumento central do pitch passou a ser a família de wallets com binário anterior ao fix upstream e a precisão medida contra fonte (`docs/PRECISION.md`).

**Fora do repo, de propósito.** `../soroguard-private/docs/` guarda a triagem nominal, o documento pré-disclosure das wallets e o rascunho de aviso ao projeto do mock em produção. Nada disso pode entrar no git antes do disclosure privado.

**Não feito nesta sessão, por ser decisão externa:** push para remoto, `npm publish`, envio dos disclosures, pergunta à SDF, post na Stellarlight Ideas, referral.

---

## 9. Pendências abertas após o censo (2026-09-17)

Detalhe nominal em `../soroguard-private/docs/REVISAO-SCF-secao9-nominal.md`. Resumo publicável:

- **L3, resolvido nesta revisão:** o corpus público não pode conter os contratos sob embargo, porque `analyze` neles reproduz o achado. Foram removidos do corpus commitado; `calibration.json`, `stats.mjs` e os exemplos foram regenerados sem eles.
- **L4:** `PRECISION.md` afirmava "nenhum permite perda de fundos hoje" sobre as 30 instâncias triadas; a mesma forma de código deployada em outras instâncias pode permitir. Texto ajustado sem nomear.
- **Censo:** 3.677 hashes distintos, 151 mil contratos, 0 falhas de parse, 2,21 achados por binário; corpus de 75 é representativo (2,16). Agregados em `corpus/census/`; candidatos a triagem manual (216) no privado.
- **P0 externos:** disclosures privados antes de qualquer nome público; P1: post Stellarlight Ideas antes de 2026-10-04, benchmark contra threat models de tranche 2 reais, 1 revisor externo.
