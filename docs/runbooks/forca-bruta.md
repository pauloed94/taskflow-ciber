# Runbook — força bruta no login

**Estado:** ensaiado em laboratório em 2026-11-07 (a detecção, as consultas e a correlação foram executadas contra um Loki real, e estão registradas na seção 6). A simulação **ao vivo**, no Grafana, deve ser repetida e registrada na apresentação.

**Escopo:** simulação autorizada contra a TaskFlow local do próprio grupo, com conta de teste. Antes de executar, registrar responsável, data, alvo, janela, volume e critério de parada.

**Framework:** as quatro fases do NIST SP 800-61 — detecção e análise, contenção, erradicação e recuperação.

## 1. Condição de disparo

Acionar este runbook quando **um mesmo IP acumular 10 ou mais falhas de login em 5 minutos**.

- **Por que 10 em 5 minutos:** uma pessoa legítima erra a senha uma ou duas vezes e para; um script tenta dezenas de vezes em segundos. No ensaio, 20 tentativas levaram 2 segundos. O limiar é um ponto de partida e deve ser ajustado com o comportamento normal da aplicação, para não gerar fadiga de alertas.
- **Quem dispara:** a consulta 2 de [`observability/consultas-logql.md`](../../observability/consultas-logql.md) (abaixo), que vem **vazia** em uso normal e devolve o IP quando o limiar é cruzado.

## 2. Detecção e análise

**Query de detecção** (a que foi usada no ensaio; roda no Grafana, em *Explore*, fonte de dados *Loki*):

```logql
sum by (ip) (count_over_time({job="taskflow"} | json | event="login_attempt" | result="failure" [5m])) >= 10
```

Se devolver um IP, confirmar o escopo, nesta ordem:

1. **Quantas falhas e de qual IP:** a própria consulta acima (valor = número de falhas em 5 minutos).
2. **Quais usuários foram testados:** `sum by (username) (count_over_time({job="taskflow"} | json | event="login_attempt" | result="failure" [5m]))`. Vários nomes (`admin`, `root`, `test`) em intervalos regulares indicam script automatizado, e não erro de digitação.
3. **Alguma tentativa deu certo?** `sum by (ip) (count_over_time({job="taskflow"} | json | event="login_attempt" | result="success" [5m]))`. Um IP com muitas falhas **e** um sucesso depois delas é possível comprometimento de conta; um sucesso **antes** das falhas é o uso legítimo.
4. **A jornada de uma tentativa:** pegar um `request_id` na lista `{job="taskflow", event="login_attempt"} | json | result="failure"` e consultar `{job="taskflow"} | json | request_id="<id>"`.
5. **O pico no tempo:** `sum(count_over_time({job="taskflow"} | json | event="login_attempt" | result="failure" [1m]))`, em série temporal.

Registrar: janela, IP, contagem, usuários testados, `request_id` de exemplo e a query exata usada. Guardar uma captura do Grafana.

## 3. Contenção

Objetivo: **parar o dano sem destruir evidências**.

1. **Preservar as evidências primeiro:** copiar `logs/taskflow.log` (e os rotacionados) para uma pasta fora do Git antes de qualquer limpeza ou rotação. Os logs têm usuários e IPs e não devem ser versionados.
2. **Conter a origem:** em um ambiente real, bloquear temporariamente o IP no firewall, no WAF ou no balanceador. **No laboratório, o ataque parte da própria máquina** (`127.0.0.1`), então bloquear esse IP derrubaria o próprio acesso; a contenção do exercício é **encerrar o script de ataque** (o critério de parada) e registrar a decisão.
3. **Se houve login com sucesso vindo do IP atacante** (passo 2.3): tratar como comprometimento. Trocar `TASKFLOW_SECRET_KEY` e reiniciar o app (isso invalida todas as sessões abertas) e renovar a senha da conta afetada.

## 4. Erradicação

**Causa raiz:** o endpoint `/login` **não limita tentativas nem bloqueia progressivamente**. Foi o que o ensaio mostrou: 20 tentativas em 2 segundos, e nenhuma foi barrada.

**Correção:** limitar as tentativas por IP e por conta (por exemplo, 5 por minuto com bloqueio temporário e atraso crescente, com uma biblioteca como o Flask-Limiter) e exigir senhas fortes. **Esta correção ainda não está implementada**; fica como melhoria com responsável e PR próprios.

## 5. Recuperação

1. Remover qualquer bloqueio temporário aplicado na contenção.
2. Confirmar que a aplicação segue funcional: um login legítimo com sucesso, e as consultas 1 e 2 sem novos picos.
3. **Monitorar a mesma query de detecção por 24 a 48 horas** para ver se o padrão volta.
4. **Pós-incidente:** registrar início, detecção, contenção e recuperação, cada um ligado a uma evidência; documentar causa, impacto e os limites da detecção; ajustar o limiar se preciso; e **criar um alerta automático** no Grafana para a consulta de detecção, com ação associada (este runbook), para o próximo caso.

## 6. Evidências do ensaio (2026-11-07)

Stack: Loki 2.9.6, Promtail 2.9.6 e Grafana 10.4.2, por `observability/docker-compose.yml`, com o app registrando em `logs/taskflow.log`.

| O que | Resultado |
| --- | --- |
| Simulação | 20 tentativas de login falhas em 2 s, com os usuários `admin`, `root` e `test` |
| Consulta de detecção (limiar ≥ 10 em 5 min) | devolveu o IP de origem com `20` |
| Consulta por usuário | `admin` 6, `root` 7, `test` 7 |
| Login com sucesso do mesmo IP | `1`, o login legítimo feito antes das falhas |
| Correlação por `request_id` | 2 eventos da mesma requisição (`login_attempt` e `http_request`) |
| Pico por minuto | `20` |
| A mesma consulta **pelo Grafana** (fonte de dados provisionada) | mesmo resultado, `20` |
| Senha do admin no arquivo de log e no Loki | **0 ocorrências** |

O que **falta** para fechar o critério da disciplina: repetir a simulação **ao vivo**, com o Grafana aberto, e anexar a captura do pico e da query de detecção.
