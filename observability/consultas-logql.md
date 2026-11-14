# Consultas LogQL da TaskFlow

Todas rodam no Grafana (**Explore**, fonte de dados **Loki**) ou direto na API do Loki. Elas dependem do formato dos logs: uma linha JSON por evento, com os campos `event`, `result`, `username`, `ip` e `request_id` (ver `app/app.py`). Foram **executadas contra um Loki real** em 2026-11-07, com 20 tentativas de login falhas simuladas, e o resultado de cada uma está registrado abaixo.

## 1. Falhas de login por IP (a que detecta o ataque)

```logql
sum by (ip) (count_over_time({job="taskflow"} | json | event="login_attempt" | result="failure" [5m]))
```

Conta as falhas de login dos últimos 5 minutos, agrupadas pelo IP de origem. **Resultado do ensaio:** um único IP com `20`.

## 2. Detecção: o limiar do runbook

```logql
sum by (ip) (count_over_time({job="taskflow"} | json | event="login_attempt" | result="failure" [5m])) >= 10
```

Só devolve os IPs com **10 falhas ou mais** em 5 minutos. É a condição de disparo do [runbook](../docs/runbooks/forca-bruta.md). **Resultado do ensaio:** o mesmo IP, com `20`. Em uso normal a consulta vem vazia.

## 3. Falhas por usuário tentado

```logql
sum by (username) (count_over_time({job="taskflow"} | json | event="login_attempt" | result="failure" [5m]))
```

Mostra quais usuários o atacante testou (varredura de nomes é característica de script automatizado). **Resultado do ensaio:** `admin` 6, `root` 7 e `test` 7.

## 4. Houve login com sucesso vindo do mesmo IP?

```logql
sum by (ip) (count_over_time({job="taskflow"} | json | event="login_attempt" | result="success" [5m]))
```

Cruze com a consulta 1: um IP com muitas falhas **e** um sucesso é possível comprometimento de conta. **Resultado do ensaio:** `1`, que foi o login legítimo feito no mesmo teste (por isso a análise precisa olhar a ordem dos eventos: o sucesso veio **antes** das falhas).

## 5. Correlação por `request_id` (a jornada de uma requisição)

Primeiro liste as falhas e escolha um `request_id`:

```logql
{job="taskflow", event="login_attempt"} | json | result="failure"
```

Depois reconstrua tudo o que aconteceu naquela requisição:

```logql
{job="taskflow"} | json | request_id="COLE_UM_REQUEST_ID_AQUI"
```

**Resultado do ensaio:** a segunda consulta devolveu **dois eventos** da mesma requisição, `login_attempt` (o evento de negócio) e `http_request` (o fechamento técnico, com o código de status).

## 6. Volume de falhas por minuto (para ver o pico em um gráfico)

```logql
sum(count_over_time({job="taskflow"} | json | event="login_attempt" | result="failure" [1m]))
```

No Explore, mude a visualização para **série temporal**. **Resultado do ensaio:** um pico de `20` no minuto do ataque.

## Observações

- O `| json` extrai os campos do JSON; sem ele só funcionam os rótulos (`job`, `app`, `level`, `event`).
- `level` e `event` são rótulos (o Promtail os extrai), por isso `{job="taskflow", event="login_attempt"}` já filtra rápido; `ip`, `username`, `result` e `request_id` ficam no JSON.
- Localmente (`python app/app.py` e `curl` na mesma máquina) o IP aparece como `127.0.0.1`. No ensaio, com o app em um container, apareceu o do gateway do Docker (`172.17.0.1`).
- **Nenhuma consulta consegue achar senha, cookie ou token**, porque eles nunca são registrados (ver o teste de `app/app.py` no PR do logging; no ensaio, 0 ocorrências da senha do admin no arquivo e no Loki).
