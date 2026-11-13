# Runbook — falhas repetidas de autenticação

**Estado:** rascunho; não executado. Completar após implementar logs e coleta. A query, o limiar e os comandos operacionais precisam ser validados no laboratório.

**Escopo:** simulação autorizada contra a TaskFlow local do grupo, com conta de teste. Registrar responsável, data, alvo, janela, volume limitado e critério de parada antes da execução.

## 1. Preparação

- Confirmar a disponibilidade da aplicação, Loki e Grafana e sincronizar a janela temporal da coleta.
- Definir o contrato de logs: sugestão inicial `event`, `source_ip`, `request_id` e `timestamp`, com evento `login_failed`. Confirmar no código os nomes efetivos.
- Não registrar senhas, cookies, tokens nem o corpo integral do formulário de login.
- Definir responsável por conduzir o exercício e quem observará o Grafana; preparar conta de teste e restauração.
- Registrar critérios de parada para erro inesperado, indisponibilidade ou alvo diferente do laboratório.

## 2. Detecção e análise

**Condição inicial proposta:** pelo menos 10 falhas de login de um mesmo IP em cinco minutos. Ajustar e justificar após observar o comportamento normal da aplicação.

Consulta inicial para contagem por IP, **ainda não validada**, assumindo label `job="taskflow"` e campos JSON sugeridos acima:

```logql
sum by (source_ip) (
  count_over_time({job="taskflow"} | json | __error__="" | event="login_failed" [5m])
) >= 10
```

Consultas complementares propostas, também pendentes de validação:

```logql
{job="taskflow"} | json | __error__="" | event="login_failed"
```

```logql
{job="taskflow"} | json | __error__="" | request_id="PREENCHER_ID_REAL"
```

Executar as três consultas com dados reais. Registrar janela temporal, IP observado, contagem, request IDs e a query exata usada. Comparar falhas com eventuais logins bem-sucedidos e distinguir a simulação de tráfego normal. Guardar captura do Grafana e amostra revisada dos logs.

## 3. Contenção, erradicação e recuperação

Encerrar a simulação ao atingir o objetivo ou um critério de parada. Aplicar a contenção adequada ao desenho final da aplicação, como bloqueio temporário da origem ou limitação de tentativas. Registrar os comandos reais, escopo e responsável após definir os componentes; não presumir mecanismos ainda inexistentes.

Investigar eventual autenticação indevida, remover efeitos do exercício e renovar apenas as credenciais de teste afetadas, se necessário. Restaurar o acesso controlado e comprovar com novas requisições e logs que a aplicação segue funcional. Preservar evidências antes de limpar dados.

## 4. Atividades pós-incidente

Registrar início, detecção, contenção e recuperação; relacionar cada horário a evidências. Documentar causa, impacto, limites da detecção, ajuste de limiar e ação de melhoria com responsável. Vincular PRs de correção e atualizar este runbook com os passos efetivamente exercitados.

O roteiro segue as quatro fases solicitadas pelo enunciado da disciplina. A entrega exige o exercício real e sua detecção no Grafana; este rascunho não comprova essa execução.
