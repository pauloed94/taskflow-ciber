# Hardening do sistema operacional (Lynis): os 3 achados corrigidos

O enunciado (requisito M2-05) pede **corrigir e documentar os 3 principais achados** do Lynis no Ubuntu do laboratório da Aula 3. Os três abaixo foram escolhidos por serem **fáceis de corrigir e de verificar**, e o segundo scan confirmou que os três sumiram da lista (índice **60 → 63**). Para cada um: o código do teste, o que significa, o risco, a correção e a prova.

**Resultado:** hardening index **60 → 63**, Suggestions **40 → 37**, Warnings **2 → 2**. Auditoria feita em 2026-11-01, com o Lynis 3.0.7, no container Ubuntu 22.04 do laboratório da Aula 3, por um integrante do grupo. Os relatórios completos (a saída do Lynis, antes e depois) ficam fora do repositório.

| Código | Resumo | Correção | Resultado |
| --- | --- | --- | --- |
| [`KRNL-5820`](#1-krnl-5820--desabilitar-core-dumps) | *core dumps* habilitados | `* hard core 0` em `/etc/security/limits.conf` | resolvido |
| [`AUTH-9262`](#2-auth-9262--módulo-pam-de-senha-forte) | o sistema aceita qualquer senha | instalar o `libpam-pwquality` | resolvido |
| [`AUTH-9328`](#3-auth-9328--umask-mais-restrito-027) | `umask` padrão permissivo | `UMASK 027` em `/etc/login.defs` | resolvido |

---

## 1. `KRNL-5820` — desabilitar core dumps

**O que o Lynis disse:** *"If not required, consider explicit disabling of core dump in /etc/security/limits.conf file"*.

- **O que é:** quando um programa trava, o sistema pode gravar em disco uma "foto" da memória dele no momento da falha, o **core dump**. Serve para o programador descobrir por que travou.
- **O risco:** essa foto contém **tudo o que estava na memória**: senhas, chaves, tokens, dados de sessão. Se o arquivo ficar legível por outros usuários ou for copiado para fora do servidor, vira um vazamento.
- **A correção:**

  ```bash
  echo '* hard core 0' >> /etc/security/limits.conf
  ```

  A linha tem quatro partes: `*` (todos os usuários), `hard` (limite que o usuário não consegue aumentar), `core` (tamanho do arquivo de core dump) e `0` (nenhum). O `>>` **acrescenta** ao final, sem apagar nada.
- **A prova:** no segundo scan, o `KRNL-5820` **não aparece mais** na lista de Suggestions.
- **A contrapartida:** depurar fica mais difícil. É uma decisão consciente, e não automática. O limite vale para sessões de login.

## 2. `AUTH-9262` — módulo PAM de senha forte

**O que o Lynis disse:** *"Install a PAM module for password strength testing like pam_cracklib or pam_passwdqc"*.

- **O que é PAM:** *Pluggable Authentication Modules*, o sistema do Linux que `login`, `sudo`, `ssh` e `passwd` usam para decidir quem entra e que regras valem para as senhas. Cada regra é um módulo pequeno, configurado em `/etc/pam.d/`.
- **O risco:** sem um módulo de qualidade, o sistema aceita **qualquer senha**, até uma de uma letra.
- **A correção:**

  ```bash
  DEBIAN_FRONTEND=noninteractive apt install -y libpam-pwquality
  ```

  O pacote traz o módulo `pam_pwquality`, que avalia a senha na troca: tamanho mínimo, mistura de tipos de caractere e recusa de palavras de dicionário e padrões óbvios (`123456`, `password`). Vieram vários pacotes porque ele depende de bibliotecas e de um dicionário (`cracklib`, `wamerican`).
- **A prova:** a linha `password requisite pam_pwquality.so retry=3` apareceu em `/etc/pam.d/common-password` (linha 25), e o `AUTH-9262` sumiu no segundo scan. `requisite` significa "se a senha for fraca, recuse na hora", e `retry=3` dá três tentativas.

## 3. `AUTH-9328` — umask mais restrito (027)

**O que o Lynis disse:** *"Default umask in /etc/login.defs could be more strict like 027"*.

- **O que é:** o **umask** é uma máscara que decide **quais permissões um arquivo novo recebe** ao ser criado. Ela diz o que **tirar** das permissões do dono, do grupo e dos outros.
- **O risco:** com o padrão `022`, todo arquivo novo nasce **legível por qualquer usuário** do sistema, o que expõe logs, configurações e arquivos de trabalho sem querer.

  | umask | Arquivo novo | Pasta nova | Quem lê um arquivo novo |
  | --- | --- | --- | --- |
  | `022` (antes) | `644` (`rw-r--r--`) | `755` | dono, grupo **e todos os outros** |
  | `027` (depois) | `640` (`rw-r-----`) | `750` | dono e grupo; **outros não** |

- **A correção:**

  ```bash
  sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
  ```

  O `sed -i` altera o arquivo no lugar. O `s/A/B/` troca A por B; `^UMASK.*` procura a linha que **começa** com `UMASK` (o `^` evita mexer em comentários que só citam a palavra).
- **A prova:** a linha 151 do arquivo passou de `UMASK 022` para `UMASK 027`, e o `AUTH-9328` sumiu no segundo scan.
- **Por que `027` e não `077`:** o `027` ainda permite compartilhar dentro do grupo (útil em equipes) e é o que o Lynis sugere. O `077` fecha até o grupo, e fica para casos mais rígidos.
- **O limite:** vale para sessões de login. Serviços que rodam sozinhos têm o umask próprio.

---

## O que não foi corrigido (e por quê)

Os **2 Warnings** continuam depois das correções:

| Código | O que o Lynis aponta | Por que não dá para corrigir num container |
| --- | --- | --- |
| `FIRE-4512` | módulos do iptables carregados, mas sem regras ativas | o container não tem a permissão `NET_ADMIN` nem os módulos do kernel necessários para ativar um firewall |
| `LOGG-2138` | o `klogd` não está rodando | o container não tem logs do kernel: quem tem é o hospedeiro |

As outras **37 Suggestions** são melhorias possíveis que não foram escolhidas (por exemplo, idade mínima e máxima de senha, banner legal, instalar o `debsums`). Escolher 3 e documentá-los bem era o pedido do enunciado.

## Como foi medido

1. Container Ubuntu 22.04 do laboratório, com o Lynis 3.0.7 instalado.
2. `lynis audit system --no-colors | tee /tmp/lynis-antes.txt` (o "antes").
3. As 3 correções acima.
4. O mesmo comando, salvo em `/tmp/lynis-depois.txt` (o "depois").
5. Comparação dos dois relatórios: **exatamente 3 suggestions resolvidas** (as três acima), **nenhuma nova**.
