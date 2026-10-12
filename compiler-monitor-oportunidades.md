# compiler-monitor: Oportunidades de Segurança, Correções e Evoluções

> **Propósito deste documento**: servir como SDD (Software Design Document) de referência para uma futura iteração do módulo `compiler-monitor`. Cada item traz identificador, severidade, localização exata, cenário de exploração ou falha, proposta de correção com detalhamento técnico e critérios de aceite.
>
> **Escopo analisado**: `compiler-monitor/src/{monitor.c, monitor.h, main.c}`, `compiler-monitor/{CMakeLists.txt, Dockerfile, Makefile, src/Makefile}` e os pontos de integração que definem o comportamento efetivo do sandbox: `compiler-images/base/base-script.sh`, scripts por linguagem (`c-script.sh`, `java-script.sh`, `python-script.sh`, etc.) e `compiler-engine/src/rcc/engine/{container.py, grading.py}`.
>
> **Data da análise**: 2026-10-11.

---

## 1. Contexto e Arquitetura Atual

### 1.1 Papel do módulo

O `compiler-monitor` é um binário C (~300 linhas) que executa um comando filho sob limites de recursos e reporta estatísticas de execução. Ele é o componente mais interno da cadeia de sandbox do run.codes:

```
compiler-engine (Python, host)
  └── docker run <imagem-da-linguagem>          [container.py:170]
        └── /usr/bin/runcodes (base-script.sh, PID 1, root)
              └── /usr/bin/monitor -f .. -m .. -i .. -o .. -e .. -c "timeout --signal=SIGKILL N <cmd>"
                    └── fork() + setrlimit(FSIZE, AS) + freopen() + execvp()
                          └── timeout(1)
                                └── programa do aluno
```

### 1.2 Contrato de saída atual

O monitor imprime em stdout (capturado em `<test_id>.monitor_out`):

```
exit_status=<int>
signal=<SIGNAME ou vazio>
time=<float, segundos wall-clock>
```

O engine (`grading.py:49-53`) parseia esse arquivo com `configparser` e decide:
- `signal` não-vazio **ou** stderr não-vazio → `STATUS_INCORRECT`;
- caso contrário → diff do output contra o gabarito.

Observação importante: `exit_status` é impresso mas **nunca consumido** pelo grading.

### 1.3 Mecanismos de contenção hoje existentes

| Camada | Mecanismo | Estado |
|---|---|---|
| monitor | `RLIMIT_FSIZE` (tamanho máximo por arquivo) | ativo (5 MB default via script) |
| monitor | `RLIMIT_AS` (memória virtual) | ativo, exceto Java (`monitor_max_ms=0`) |
| monitor | redirecionamento stdin/stdout/stderr | ativo |
| script | `timeout --signal=SIGKILL N` (wall-clock) | ativo |
| engine | timeout de fase via protocolo de log (`compilation.done`, `run.done`) | ativo |
| engine | `container.wait(timeout)` + `kill` + `remove(force=True)` | ativo |
| docker | isolamento default de namespaces/capabilities | default, sem hardening |

### 1.4 Mecanismos ausentes (resumo do gap)

Sem limite de CPU, sem limite de número de processos, sem limite de disco total, sem isolamento de rede, sem drop de privilégios (tudo roda como **root** dentro do container), sem seccomp/AppArmor custom, sem medição de memória de pico ou tempo de CPU, sem distinção TLE/MLE/RE no resultado. O próprio `README.md` do módulo admite: *"this solution... might not be sufficient on preventing miss-use from the users"*.

---

## 2. Vulnerabilidades de Segurança

Severidades: **Crítica** (comprometimento do host ou de outros usuários), **Alta** (fraude de correção, DoS do serviço), **Média** (defesa em profundidade), **Baixa** (higiene).

### S1 — [CRÍTICA] Container sem limites de recursos no Docker

**Local**: `compiler-engine/src/rcc/engine/container.py:170-176`.

```python
container = await asyncio.to_thread(
    client.containers.run,
    language.image,
    detach=True,
    remove=False,
    volumes=volumes,
)
```

Nenhum dos parâmetros de contenção do Docker é usado: `mem_limit`, `memswap_limit`, `pids_limit`, `cpu_quota`/`cpu_period` (ou `nano_cpus`), `storage_opt`, `ulimits`.

**Cenários de exploração**:
1. **Fork bomb**: `RLIMIT_NPROC` não é setado pelo monitor e `pids_limit` não é setado no container. Um `:(){ :|:& };:` ou `while(1) fork();` esgota a tabela de processos do host e derruba o serviço inteiro.
2. **Exaustão de memória do host**: o `RLIMIT_AS` é por processo. O aluno forka N processos, cada um alocando logo abaixo do limite (`N × 256 MB`), ou simplesmente submete Java, cujo script define `monitor_max_ms=0` (`java-script.sh`: `# FIXME: Overriding settings / monitor_max_ms=0`). Resultado: OOM killer do host, afetando outros containers e o próprio engine.
3. **Exaustão de CPU**: sem `cpu_quota`, cada submissão pode saturar todos os cores, degradando todas as correções concorrentes (o engine processa commits em paralelo).

**Correção proposta**:
```python
container = client.containers.run(
    language.image,
    detach=True,
    remove=False,
    volumes=volumes,
    network_mode="none",            # ver S2
    mem_limit=f"{language.mem_limit_mb}m",
    memswap_limit=f"{language.mem_limit_mb}m",   # swap = 0
    pids_limit=64,
    nano_cpus=1_000_000_000,        # 1 core
    cap_drop=["ALL"],
    security_opt=["no-new-privileges"],
    read_only=True,                 # rootfs read-only; ver S4 para o volume
    tmpfs={"/tmp": "size=64m"},
)
```
Limites por linguagem devem vir da configuração da linguagem no banco (Java/JVM precisa de mais memória de container, mas limitada — ex. 1 GB hard no cgroup, resolvendo o `FIXME` do `java-script.sh` sem abrir mão de limite).

**Critérios de aceite**: fork bomb submetida mata apenas o container (cgroup pids esgotado); alocação acima do limite gera OOM apenas no container; submissão com loop infinito não afeta latência de outras correções além da fração de CPU reservada.

---

### S2 — [CRÍTICA] Rede habilitada dentro do container de execução

**Local**: `container.py:170-176` (ausência de `network_mode="none"`).

O código do aluno roda com acesso de rede completo (bridge default do Docker). Isso permite:
1. **Exfiltração** de casos de teste (`.in` estão todos montados em `/root`, ver S9) para colegas via requisição HTTP.
2. **Ataque à rede interna**: o container enxerga o gateway da bridge e, dependendo da topologia de deploy, o banco PostgreSQL, S3/MinIO e o RabbitMQ do engine. Credenciais não estão no container, mas scanning e exploração de serviços internos ficam possíveis.
3. **Uso do serviço como botnet/proxy** (abuso de rede de saída, mineração com C2, etc.).
4. **Download de payloads** para burlar análise estática que o servidor eventualmente faça do fonte.

**Correção**: `network_mode="none"` na criação do container. Nenhuma funcionalidade legítima atual depende de rede em tempo de execução (compilação não baixa dependências; para linguagens que precisem — ex. futura imagem com gerenciador de pacotes — usar estágio de pré-busca fora do container de execução).

**Critérios de aceite**: dentro do container de execução, `ip addr` mostra apenas `lo`; qualquer `connect()` externo falha com `ENETUNREACH`.

---

### S3 — [CRÍTICA] Todo o pipeline roda como root dentro do container

**Local**: imagens (`compiler-images/*/Dockerfile` não definem `USER`), `base-script.sh` (PID 1 root), `monitor.c` (não faz `setuid`/`setgid` antes do `execvp`).

O programa do aluno herda **root** do monitor. Consequências dentro do container:
1. Sobrescrever `/usr/bin/monitor` ou `/usr/bin/runcodes` durante a fase de compilação (um `Makefile` é código arbitrário executado com `make all`), comprometendo todas as fases seguintes do mesmo commit, inclusive forjando resultados.
2. Matar/parar o PID 1 (`kill -STOP 1`), travando o protocolo de mensagens e consumindo o timeout do engine (DoS barato).
3. Manipular arquivos de outros testes no volume (ver S5 e S9).
4. Ampliação de superfície para escape de container: qualquer CVE de runtime (runc, kernel) quase sempre exige root no container como pré-condição.

**Correção proposta (duas camadas)**:
1. **No monitor** (defesa principal, independente da imagem): após o `fork()` e antes do `execvp()`, o filho faz:
   ```c
   if (setgid(SANDBOX_GID) != 0 || setgroups(0, NULL) != 0 || setuid(SANDBOX_UID) != 0)
       exit(255);
   prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
   ```
   com `SANDBOX_UID/GID` (ex. usuário `runner`, uid 1000) configuráveis por flag (`-u uid:gid`). O monitor continua root (ou com `CAP_SETUID` apenas) para poder rebaixar; os arquivos de I/O devem ser abertos **antes** do drop para que o aluno não precise de permissão nos diretórios de resultado (ou o diretório do teste recebe `chown` para o runner).
2. **Nas imagens**: criar usuário `runner` na imagem base; diretórios de trabalho com dono correto; o `base-script.sh` pode continuar root (orquestração), mas tudo que toca código do aluno (compilação inclusive — `make` executa código arbitrário) roda rebaixado via monitor.

**Critérios de aceite**: `id` executado por uma submissão imprime uid=1000; escrita em `/usr/bin` falha com `EACCES`; `kill -9 1` falha com `EPERM`.

---

### S4 — [ALTA] Exaustão de disco do host via volume `rw`

**Local**: `container.py:164-166` (`{remote_dir: {"bind": "/root", "mode": "rw"}}`) combinado com `RLIMIT_FSIZE` em `monitor.c:86-92`.

`RLIMIT_FSIZE` limita o tamanho de **cada arquivo** (5 MB default), não o total escrito. O volume é um diretório do host sem quota. Um programa que crie milhares de arquivos de 5 MB (ou um `Makefile` na compilação, que também roda sem limite de quantidade de arquivos) enche o disco do host, derrubando o engine, o Docker daemon e potencialmente o banco.

**Correção proposta** (em ordem de preferência):
1. Montar o workspace como volume com quota (`docker volume create --opt o=size=...` com driver que suporte, ou loopback ext4/xfs com project quota).
2. Alternativa mais simples: workspace em `tmpfs` com `size=` fixo e o engine copia os artefatos para fora após `run.done` (muda o fluxo de coleta de resultados).
3. Complementar no monitor: `RLIMIT_NOFILE` (ex. 64) reduz paralelismo de criação de arquivos, mas não substitui a quota.

**Critérios de aceite**: loop de criação de arquivos para com `ENOSPC` dentro do limite do workspace sem afetar `df` do host.

---

### S5 — [ALTA] Forja de resultados: escrita cruzada entre testes e symlink attack

**Local**: `base-script.sh` (`run_tests`), `monitor.c:106-116` (`freopen` com modo `"w"`).

Todos os testes do commit compartilham o mesmo container e o mesmo volume. O programa do aluno (hoje root; mesmo rebaixado, dono dos arquivos do seu teste) pode:
1. **Escrever diretamente** `../<outro_id>.output`, `.monitor_out` ou `.error` de testes que ainda vão rodar ou que já rodaram. O `freopen(..., "w")` do teste seguinte trunca o `.output`, mas `.monitor_out` é escrito pelo shell **após** o monitor terminar; um processo em background (ver S6) pode sobrescrevê-lo depois, forjando `signal=` vazio e `time=` baixo.
2. **Symlink attack**: criar `ln -s /usr/bin/monitor ../5.output` antes do teste 5; o `freopen("w")` do monitor (root) segue o symlink e trunca o binário alvo. Como tudo é root hoje, isso permite sobrescrever qualquer arquivo do container através do monitor.

**Correção proposta**:
1. No monitor, substituir `freopen` por `open()` explícito com `O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC` e `dup2`, falhando se o alvo for symlink (`O_NOFOLLOW` → `ELOOP`).
2. Isolar cada teste: diretório de resultados fora do alcance do processo do aluno (dono root, processo rebaixado via S3 não escreve nele; o monitor abre os FDs antes do drop de privilégio).
3. Idealmente, um workspace efêmero por teste (overlay ou cópia) descartado após a execução — elimina a classe inteira de interferência entre testes.

**Critérios de aceite**: symlink pré-criado no lugar do arquivo de saída faz o monitor abortar com erro reportado (status interno IE), não seguir o link; escrita de um teste nos artefatos de outro falha com `EACCES`.

---

### S6 — [ALTA] Processos persistentes entre fases e injeção no protocolo de log

**Local**: `monitor.c:140-171` (`trace_child` espera apenas até o filho direto sair), `base-script.sh` (nenhuma limpeza entre testes), `container.py:117-131` (`expect_message` confia em qualquer linha do log).

O monitor faz `waitpid` até o filho direto terminar, mas **não mata descendentes**. O `timeout(1)` também só sinaliza o processo que lançou. Um programa (ou `Makefile` na compilação) pode daemonizar (`fork` + `setsid`) e sobreviver a todas as fases:

1. **Adulteração retroativa**: o daemon reescreve `.output`/`.monitor_out` de testes já concluídos antes de o engine ler (o engine só lê após `run.done`).
2. **Injeção de protocolo**: como root (S3), o daemon abre `/proc/1/fd/1` (stdout do PID 1, que é o log do container) e escreve `compilation.done` ou `run.done`, dessincronizando a máquina de estados do engine (`expect_message` lança `RuntimeError` em linha inesperada — no mínimo um DoS do commit; na pior hipótese, pular fases).
3. **Consumo de recursos silencioso** durante os testes seguintes, distorcendo o `time` deles.

**Correção proposta**:
1. No monitor: criar process group próprio para o filho (`setpgid(0,0)` no filho) e, ao final (saída normal, sinal ou timeout interno — ver E2), `kill(-child_pgid, SIGKILL)` em loop até `waitpid` retornar `ECHILD`.
2. Complemento estrutural: `pids_limit` do cgroup (S1) limita a escala; um container por teste (E11) elimina a persistência; alternativa barata no `base-script.sh`: após cada fase, `pkill -9 -u runner` (exige S3).
3. No engine: tratar linha inesperada do log sem derrubar o processamento (log + ignorar linhas que não são do protocolo, aceitando apenas o conjunto fechado de mensagens, e marcando o commit com erro interno em caso de forja detectada).

**Critérios de aceite**: submissão que daemoniza um processo tem o daemon morto antes do teste seguinte iniciar (verificável por teste de integração que tenta escrever em arquivo sentinela); linhas arbitrárias no stdout do container não travam o engine.

---

### S7 — [ALTA] Fase de compilação é execução arbitrária com os mesmos privilégios

**Local**: `base-script.sh` (`compile()`), `c-script.sh` (suporte a `?akefile` → `make all`).

Submissões com `Makefile` executam `make all` — código arbitrário do aluno — dentro do monitor, mas com os mesmos problemas: root, rede, sem limite de processos. Tudo o que vale para a execução vale para a compilação, e a compilação roda **antes** de qualquer teste, sendo o ponto ideal para plantar os ataques S5/S6. Qualquer correção de S1-S6 precisa cobrir a fase de compilação igualmente (hoje ela já passa pelo monitor, o que facilita).

Adicionalmente, `compilation_timeout` default é 10 s no script, mas o limite de memória da compilação é o mesmo da execução — compiladores (GHC, rustc, javac) podem precisar de perfis distintos. Oportunidade: parâmetros `-f/-m` separados para compilação e execução no `container.config`.

---

### S8 — [MÉDIA] `eval`/`source` de configuração e expansão indireta no base-script

**Local**: `base-script.sh`: `source "${container_config_file}"`, `eval "${pre_run_command} ${test_id}"`, `var="t_${test_id}"; ${!var}`.

O `container.config` é gerado pelo engine a partir de dados do exercício (criados por professores — semi-confiáveis — e transportados pelo pipeline). `source` executa o arquivo como shell: qualquer injeção nesse arquivo (via campo de configuração do exercício mal sanitizado no server/engine) vira execução arbitrária como root no container. O mesmo vale para `pre/post_compilation_command` e `pre/post_run_command` passados a `eval`.

**Correção proposta**: trocar `source` por parser de `chave=valor` com allowlist de chaves e validação de formato (números para limites, caminho relativo simples para `src_file`); eliminar `eval` em favor de arrays bash ou de chamada direta; validar `test_id` com `[[ "$test_id" =~ ^[0-9]+$ ]]` antes da expansão indireta.

**Critérios de aceite**: `container.config` contendo `$(touch /pwned)` ou `; comando` em qualquer valor não executa nada além do parse falhar com erro explícito.

---

### S9 — [MÉDIA] Todos os casos de teste visíveis ao código do aluno

**Local**: `container.py:164` (volume inteiro em `/root`), `base-script.sh` (`.in` de todos os testes no diretório raiz do workspace).

O programa do teste 1 pode ler `../2.in`, `../3.in`, etc. Os gabaritos (`.out` esperados) não estão no container (são buscados do S3 pelo engine — bom), então o impacto é limitado a: inspecionar inputs futuros para hardcode de respostas em exercícios com saída derivável do input, e vazar inputs de testes fechados (que professores às vezes tratam como confidenciais).

**Correção**: montar/copiar para o diretório do teste apenas o `.in` do próprio teste no momento da execução (o `base-script` já faz `cd` por teste; basta mover o `.in` para dentro e dar permissão de leitura só ao teste corrente), ou isolar por teste (E11).

---

### S10 — [MÉDIA] Sem seccomp/caps: superfície de syscalls ampla

**Local**: ausência em `monitor.c` e em `container.py` (perfil default do Docker).

O perfil seccomp default do Docker bloqueia o pior (mount, reboot, module loading), mas o código do aluno ainda tem acesso a `ptrace` (pode se auto-depurar para evadir análise), `personality`, sockets unix abstratos, etc. Para um juiz online, a allowlist pode ser bem mais estreita.

**Correção proposta (incremental)**:
1. Curto prazo: `cap_drop=["ALL"]` + `no-new-privileges` no docker run (já em S1).
2. Médio prazo: perfil seccomp próprio por classe de linguagem (nativas vs. VM) aplicado via `security_opt=["seccomp=<perfil>.json"]`.
3. Longo prazo: aplicar filtro seccomp-BPF dentro do monitor (libseccomp) após o `fork`, permitindo granularidade por execução — ou adotar runtime de isolamento pronto (ver E5: nsjail/isolate/gVisor; o README do módulo já sugere firejail).

---

### S11 — [BAIXA] `execvp` resolve via PATH herdado e ambiente não sanitizado

**Local**: `monitor.c:134` (`execvp(args[0], args)`), `base-script.sh` (`-c "timeout ..."`).

O `timeout` é resolvido pelo `PATH` do ambiente do container. Como a compilação roda antes (S7) e como root (S3), um `Makefile` pode trocar `PATH` persistido? Não diretamente (ambiente não persiste entre processos), mas pode substituir o binário `timeout`/`gcc` no filesystem. Após S3/S5 resolvidos, o risco residual é baixo; ainda assim:

**Correção**: usar caminhos absolutos no comando montado pelo script (`/usr/bin/timeout`), `execve` com ambiente mínimo controlado (`PATH=/usr/bin:/bin`, `HOME`, locale) em vez de `execvp` com ambiente herdado.

---

## 3. Bugs de Corretude

### B1 — [CRÍTICA] Core dump mascara o sinal: crash é tratado como execução limpa

**Local**: `monitor.c:165-167`:

```c
if (WCOREDUMP(status)) {
} else
    stats->signal = WTERMSIG(status);
```

Quando o processo morre por sinal **com** core dump (SIGSEGV/SIGABRT com `RLIMIT_CORE > 0`, que não é zerado pelo monitor), o branch `WCOREDUMP` é vazio e `stats->signal` permanece `-1` → `signal_name(-1)` retorna `""` → o monitor imprime `signal=` vazio → `grading.py:53` considera que não houve sinal. Se o programa tiver escrito o output correto antes de crashar (ou output vazio que bata com gabarito vazio) e stderr estiver vazio, **um programa que segfaulta é aceito como correto**; no mínimo, o aluno não recebe a informação do sinal.

**Correção**:
```c
} else if (WIFSIGNALED(status)) {
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    stats->time_sec = elapsed_secs(&ts_start, &ts_end);
    stats->signal = WTERMSIG(status);   /* com ou sem core dump */
    break;
}
```
E, adicionalmente, `setrlimit(RLIMIT_CORE, {0,0})` no filho — core dumps não servem a nenhum propósito no sandbox e consomem disco (interage com S4).

**Critérios de aceite**: submissão C com `*(int*)0 = 1;` reporta `signal=SIGSEGV` de forma determinística, com e sem `ulimit -c` herdado.

---

### B2 — [ALTA] TLE invisível: o monitor observa o `timeout`, não o programa

**Local**: `base-script.sh` (`-c "timeout --signal=SIGKILL ${timeout} ${run_command}"`) + `monitor.c` + `grading.py`.

O filho do monitor é o `timeout(1)`. Quando o tempo estoura, `timeout` envia SIGKILL ao programa e **sai com exit status 137** (não é morto por sinal). O monitor então reporta `exit_status=137`, `signal=` vazio. Como o grading ignora `exit_status` e só olha `signal`/stderr, um TLE é indistinguível de "rodou e deu resposta errada" — o aluno vê "incorreto" sem saber que foi tempo. Também não existe `STATUS_TIMEOUT` em `TestCaseResult`.

Casos relacionados:
- Programa morto por SIGSEGV sob `timeout`: `timeout` propaga (re-envia o sinal a si mesmo), então `WIFSIGNALED` funciona — mas isso é acoplamento frágil ao comportamento do `timeout`.
- `exit_status` nunca usado pelo grading (`grading.py` lê apenas `time` e `signal`): exit code ≠ 0 com stdout correto conta como correto. Se isso é intencional, documentar; se não, é bug de política de correção.

**Correção proposta** (estrutural, ver também E2/E3): o monitor assume o timeout internamente (`-t <segundos>`): timer + `kill(-pgid, SIGKILL)` + flag `timeout=1` na saída. O script deixa de envolver com `timeout(1)`. O engine passa a receber um campo explícito e cria `STATUS_TIMEOUT` (e `STATUS_MEM_EXCEEDED`), exibindo ao aluno a causa real.

**Critérios de aceite**: `while(1);` reporta `timeout=1` e o resultado do teste aparece como "tempo excedido", não "incorreto"; o tempo reportado é ≈ o limite configurado.

---

### B3 — [ALTA] Buffer sem terminação NUL para comandos com ≥ 2000 caracteres

**Local**: `monitor.c:120-122`:

```c
char buf[COMMAND_MAX + 1];
strncpy(buf, params->command, COMMAND_MAX);
char **args = parse_args(buf);
```

`strncpy` não escreve o `\0` quando `strlen(src) >= n`. Para comando com 2000+ caracteres, `buf` fica sem terminador e `strtok` lê além do fim do buffer (CWE-170/CWE-125): comportamento indefinido, potencial crash do monitor ou parse de lixo da stack como argumentos. O comando vem do `container.config`/scripts (não diretamente do aluno), mas `run_command` inclui `src_file`, que **deriva do nome de arquivo submetido** — vetor parcialmente controlável.

**Correção**: `buf[COMMAND_MAX] = '\0';` após o `strncpy`, e truncamento deve ser erro explícito (comando truncado silenciosamente executa coisa diferente da pedida):
```c
if (strlen(params->command) > COMMAND_MAX) { fprintf(stderr, "monitor: command too long\n"); exit(255); }
```

---

### B4 — [MÉDIA] `parse_args`: `realloc` sem checagem e deref de NULL com comando vazio

**Local**: `monitor.c:66-81`.

1. `args = realloc(args, ...)` sem verificar retorno — em OOM, deref de NULL (e leak do bloco antigo).
2. Comando vazio ou só espaços: o loop não executa, `args` permanece `NULL` e `args[i] = NULL` (linha 78) é deref de ponteiro nulo → segfault do próprio monitor → `monitor_out` vazio → exceção no engine (ver B7).
3. `execvp(args[0], ...)` com `args[0] == NULL` é UB mesmo se (2) for corrigido parcialmente.

**Correção**: validar `params->command` não-vazio após o parse (`if (!args || !args[0]) exit(255)` com mensagem), checar `realloc` (padrão `tmp = realloc(...); if (!tmp) ...`), e pré-alocar por contagem de tokens para evitar realloc por token.

---

### B5 — [MÉDIA] Tempo medido é wall-clock e nenhuma métrica real de recursos é coletada

**Local**: `monitor.c:145-171`, `monitor.h:15-19`.

O contrato do módulo ("garantir que retorna a quantidade de recursos utilizados") não é cumprido: só há tempo de parede. Problemas:
1. Wall-clock inclui overhead de `fork`/`exec`/scheduling e I/O — injusto sob carga concorrente (correções paralelas disputam CPU e inflam o tempo do aluno).
2. Nenhuma medição de memória de pico, tempo de CPU (user/sys), page faults ou I/O.
3. Um processo pode `SIGSTOP` a si mesmo: queima wall-clock sem CPU (interage com B2 — o `timeout` wall-clock pega, mas a métrica reportada não reflete uso real).

**Correção** (ver E1): usar `wait4()` em vez de `waitpid()` e reportar `struct rusage`: `ru_maxrss` (KB de pico), `ru_utime`/`ru_stime`, `ru_minflt/majflt`, `ru_inblock/oublock`. Adicionar `RLIMIT_CPU` como limite de tempo de CPU (gera SIGXCPU/SIGKILL) complementar ao timeout wall-clock. O schema de saída ganha campos novos (ver E10 para versionamento do contrato).

---

### B6 — [MÉDIA] Engine quebra sem tratamento quando `monitor_out` está vazio ou ausente

**Local**: `grading.py:49-53`.

`open(run_info_fname)` sem tratamento → `FileNotFoundError` se o monitor nunca rodou (ex. falha no `cd` do script); `run_info["info"]["signal"]` → `KeyError` se o arquivo está vazio (ex. monitor segfaultou, B4). A exceção sobe por `process_test_results_batch` e aborta o processamento do commit inteiro, possivelmente deixando-o em estado inconsistente na fila.

**Correção**: try/except granular por teste convertendo em `TestCaseResult` com status de erro interno (novo `STATUS_JUDGE_ERROR`), logando e seguindo para os demais testes; alarme/metrica para ocorrências (indicam bug no sandbox, não no aluno).

---

### B7 — [MÉDIA] Parsing de limites aceita lixo e negativos

**Local**: `main.c:56-63`.

`sscanf("%lu")` aceita `"10abc"` (lê 10, ignora resto) e `"-1"` (wrap para `ULONG_MAX`, ou seja, `-f -1` vira limite gigante = sem limite, silenciosamente). Para um componente de segurança, falha de validação de limite deve ser fatal e ruidosa.

**Correção**: `strtoul` com `errno`, checagem de `endptr` consumindo a string toda, rejeição de `'-'` inicial e de zero quando zero significa "sem limite" apenas se explícito/documentado.

---

### B8 — [MÉDIA] `-static` como opção de compilação não produz binário estático

**Local**: `CMakeLists.txt:5` (`ADD_COMPILE_OPTIONS(-Wall -O2 -static)`).

`ADD_COMPILE_OPTIONS` aplica flags só na compilação; `-static` é flag de **link**. O binário sai dinâmico. Funciona hoje porque builder e imagem base são ambos `debian:trixie-slim` (mesma glibc), mas quebra silenciosamente se as bases divergirem (o binário é copiado via `COPY --from=ghcr.io/...compiler-monitor:latest` para a imagem base de todas as linguagens).

**Correção**:
```cmake
add_link_options(-static)
```
ou `target_link_options(monitor PRIVATE -static)`; validar com `file monitor | grep "statically linked"` no CI (o `src/Makefile` manual já linka estático corretamente — divergência entre os dois builds também é um problema: eliminar um deles, preferindo CMake).

---

### B9 — [BAIXA] Sem suporte a quoting no comando

**Local**: `monitor.c:66-81` (`strtok` em espaço/tab).

`-c 'prog "arg com espaco"'` vira três argumentos. Hoje os scripts não precisam, mas `src_file` com espaço no nome quebra a execução de forma confusa. Documentar a limitação no curto prazo; no redesign, aceitar `--` e argumentos posicionais (`monitor [opts] -- prog arg1 arg2`), eliminando o parse manual e a classe inteira de problemas (inclusive B3/B4).

---

### B10 — [BAIXA] Itens de higiene no código C

- `monitor.c:54`: comparação signed/unsigned (`signal >= sizeof(...)/sizeof(char*)`) — cast ou usar `(int)` no limite.
- `signal_list` deveria ser `static const char *const[]`.
- `main.c:104`: retorno de `run_monitor` ignorado — fork falho imprime `exit_status=-1, signal=, time=-1.0` como se fosse resultado válido (o engine aceita! signal vazio); deve sair com código ≠ 0 e mensagem em stderr.
- `elapsed_secs` com `float`: ~7 dígitos significativos; usar `double`.
- `trace_child` recebe `child_pid`/`params` e não usa (resquício de design com ptrace?); `waitpid(-1, ...)` genérico quando só há um filho — após E2/S6 (process groups), revisitar.
- Mensagens de erro do filho pós-`freopen` vão para o `err_fname` do aluno (ex. `monitor: exec failed` aparece no `.error` do teste e conta como stderr não-vazio → INCORRECT, mascarando erro de infra como erro do aluno). Erros do monitor devem ir para canal próprio (fd 3 ou arquivo separado) ou ocorrer antes do redirecionamento quando possível.

---

## 4. Evoluções Propostas

### E1 — Coleta real de recursos (`wait4` + `rusage`)

Substituir `waitpid` por `wait4(pid, &status, __WALL, &usage)` e expandir `MonitorStats`:

```c
typedef struct {
    int exit_status;
    int signal;
    int timed_out;        /* 1 se morto pelo timeout interno (E2) */
    int mem_exceeded;     /* 1 se SIGSEGV/ENOMEM sob RLIMIT_AS ou cgroup OOM */
    double wall_sec;
    double cpu_user_sec;  /* ru_utime */
    double cpu_sys_sec;   /* ru_stime */
    long   max_rss_kb;    /* ru_maxrss */
    long   major_faults;  /* ru_majflt */
    long   fs_reads;      /* ru_inblock */
    long   fs_writes;     /* ru_oublock */
} MonitorStats;
```

Saída correspondente (mantendo compatibilidade, ver E10). O engine passa a gravar e exibir memória de pico e CPU — hoje o banco só recebe `time` e `signal` (`TestCaseResult`). Benefício pedagógico direto (aluno vê consumo) e operacional (detecção de MLE, ranking por eficiência, limites por exercício em CPU-time em vez de wall).

### E2 — Timeout e controle de processo nativos no monitor

Remover a dependência do `timeout(1)` externo:
1. Filho: `setpgid(0, 0)` antes do exec (novo process group).
2. Pai: `timer_create`/`alarm` ou `waitpid` com `WNOHANG` + `clock_gettime` em loop com `sigtimedwait(SIGCHLD)`; ao estourar `-t`: `kill(-pgid, SIGKILL)`, marcar `timed_out=1`, continuar o reap até `ECHILD` (resolve S6 junto).
3. `RLIMIT_CPU` = teto de CPU (SIGXCPU → SIGKILL) como segunda linha, protegendo contra o caso SIGSTOP (B5).

Flags novas: `-t <wall_sec>` e `-T <cpu_sec>`.

### E3 — Status semânticos de resultado

Hoje o veredito é inferido por heurística (`signal` vazio + stderr vazio). Formalizar enum no contrato monitor→engine e no `TestCaseResult`:

| Código | Significado | Fonte |
|---|---|---|
| `OK` | terminou normalmente | `WIFEXITED` |
| `TLE` | tempo excedido | timeout interno (E2) |
| `MLE` | memória excedida | cgroup OOM / RLIMIT_AS (heurística: SIGSEGV + maxrss ≈ limite, ou `memory.events` do cgroup) |
| `OLE` | output excedido | SIGXFSZ |
| `RE` | morto por sinal | `WIFSIGNALED` |
| `NZEC` | exit code ≠ 0 | `WEXITSTATUS` (política a definir com o produto) |
| `IE` | erro interno do monitor | falhas de setup (B4, B6, B10) |

O engine mapeia para novos `TestCaseResult.STATUS_*` e o server exibe a causa ao aluno. Isso corrige de vez a ambiguidade de B1/B2 e melhora a experiência pedagógica (a diferença entre "errado" e "estourou o tempo" muda o que o aluno estuda).

### E4 — Limites via cgroups v2 por execução

`RLIMIT_AS` é por processo e inadequado para VMs/JITs (o `FIXME` do Java existe por isso). Com cgroup v2 delegado ao container, o monitor (ou o base-script) pode criar um sub-cgroup por teste:
- `memory.max` = limite real de RAM do conjunto de processos (resolve multiprocessos e Java);
- `pids.max` = anti-forkbomb por teste;
- `cpu.max` = fatia de CPU;
- `memory.peak` (kernel ≥ 5.19) = métrica de pico fiel para E1;
- `memory.events` (`oom_kill`) = detecção MLE determinística para E3.

Design: monitor cria `/sys/fs/cgroup/test_<id>/`, escreve limites, `echo $child_pid > cgroup.procs`, lê métricas após o término, remove o cgroup. Requer `cgroupns` adequado no docker run. Esta é a evolução de maior valor técnico do módulo.

### E5 — Decisão estratégica: endurecer o monitor vs. adotar sandbox pronto

O README já aponta firejail. Avaliar formalmente (ADR) três rotas:

| Rota | Prós | Contras |
|---|---|---|
| **Endurecer monitor próprio** (E1-E4 + seccomp via libseccomp + namespaces via `clone(CLONE_NEWPID\|NEWNET\|NEWNS...)`) | controle total, binário único, didático para o projeto | custo de manutenção e de auditoria de segurança contínuos |
| **Adotar [isolate](https://github.com/ioi/isolate)** (usado no IOI/CMS) ou **nsjail** | battle-tested exatamente para juízes online; cgroups+namespaces+rlimits prontos; métricas inclusas | dependência externa; integração com o protocolo atual |
| **Runtime isolado no Docker** (gVisor/runsc ou Kata) | isolamento forte sem mudar o monitor | overhead por submissão; infra de deploy mais complexa |

Recomendação: **isolate/nsjail como motor de contenção, mantendo o monitor como adaptador fino do protocolo atual** (parse de saída do isolate → `monitor_out`), preservando o contrato com o engine. Caminho incremental com P0/P1 aplicados antes, pois a migração é mais longa.

### E6 — Limites distintos para stdout/stderr (anti-spam de output)

`RLIMIT_FSIZE` é global ao processo. Um programa que escreva 5 MB de stderr cheio de lixo infla storage e banco (o `compiled_error`/outputs sobem para S3). Alternativa: o monitor trunca ativamente (`copy loop` com pipe em vez de redirecionamento direto, cortando em N KB) ou pós-processamento no script (`head -c`). Com pipe, ganha-se também timestamping e detecção de OLE precisa (E3).

### E7 — Testes e CI

O módulo de **segurança** do sistema não tem um único teste. Proposta:
1. **Unit (C)**: harness com CMocka/Unity para `parse_args` (B3/B4/B9), `signal_name`, validação de flags (B7). Build de teste no CMake (`enable_testing()`).
2. **Integração (shell/Python)**: suíte que compila o monitor e executa binários-fixture: loop infinito (espera TLE), alocador guloso (MLE), segfault com core (B1), fork bomb (com cgroup), escritor de arquivo gigante (OLE), programa correto (OK). Asserções sobre o `monitor_out` gerado.
3. **Sanitizers**: job de CI compilando com `-fsanitize=address,undefined` e rodando a suíte.
4. **Fuzzing leve**: afl++/libFuzzer sobre o parser de argumentos e de comando.
5. **Análise estática**: `clang-tidy` + `cppcheck` no workflow (hoje `docker-build.yml` só constrói a imagem).
6. **Verificação do artefato**: asserção de binário estático (B8) e smoke test do container (`docker run ... monitor -c 'echo ok'`).

### E8 — Hardening de build

`CFLAGS` atuais: `-Wall -O2 -static`. Adicionar: `-Wextra -Werror`, `-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, `-fPIE -pie` + `-Wl,-z,relro,-z,now` (quando dinâmico) — ou manter estático com musl (builder `alpine`) para portabilidade total entre imagens (resolve B8 por construção e reduz o tamanho).

### E9 — Observabilidade

- Logs do monitor em stderr próprio com prefixo e exit codes documentados (hoje `exit(255)` para três causas distintas: limites, streams, exec — diferenciá-los: 252/253/254/255).
- Métricas no engine: contagem de IE, TLE, MLE, OOM-kills do cgroup, duração por fase; alarme para taxa anômala de IE (indica regressão no sandbox).
- `monitor --version` imprimindo versão/commit para rastrear qual binário está em cada imagem (hoje a tag é sempre `:latest` — fixar por digest/versão nas imagens de linguagem também é oportunidade de supply chain).

### E10 — Contrato formal monitor ↔ engine (schema versionado)

O formato `chave=valor` atual é parseado com truque do configparser (`it.chain(("[info]",), ...)`). Formalizar:
1. Documento de contrato no repo (`docs/output-format.md`) com todas as chaves, tipos e semântica.
2. Campo `version=2` na primeira linha; engine aceita v1 (atual) e v2 durante a transição.
3. Chaves novas de E1/E2/E3: `status=`, `timeout=`, `cpu_user=`, `cpu_sys=`, `max_rss_kb=`, etc.
4. Parser dedicado no engine com validação e defaults explícitos (substitui o configparser e resolve B6).
5. Golden tests dos dois lados (fixture compartilhada).

### E11 — Isolamento por caso de teste

Hoje: 1 container por commit, todos os testes compartilham filesystem e podem se influenciar (S5/S6/S9). Evoluções possíveis, em custo crescente:
1. **Cleanup entre testes**: matar órfãos + diretório de resultados inacessível ao runner (barato, cobre a maior parte).
2. **Workspace efêmero por teste**: overlay/cópia descartada (médio).
3. **Container por teste**: isolamento máximo, custo de startup por teste (~100-300 ms cada; viável com reuso de imagem e pool pré-aquecido; combina com E5/gVisor).

Decisão sugerida: (1) imediatamente, (2) junto do redesign E4/E5.

---

## 5. Priorização e Roadmap Sugerido

### Fase P0 — Correções críticas (dias; sem mudança de contrato)

| Item | Ação | Risco de regressão |
|---|---|---|
| S1 | limites de cgroup no `containers.run` (mem, pids, cpu) | baixo (ajustar valores por linguagem) |
| S2 | `network_mode="none"` | baixo |
| B1 | corrigir branch `WCOREDUMP` + `RLIMIT_CORE=0` | nenhum |
| B3 | terminação NUL / rejeição de comando longo | nenhum |
| B4 | validação de comando vazio e `realloc` | nenhum |
| B6 | tratamento de `monitor_out` ausente/vazio no engine | nenhum |
| B8 | link estático de verdade + asserção no CI | nenhum |

### Fase P1 — Fraude e abuso (semanas; pequenas mudanças de contrato)

S3 (drop de privilégio, `-u uid:gid`), S5 (`O_NOFOLLOW`, FDs antes do drop), S6 (process group + kill no reap; tolerância a linhas estranhas no engine), S4 (quota de workspace), S8 (eliminar `source`/`eval`), B2+E2+E3 (timeout interno, `status=`/`timeout=` no output, novos status no engine/server), B7, B10.

### Fase P2 — Redesign do sandbox (1-2 ciclos)

E1 (rusage), E4 (cgroups v2 por teste — resolve o `FIXME` do Java), E10 (contrato v2), E7 (suíte de testes completa), E5 (ADR: isolate/nsjail vs. monitor endurecido), E11, S9, S10, E6, E8, E9.

### Dependências entre itens

- E3 depende de E2 (timeout interno) e de mudança coordenada em `grading.py`/`TestCaseResult`/server (exibição).
- S3 precisa preceder a parte "FDs antes do drop" de S5.
- E4 depende de ajuste no `containers.run` (cgroupns) — fazer junto de S1.
- E10 deve ser especificado antes de E1/E2/E3 serem mesclados, para evitar duas migrações de formato.

---

## 6. Apêndice: Inventário de Arquivos e Pontos Citados

| Referência | Arquivo | Linhas |
|---|---|---|
| Parse e exec do comando | `compiler-monitor/src/monitor.c` | 66-138 |
| Loop de wait / WCOREDUMP | `compiler-monitor/src/monitor.c` | 140-171 |
| Limites (FSIZE/AS) | `compiler-monitor/src/monitor.c` | 83-104 |
| CLI e validação de flags | `compiler-monitor/src/main.c` | 34-76 |
| Impressão do resultado | `compiler-monitor/src/main.c` | 103-111 |
| Flag `-static` incorreta | `compiler-monitor/CMakeLists.txt` | 5 |
| Build Docker (2 estágios) | `compiler-monitor/Dockerfile` | 1-23 |
| Invocação do monitor (compilação/testes) | `compiler-images/base/base-script.sh` | funcs `compile`/`run_tests` |
| `source`/`eval` de config | `compiler-images/base/base-script.sh` | topo e funcs |
| Java sem limite de memória | `compiler-images/java/java-script.sh` | `monitor_max_ms=0` |
| `docker run` sem contenção | `compiler-engine/src/rcc/engine/container.py` | 163-176 |
| Protocolo de mensagens de log | `compiler-engine/src/rcc/engine/container.py` | 117-131, 201-271 |
| Parse do `monitor_out` e veredito | `compiler-engine/src/rcc/engine/grading.py` | 39-73 |
