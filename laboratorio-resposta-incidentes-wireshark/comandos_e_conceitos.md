# 📘 Guia Técnico de Comandos e Conceitos Teóricos do Laboratório

**Projeto:** Forense de Rede com Wireshark  
**Autor:** Giovanne Santos (Analyst / Blue Team)  
**Data:** 2026-09-13  

---

## 📖 Apresentação

Este documento foi criado especificamente para **desmistificar a complexidade dos comandos executados na linha de comando (`tshark`, `dig`, `curl`, `nc`, etc.)** e **aprofundar os conceitos teóricos de redes, criptografia e resposta a incidentes** que foram aplicados de forma prática ao longo das 6 fases do laboratório.

---

## 🛠️ PARTE 1 — Guia Técnico de Comandos Executados

Nesta seção, cada comando utilizado no laboratório é desmembrado flag por flag, explicando exatamente o que faz, por que foi escolhido e como interpretar seu resultado.

---

### 1. Captura e Geração de Tráfego

#### 1.1 Iniciar Captura Global no `tshark`

```bash
tshark -i any -w lab_capture.pcapng
```

- **`tshark`**: Versão em linha de comando (CLI) do Wireshark. Permite capturar e analisar pacotes diretamente do terminal.
- **`-i any`**: Define a interface de rede para captura. O valor `any` instrui o kernel do Linux a capturar pacotes de **todas as interfaces ativas simultaneamente**.
  - 💡 *Por que usarmos `-i any` e não `-i eth0`?* No WSL2 (Windows Subsystem for Linux), o tráfego DNS direcionado para o gateway (`10.255.255.254`) passa por um comutador virtual/loopback interno em vez da interface primária `eth0`. Capturar apenas na `eth0` deixaria o tráfego DNS invisível.
- **`-w lab_capture.pcapng`**: Salva os pacotes capturados diretamente no arquivo especificado em formato PCAPNG (*Pcap Next Generation*).

#### 1.2 Resolução de Nomes com `dig`

```bash
dig google.com
dig +tcp cloudflare.com
```

- **`dig`** (*Domain Information Groper*): Ferramenta CLI para realizar consultas DNS.
- **`dig google.com`**: Envia uma consulta DNS padrão para o registro tipo **A** (IPv4) sobre o transporte **UDP (porta 53)**.
- **`dig +tcp cloudflare.com`**: A flag `+tcp` força o `dig` a enviar a consulta DNS sobre o protocolo **TCP (porta 53)** em vez de UDP. Utilizado no laboratório para demonstrar o handshake TCP de 3 vias aplicando-se ao serviço DNS.

#### 1.3 Teste de Conectividade TCP com `netcat` (`nc`)

```bash
nc -v example.com 80
```

- **`nc`** (*Netcat*): Conhecido como o "canivete suíço do TCP/IP", permite ler e escrever dados em conexões de rede usando TCP ou UDP.
- **`-v`** (*verbose*): Exibe detalhes sobre o status do estabelecimento da conexão no terminal.
- **`example.com 80`**: Abre um socket TCP contra o domínio `example.com` na porta `80` (HTTP). Na prática, esse comando força a realização do handshake TCP de 3 vias (SYN, SYN-ACK, ACK).

#### 1.4 Requisição HTTP/HTTPS com `curl`

```bash
curl -v https://example.com
```

- **`curl`**: Cliente de linha de comando para transferência de dados usando diversos protocolos (HTTP, HTTPS, FTP, etc.).
- **`-v`** (*verbose*): Exibe todo o processo de negociação abaixo da aplicação, incluindo resolução de IP, conexão TCP, handshake TLS e cabeçalhos HTTP enviados/recebidos.
- **`https://example.com`**: Dispara a negociação criptografada **TLS 1.3** na porta `443`.

#### 1.5 Leitura e Contagem de Pacotes no `tshark`

```bash
tshark -r lab_capture.pcapng | wc -l
```

- **`-r lab_capture.pcapng`** (*read*): Lê e processa o arquivo PCAP indicado sem abrir a interface gráfica.
- **`|`** (*pipe*): Redireciona a saída do `tshark` para a entrada do próximo comando.
- **`wc -l`** (*word count - lines*): Conta quantas linhas de pacotes foram impressas, permitindo validar rapidamente o volume de tráfego capturado.

---

### 2. Análise de DNS no `tshark`

#### 2.1 Filtrando Tráfego DNS com Display Filter

```bash
tshark -r lab_capture.pcapng -Y "dns"
```

- **`-Y "dns"`** (*display filter*): Aplica um filtro de exibição **após** a leitura do arquivo PCAP, mostrando apenas os quadros que contêm o protocolo DNS.
  - ⚠️ *Diferença crucial entre `-Y` e `-f`:* O `-f` é um *capture filter* (usado durante a captura ao vivo no formato BPF), enquanto `-Y` é um *display filter* (usado na análise do Wireshark/tshark pós-captura).

#### 2.2 Extração Tabular de Campos Específicos

```bash
tshark -r lab_capture.pcapng -Y "dns" -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e dns.flags.response \
  -e dns.qry.name \
  -e dns.qry.type \
  -e dns.a \
  -e dns.aaaa \
  -e dns.flags.rcode
```

- **`-T fields`**: Altera o formato de saída do `tshark` para exibir apenas os campos especificados pelos parâmetros `-e`, separados por tabulação (formato limpo para tabelas/relatórios).
- **`-e <nome_do_campo>`**: Seleciona exatamente o campo da árvore do protocolo que se deseja extrair:
  - `frame.number`: Número sequencial do pacote no PCAP.
  - `frame.time_relative`: Tempo decorrido em segundos desde o primeiro pacote capturado.
  - `ip.src` / `ip.dst`: Endereço IP de origem e destino.
  - `dns.flags.response`: `0` indica uma Query (pergunta) e `1` indica uma Response (resposta).
  - `dns.qry.name`: O nome de domínio consultado (ex: `google.com`).
  - `dns.qry.type`: O tipo de registro consultado (`1` = Registro A/IPv4, `28` = Registro AAAA/IPv6).
  - `dns.a` / `dns.aaaa`: O endereço IP retornado na seção de resposta.
  - `dns.flags.rcode`: O código de retorno da resposta (`0` = NOERROR/Sucesso, `3` = NXDOMAIN/Não encontrado).

#### 2.3 Medição de Latência de Resolução DNS

```bash
tshark -r lab_capture.pcapng -Y "dns" -T fields -e frame.number -e dns.time
```

- **`-e dns.time`**: Campo calculado pelo Wireshark que mede o intervalo exato (em segundos) entre a consulta enviada pelo cliente e a resposta recebida do servidor DNS.

#### 2.4 Isolamento de Respostas com Erro (`NXDOMAIN`)

```bash
tshark -r lab_capture.pcapng -Y "dns.flags.rcode == 3"
```

- **`dns.flags.rcode == 3`**: Filtra exclusivamente pacotes de resposta DNS onde o servidor retornou a condição `NXDOMAIN` (*Non-Existent Domain*).

---

### 3. Análise de TCP no `tshark`

#### 3.1 Mapeamento de Pacotes de Controle (Handshake e Encerramento)

```bash
tshark -r lab_capture.pcapng -Y "tcp.flags.syn==1 || tcp.flags.fin==1"
```

- **`tcp.flags.syn==1`**: Identifica pacotes com a flag **SYN** ativada (utilizados para iniciar conexões TCP).
- **`tcp.flags.fin==1`**: Identifica pacotes com a flag **FIN** ativada (utilizados para encerrar conexões graciosamente).
- **`||`** (*OR lógico*): Exibe pacotes que atendam a qualquer uma das duas condições.

#### 3.2 Listagem de Streams TCP Únicos

```bash
tshark -r lab_capture.pcapng -T fields -e tcp.stream -Y tcp | sort -u
```

- **`-e tcp.stream`**: O Wireshark atribui um índice numérico único (`0`, `1`, `2`...) para cada conversa TCP individual (par IP Origem + Porta Origem ↔ IP Destino + Porta Destino).
- **`sort -u`** (*sort unique*): Ordena os números e remove duplicatas, resultando em uma lista dos IDs de todas as conversas TCP capturadas.

#### 3.3 Isolamento e Acompanhamento de um Stream Específico

```bash
tshark -r lab_capture.pcapng -Y "tcp.stream==0"
```

- **`tcp.stream==0`**: Mostra em ordem cronológica **todos os pacotes de uma única conversa TCP** (Stream 0), permitindo acompanhar do `SYN` inicial até o `FIN` final sem interferência de outros pacotes da rede.

#### 3.4 Motor de Análise de Anomalias do Wireshark

```bash
tshark -r lab_capture.pcapng -Y "tcp.analysis.retransmission || tcp.analysis.duplicate_ack || tcp.analysis.zero_window"
```

- **`tcp.analysis.retransmission`**: Filtra pacotes retransmitidos por perda na rede.
- **`tcp.analysis.duplicate_ack`**: Filtra confirmações (ACKs) duplicadas enviadas quando um pacote chega fora de ordem.
- **`tcp.analysis.zero_window`**: Filtra pacotes onde o receptor avisa que sua memória de recepção está cheia (janela zero).

---

### 4. Análise de TLS no `tshark`

#### 4.1 Isolando Mensagens do Handshake TLS

```bash
tshark -r lab_capture.pcapng -Y "tls.record.content_type==22"
```

- **`tls.record.content_type==22`**: Na especificação TLS, o tipo de registro `22` define mensagens de **Handshake** (Client Hello, Server Hello, Certificate, etc.). Utilizar este filtro de nível mais baixo garante compatibilidade caso o filtro genérico `tls.handshake` não funcione em determinadas versões da biblioteca decodificadora.

#### 4.2 Inspeção Verbosa de um Quadro Específico

```bash
tshark -r lab_capture.pcapng -Y "frame.number==34" -V
```

- **`-V`** (*verbose / full detail*): Imprime a árvore estruturada completa com todos os campos e subcampos decodificados do pacote de número 34 (Client Hello).

#### 4.3 Filtrando Seções do Output com `grep`

```bash
tshark -r lab_capture.pcapng -Y "frame.number==36" -V | grep -A 30 "Transport Layer Security"
```

- **`grep -A 30 "Transport Layer Security"`**: Procura pela expressão dentro do texto e imprime essa linha mais as **30 linhas seguintes (`-A 30` = After)**, isolando a camada TLS do restante do pacote.

---

### 5. Comandos da Investigação de Incidente (FormBook)

#### 5.1 Descompactando Evidências com Senha

```bash
unzip -P infected_20260809 2026-08-09-traffic-analysis-exercise.pcap.zip
```

- **`-P infected_20260809`**: Fornece a senha de descompactação do arquivo Zip diretamente pela linha de comando, sem abrir prompts interativos.

#### 5.2 Resumo de Conversações de Rede

```bash
tshark -r 2026-08-09-traffic-analysis-exercise.pcap -q -z conv,ip | head -30
```

- **`-q`** (*quiet*): Inibe a impressão padrão de pacote por pacote.
- **`-z conv,ip`**: Mapeia e gera uma tabela estatística agrupando todo o tráfego transferido entre pares de endereços IP (origem ↔ destino, total de pacotes e bytes).

#### 5.3 Mapeamento de Requisições HTTP Maliciosas

```bash
tshark -r 2026-08-09-traffic-analysis-exercise.pcap -Y "http.request" -T fields \
  -e frame.number -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri -e http.user_agent
```

- **`-Y "http.request"`**: Filtra apenas pacotes que contêm requisições HTTP de saída (GET, POST, etc.).
- **`-e http.host`**: Extrai o domínio de destino solicitado no cabeçalho `Host:`.
- **`-e http.request.uri`**: Extrai o caminho/URI da requisição (ex: `/ujvq/?2kn1=...`).
- **`-e http.user_agent`**: Extrai a string de identificação do navegador/aplicativo enviada no cabeçalho `User-Agent:`.

#### 5.4 Mapeamento de Ativos e Usuários do Active Directory

```bash
# Descobrir Hostname e Usuário via Kerberos
tshark -r 2026-08-09-traffic-analysis-exercise.pcap -Y "kerberos.CNameString && ip.addr==172.16.8.49" -T fields -e kerberos.CNameString | sort -u

# Descobrir Nome Completo do Usuário via SAMR (RPC)
tshark -r 2026-08-09-traffic-analysis-exercise.pcap -Y "frame.number==2947" -V | grep -i -B 2 -A 2 "name:"
```

- **`kerberos.CNameString`**: Nome da entidade solicitando autenticação Kerberos (`DESKTOP-5NLV63K$` para máquina, `rvance` para usuário).
- **`grep -i -B 2 -A 2 "name:"`**: Procura case-insensitive (`-i`) por `name:`, trazendo 2 linhas antes (`-B 2` = Before) e 2 linhas depois (`-A 2` = After) para capturar `Account Name` e `Full Name` do pacote SAMR.

---

## 📚 PARTE 2 — Guia Teórico de Conceitos Aplicados

Nesta seção, revisamos de forma didática e aprofundada os fundamentos teóricos que sustentaram cada análise no laboratório.

---

### 1. Redes & Virtualização

#### 1.1 Arquitetura de Rede Virtualizada no WSL2

O WSL2 (Windows Subsystem for Linux 2) não compartilha diretamente a placa de rede física com o Windows; ele roda dentro de uma máquina virtual leve sobre o Hyper-V.

- **vEthernet (Default Switch):** O Windows cria uma placa de rede virtual que conecta o Linux ao Host via NAT (Network Address Translation).
- **Roteamento Interno:** Requisições para serviços locais (como o resolvedor DNS em `10.255.255.254`) utilizam interfaces virtuais de loopback/ponte interna. Por esse motivo, capturar pacotes apenas na interface `eth0` resulta em omissão de tráfego, exigindo o uso da captura global `-i any`.

#### 1.2 Linux Cooked Capture (SLL)

Quando o `tshark` grava pacotes ouvindo em `any`, o kernel do Linux não pode utilizar o cabeçalho Ethernet II padrão (pois pacotes de interfaces diferentes possuem estruturas distintas). Ele encapsula os quadros no formato **SLL (Sock Line Level)**, substituindo o cabeçalho Ethernet por um cabeçalho fictício de 16 bytes que identifica o tipo de interface de origem.

---

### 2. Protocolo DNS (Domain Name System)

#### 2.1 Registros A vs AAAA (Dual-Stack)

- **Registro A:** Mapeia um nome de domínio para um endereço **IPv4** de 32 bits (ex: `104.20.23.154`).
- **Registro AAAA:** Mapeia um nome de domínio para um endereço **IPv6** de 128 bits (ex: `2606:4700:10::ac42:93f3`). O nome "quad-A" deriva do fato de um endereço IPv6 possuir 4 vezes os bits de um IPv4.

#### 2.2 Algoritmo Happy Eyeballs (RFC 8305)

Sistemas operacionais modernos que possuem suporte dual-stack (IPv4 e IPv6 ativados) disparam consultas DNS para registros A e AAAA **simultaneamente**. O sistema tenta conectar em ambos os endereços e escolhe o que responder mais rápido, oferecendo uma experiência transparente ao usuário caso uma das redes falhe.

#### 2.3 Mecanismo de Sufixo de Busca (Search Suffix / Search List)

Quando uma consulta DNS falha em resolver um nome simples ou mal digitado (como `example.com80`), o resolvedor local do sistema operacional presume que o nome possa ser um host interno da rede corporativa. Ele automaticamente anexa o sufixo de domínio da rede local (ex: `.hitronhub.home`) e reenvia a consulta (`example.com80.hitronhub.home`).

#### 2.4 Relevância Forense dos Códigos de Retorno (RCODE)

- `RCODE 0` (**NOERROR**): Consulta resolvida com sucesso.
- `RCODE 3` (**NXDOMAIN**): O servidor autoritativo confirma que o domínio consultado não existe.
  - 🚩 *Threat Hunting:* Rajadas frequentes de respostas `NXDOMAIN` a cada poucos segundos são forte indício de infecção por malware usando **DGA (Domain Generation Algorithms)** — uma técnica onde o malware gera milhares de nomes de domínio pseudo-aleatórios por dia tentando encontrar o servidor de C2 ativo.

---

### 3. Protocolo TCP (Transmission Control Protocol)

#### 3.1 Ciclo de Vida e Handshake de 3 Vias (3-Way Handshake)

O TCP é um protocolo orientado a conexão e confiável. Antes de qualquer dado ser transmitido, o cliente e o servidor sincronizam seus números de sequência:

```text
  Cliente                               Servidor
     │                                     │
     │────────────── SYN ─────────────────►│  (1. Solicita conexão)
     │                                     │
     │◄────────── SYN, ACK ───────────────│  (2. Confirma e solicita)
     │                                     │
     │────────────── ACK ─────────────────►│  (3. Confirma conexão estabelecida)
     │                                     │
```

#### 3.2 Parâmetros de Controle de Fluxo

No momento do handshake, ambos os lados negociam parâmetros cruciais para a eficiência e integridade da transferência:

- **MSS (Maximum Segment Size):** Define o maior tamanho de payload útil (sem cabeçalhos) que o host pode receber em um único segmento TCP.
- **Window Scale (WS):** Como o campo original da Janela TCP no cabeçalho possui apenas 16 bits (máximo de 65.535 bytes), o *Window Scale* atua como um multiplicador exponencial, permitindo janelas de recepção de megabytes em conexões de alta velocidade.
- **SACK (Selective Acknowledgment):** Permite que o receptor avise exatamente quais blocos de dados foram recebidos, evitando que o transmissor precise retransmitir segmentos que já chegaram corretamente.

#### 3.3 Diagnóstico de Confiabilidade: Duplicate ACKs

- Quando o receptor recebe um pacote fora de ordem, ele reenvia imediatamente uma confirmação duplicada (**Duplicate ACK**) informando qual o último byte sequencial correto recebido.
- **Regra da Retransmissão Rápida (Fast Retransmit):** Um único Duplicate ACK isolado ocorre por pequenos atrasos de rede (*jitter*) e é inofensivo. Somente quando **3 ACKs duplicados idênticos** chegam consecutivamente, o TCP conclui que o pacote foi realmente perdido e dispara a retransmissão imediata sem esperar pelo estouro de timer (*Timeout*).

---

### 4. Protocolo TLS 1.3 & Criptografia Moderna

#### 4.1 Handshake TLS 1.3 (1-RTT)

O TLS 1.3 reduziu o tempo de estabelecimento de conexão criptografada de 2 idas e voltas (2-RTT) para apenas **1-RTT**:

- **Client Hello:** O cliente envia as suítes de criptografia suportadas, a versão desejada, o nome do servidor de destino (SNI) e já inclui sua chave pública temporária (*key_share*).
- **Server Hello:** O servidor escolhe a suíte de criptografia, responde com sua chave pública (*key_share*) e a partir desse instante todo o restante da negociação (certificados e dados) já trafega criptografado.

#### 4.2 Criptografia Híbrida Pós-Quântica (PQC) — X25519MLKEM768

Identificada na análise da Fase 04 do laboratório, esta implementação combina dois algoritmos na extensão `key_share`:

1. **X25519:** Criptografia de curva elíptica tradicional que garante a segurança contra ataques clássicos de hoje.
2. **ML-KEM-768 (antigo Kyber-768):** Algoritmo de criptografia pós-quântica padronizado pelo NIST (**FIPS 203**), baseado em redes láticas (*lattice-based cryptography*), resistente a computadores quânticos operando o algoritmo de Shor.

- 🛡️ **Defesa Contra Ataques "Harvest Now, Decrypt Later":** Adoção estratégica preventiva para impedir que atores maliciosos capturem e armazenem tráfego criptografado hoje para descriptografá-lo no futuro quando computadores quânticos viáveis estiverem operacionais.

---

### 5. Resposta a Incidentes & Malware FormBook

#### 5.1 O Infostealer FormBook / XLoader

O FormBook é uma das famílias de malware do tipo **Infostealer** mais ativas do mundo. Seu objetivo principal é roubar credenciais salvas em navegadores, formulários web, clientes de e-mail e registrar digitações (*keylogger*).

#### 5.2 Estratégia de C2: Domain Cycling & Beaconing

Para garantir que a comunicação não seja interrompida caso um domínio de C2 seja derrubado, o FormBook embuti uma lista de múltiplos domínios (15 no caso analisado). O malware realiza um **ciclo de beaconing**:

- Envia de 7 a 8 requisições HTTP GET consecutivas para o primeiro domínio.
- Caso não receba os comandos esperados, avança para o próximo domínio da lista.
- Cada volta completa pelos 15 domínios leva ~8 minutos, reiniciando o ciclo continuamente.

#### 5.3 Masquerading & Evasão

- **User-Agent Falso (Spoofing):** O malware simula ser um navegador legítimo (`Firefox 39 / Windows 8`), mas utiliza uma versão antiga e incompatível com o sistema real do host, permitindo criar regras de detecção de anomalia no SIEM.
- **Exfiltração na Query String:** Dados roubados do host são codificados e anexados aos parâmetros da URL no próprio HTTP GET (ex: `?2kn1=<blob_codificado>`).

#### 5.4 Forense de Metadados no Active Directory (Kerberos e SAMR)

Sem depender de agentes de EDR no endpoint, o tráfego de rede de infraestrutura da rede Microsoft vaza identidades cruciais:

- **Kerberos:** Protocolo de autenticação do AD. A requisição de ticket expõe a conta do computador (`DESKTOP-5NLV63K$`) e a conta do usuário (`rvance`).
- **SAMR (Security Account Manager Remote Protocol):** Protocolo RPC usado para consultar o banco de contas do Active Directory. A chamada **QueryUserInfo** (pacote 2947) retorna o nome completo cadastrado no diretório (`Raymond Vance`).

---

### 6. Mapeamento no MITRE ATT&CK

| Tática | Técnica | ID MITRE | Aplicação Prática |
| :--- | :--- | :--- | :--- |
| **Command and Control** | Application Layer Protocol: Web Protocols | `T1071.001` | Comunicação C2 via HTTP GET não criptografado |
| **Command and Control** | Fallback Channels | `T1008` | Lista redundante de 15 domínios de C2 ciclando |
| **Defense Evasion** | Masquerading | `T1036` | User-Agent de navegador antigo disfarçando a ferramenta |
| **Exfiltration** | Exfiltration Over C2 Channel | `T1041` | Transmissão de dados roubados anexados aos parâmetros da URL |
| **Command and Control** | Data Encoding | `T1132` | Payloads codificados em Base64 na query string |
| **Credential Access** | Credentials from Password Stores | `T1555` | Ação do infostealer FormBook roubando dados locais |

---

## 🏁 Conclusão

Compreender **tanto a sintaxe exata dos comandos quanto a teoria por trás dos protocolos** é o que diferencia um operador de ferramentas de um **Analista Forense de Rede / SOC**. Este guia serve como ponte entre a execução prática do laboratório e o domínio conceitual exigido na rotina de investigações de segurança.
