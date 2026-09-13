# 🟣 Relatório Técnico de Análise de Tráfego TCP

**Autor:** Analyst / Blue Team  
**Data da Análise:** 2026-09-12  
**Arquivo de Origem:** `lab_capture.pcapng`  
**Ferramentas Utilizadas:** `tshark`, `wireshark`  

---

## 1. Sumário Executivo

Este relatório detalha a análise do protocolo **TCP (Transmission Control Protocol)** realizada na Fase 03 do laboratório. Foram examinadas as etapas do ciclo de vida das conexões TCP: o estabelecimento (*3-Way Handshake*), os parâmetros de controle de fluxo negociados, a análise isolada de conversas (*Streams*), o diagnóstico de retransmissões e o encerramento ordenado da sessão.

---

## 2. Metodologia e Filtros Utilizados

### 2.1 Mapeamento de Conexões (Pacotes de Controle SYN/FIN)

```bash
tshark -r lab_capture.pcapng -Y "tcp.flags.syn==1 || tcp.flags.fin==1"
```

### 2.2 Listagem de Streams Únicos

```bash
tshark -r lab_capture.pcapng -T fields -e tcp.stream -Y tcp | sort -u
```

### 2.3 Detecção de Anomalias e Retransmissões

```bash
tshark -r lab_capture.pcapng -Y "tcp.analysis.retransmission || tcp.analysis.duplicate_ack || tcp.analysis.zero_window"
```

### 2.4 Medição do RTT (Round Trip Time) do Handshake

```bash
tshark -r lab_capture.pcapng -Y "tcp.flags.syn==1 && tcp.flags.ack==1" -T fields -e tcp.analysis.ack_rtt
```

---

## 3. Análise Detalhada dos Streams TCP

### 3.1 Stream 0 — DNS sobre TCP (`10.255.255.254:53`)

Filtro: `tshark -r lab_capture.pcapng -Y "tcp.stream==0"`

- **Abertura (3-Way Handshake):** Quadros 13-15 (`SYN` -> `SYN-ACK` -> `ACK`). Parâmetros: `MSS=1220`, `Window Scale=128`, `SACK_PERM`.
- **Troca de Dados:** Quadros 16-19: Consulta DNS para `cloudflare.com` trafegando encapsulada sobre TCP em vez de UDP.
- **Encerramento Gracioso:** Quadros 20-22: `[FIN, ACK]` enviado pelo cliente -> `[FIN, ACK]` retornado pelo servidor -> `[ACK]` final.

### 3.2 Stream 1 — HTTPS / TLS (`104.20.23.154:443`)

Filtro: `tshark -r lab_capture.pcapng -Y "tcp.stream==1"`

- **Abertura TCP:** Quadros 31-33: `[SYN]` -> `[SYN, ACK]` -> `[ACK]`. Parâmetros: `MSS=1400`, `Window Scale=8192`, `SACK_PERM`.
- **Sessão TLS / Aplicação:** Quadros 34-50: Handshake TLS 1.3 e transferência de dados da aplicação (`example.com`).
- **Encerramento Gracioso:** Quadros 51-54: `[FIN, ACK]` (cliente) -> `[ACK]` (servidor) -> `[FIN, ACK]` (servidor) -> `[ACK]` (cliente).

---

## 4. Tabela Comparativa de Parâmetros de Stream

| Parâmetro | Stream 0 (DNS/TCP) | Stream 1 (HTTPS/TLS) |
| :--- | :---: | :---: |
| **Porta Destino** | 53 | 443 |
| **MSS (Maximum Segment Size)** | 1220 bytes | 1400 bytes |
| **Window Scaling Factor** | 128 | 8192 |
| **Total de Pacotes na Conversa** | 10 pacotes | 24 pacotes |
| **Suporte a SACK** | Sim (`SACK_PERM`) | Sim (`SACK_PERM`) |
| **Segurança** | Texto claro | Criptografado (TLS 1.3) |

---

## 5. Diagnóstico de Anomalias e Confiabilidade

### 5.1 Análise do Duplicate ACK (Pacote 35)

- **Ocorrência:** No pacote 35 do Stream 1, o tshark sinalizou a flag `[TCP Dup ACK 34#1]`.
- **Diagnóstico Técnico:** O servidor reenviou uma confirmação (ACK) duplicada referente ao pacote 34. Em ambientes virtualizados (como o adaptador vEthernet do WSL2 com NAT no Windows), pequenas oscilações de tempo (*jitter*) na pilha de rede do sistema operacional podem causar o envio de um ACK duplicado isolado.
- **Impacto:** Nulo. Como **não ocorreram 3 ACKs duplicados consecutivos**, o algoritmo de Retransmissão Rápida (*Fast Retransmit*) não foi acionado, e a transmissão continuou sem degradação de desempenho.

---

## 6. Relevância Forense e Threat Hunting

1. **Detecção de Port Scanning:** Múltiplos pacotes `SYN` sem a conclusão do 3-way handshake (`SYN-ACK` seguido de `RST` ou ausência de resposta) indicam escaneamento de portas do tipo **SYN Stealth Scan** (`nmap -sS`).
2. **Conexões Abertas Sem Dados (Keep-Alive / Beaconing):** Conexões TCP mantidas abertas por longos períodos enviando pacotes mínimos de ACK podem indicar canais de C2 (*Command and Control*) mantendo persistência.
3. **Anomalias na Janela TCP (Zero Window):** Pacotes anunciando `TCP Zero Window` indicam esgotamento de recursos no host destino, sinalizando potencial ataque de **Negação de Serviço (DoS)** na camada de transporte ou estresse severo de memória.

---

## 7. Conclusão

As conexões TCP analisadas demonstraram comportamento perfeitamente aderente às especificações RFC. Os parâmetros de controle de fluxo garantiram ótima utilização da banda, e o único evento de ACK duplicado foi devidamente diagnosticado como ruído inofensivo da camada de virtualização do WSL2.
