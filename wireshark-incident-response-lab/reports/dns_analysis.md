# 🔵 Relatório Técnico de Análise de Tráfego DNS

**Autor:** Analyst / Blue Team  
**Data da Análise:** 2026-09-12  
**Arquivo de Origem:** `lab_capture.pcapng`  
**Ferramentas Utilizadas:** `tshark`, `wireshark`  

---

## 1. Sumário Executivo

Este relatório apresenta os achados técnicos obtidos durante a análise do protocolo **DNS (Domain Name System)** capturado na Fase 02 do laboratório. A análise cobriu a validação de resolução de nomes legítimos, avaliação de tempos de resposta, identificação de comportamentos dual-stack (IPv4/IPv6) e diagnóstico de falhas de resolução (`NXDOMAIN`).

---

## 2. Metodologia e Filtros Utilizados

Para isolar e extrair métricas do tráfego DNS no `tshark`, foram aplicados os seguintes filtros de exibição e comandos de extração tabular:

### 2.1 Isolamento de Pacotes DNS

```bash
tshark -r lab_capture.pcapng -Y "dns"
```

### 2.2 Extração Tabular de Campos Relevantes

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

### 2.3 Medição de Latência de Resolução

```bash
tshark -r lab_capture.pcapng -Y "dns" -T fields -e frame.number -e dns.time
```

---

## 3. Análise Detalhada dos Registros DNS

| Quadro | Tempo (s) | Origem | Destino | Tipo | Nome Consultado | Resposta (IPs) | Status (rcode) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **11** | 0.000 | `10.255.255.254` | `10.255.255.254` | Query A | `google.com` | — | - |
| **12** | 0.012 | `10.255.255.254` | `10.255.255.254` | Resp A | `google.com` | `172.217.28.174` | 0 (NOERROR) |
| **16** | 0.045 | `10.255.255.254` | `10.255.255.254` | Query A | `cloudflare.com` | — | - |
| **18** | 0.058 | `10.255.255.254` | `10.255.255.254` | Resp A | `cloudflare.com` | `104.16.133.229`, `104.16.132.229` | 0 (NOERROR) |
| **23** | 0.102 | `10.255.255.254` | `10.255.255.254` | Query A | `example.com80` | — | - |
| **24** | 0.115 | `10.255.255.254` | `10.255.255.254` | Resp A | `example.com80` | — | **3 (NXDOMAIN)** |
| **25** | 0.116 | `10.255.255.254` | `10.255.255.254` | Query A | `example.com80.hitronhub.home` | — | - |
| **26** | 0.128 | `10.255.255.254` | `10.255.255.254` | Resp A | `example.com80.hitronhub.home` | — | **3 (NXDOMAIN)** |
| **27** | 0.150 | `10.255.255.254` | `10.255.255.254` | Query AAAA | `example.com` | — | - |
| **28** | 0.151 | `10.255.255.254` | `10.255.255.254` | Query A | `example.com` | — | - |
| **29** | 0.162 | `10.255.255.254` | `10.255.255.254` | Resp AAAA | `example.com` | `2606:4700:10::ac42:93f3` | 0 (NOERROR) |
| **30** | 0.163 | `10.255.255.254` | `10.255.255.254` | Resp A | `example.com` | `104.20.23.154` | 0 (NOERROR) |

---

## 4. Principais Achados Técnicos

### 4.1 Diagnóstico da Anomalia NXDOMAIN e DNS Search Suffix

Filtro utilizado:

```bash
tshark -r lab_capture.pcapng -Y "dns.flags.rcode == 3"
```

- **Causa Raiz:** Ocorreu um erro de digitação durante a execução do comando `nc` / `dig` (`example.com80` em vez de `example.com 80`).
- **Comportamento do SO (Search Suffix):**
  1. O resolvedor tentou resolver primeiramente `example.com80`, recebendo **NXDOMAIN** (pacote 24).
  2. Em seguida, o mecanismo de sufixo de busca local do sistema operacional anexou o domínio local da rede (`hitronhub.home`), resultando na consulta `example.com80.hitronhub.home` (pacote 25), que também falhou com **NXDOMAIN** (pacote 26).

### 4.2 Comportamento Dual-Stack (A vs AAAA)

- **Consultas Simultâneas (Happy Eyeballs):** Para o domínio `example.com`, o sistema enviou requisições do tipo **A** (IPv4) e **AAAA** (IPv6) quase simultaneamente (quadros 27 e 28).
- **Decisão do Cliente:** Apesar de ambos os registros terem sido resolvidos com sucesso (`104.20.23.154` e `2606:4700:10::ac42:93f3`), o sistema operacional preferiu estabelecer a conexão TCP subsequente sobre IPv4.

---

## 5. Relevância Forense e Threat Hunting

1. **Monitoramento de NXDOMAIN:** Surtos de erros NXDOMAIN em curtos intervalos de tempo são indicadores fortes de:
   - Presença de malware utilizando **DGA (Domain Generation Algorithms)** para contactar infraestrutura de C2.
   - Ferramentas de escaneamento de subdomínios ou recon ativo na rede.
2. **Consultas AAAA para Evasão:** Malware moderno pode utilizar túneis IPv6 ou canais de C2 sobre IPv6 para evadir controles de segurança legados focados apenas em IPv4.
3. **Análise de Latência (`dns.time`):** Tempos de resposta extremamente curtos (< 1ms) sugerem respostas vindas do cache local ou autoritativo local, enquanto latências mais altas indicam resolução recursiva externa.

---

## 6. Conclusão

O tráfego DNS analisado apresentou um comportamento majoritariamente saudável, com tempo médio de resolução de **~12ms** a **~13ms**. As respostas com código `rcode 3` (NXDOMAIN) foram conclusivamente associadas a erros de digitação do operador durante a simulação de tráfego, descartando atividade maliciosa nesta captura.
