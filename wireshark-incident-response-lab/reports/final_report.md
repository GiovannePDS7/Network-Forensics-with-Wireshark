# 📊 Relatório Executivo Consolidado do Laboratório

**Projeto:** Network Forensics with Wireshark  
**Autor:** Giovanne Santos (Analyst / Blue Team)  
**Data de Conclusão:** 2026-09-12  
**Status do Laboratório:** 100% Concluído (Fases 01 a 06)  

---

## 1. Visão Geral do Projeto

Este relatório executivo consolida as atividades, metodologias, análises e conclusões desenvolvidas ao longo de todas as fases do **Wireshark Incident Response Lab**. O objetivo principal foi construir uma peça prática de portfólio para demonstrar competência em **Forense de Rede**, **Análise de Tráfego de Protocolos** e **Resposta a Incidentes**, aplicando metodologias reconhecidas pelo mercado como **MITRE ATT&CK** e o ciclo de resposta a incidentes do **NIST**.

---

## 2. Síntese dos Achados por Fase

```text
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │                                 FLUXO DO LABORATÓRIO                             │
 └──────────────────────────────────────────────────────────────────────────────────┘
   Fase 01: Captura Real (Kali/WSL2) ──► Fase 02: Dissecação DNS
                                             │
   Fase 04: Dissecação TLS 1.3 ◄─────────────┴──► Fase 03: Dissecação TCP
         │
         ▼
   Fase 05: Investigação de Incidente (FormBook C2) ──► Fase 06: Síntese & MITRE ATT&CK
```

### 2.1 Fase 01 — Captura de Tráfego Real (`lab_capture.pcapng`)

- **Validação do Ambiente:** Implementação de captura multitier no Kali Linux rodando sobre WSL2.
- **Achado Principal:** Identificação de que o tráfego DNS para o gateway local (`10.255.255.254`) não passava pela interface primária (`eth0`), exigindo a captura global em modo `-i any` (*Linux cooked capture SLL*).

### 2.2 Fase 02 — Análise de Tráfego DNS

- **Métricas:** Resolução de nomes com tempo médio de resposta de **~12ms**.
- **Diagnóstico:** Diagnóstico de erros `NXDOMAIN` (rcode 3) decorrentes de erros de digitação e acionamento automático do mecanismo de sufixo de busca do sistema operacional (`.hitronhub.home`).
- **Relatório Completo:** 📄 **[Relatório de Análise DNS](dns_analysis.md)**

### 2.3 Fase 03 — Análise de Tráfego TCP

- **Controle de Fluxo:** Avaliação do *3-Way Handshake*, tamanhos de janela (*Window Scaling* até 8192) e tamanho máximo de segmento (`MSS` de 1220 a 1400 bytes).
- **Diagnóstico de Retransmissão:** Identificação de um único `Duplicate ACK` isolado no pacote 35, decorrente de jitter na interface virtualizada, sem impacto em retransmissões rápidas.
- **Relatório Completo:** 📄 **[Relatório de Análise TCP](tcp_analysis.md)**

### 2.4 Fase 04 — Análise de Tráfego TLS

- **Negociação TLS 1.3:** Dissecação dos quadros *Client Hello* e *Server Hello* estabelecidos com `example.com`.
- **Inovação em Segurança (PQC):** Identificação da extensão `key_share` utilizando a suíte de troca de chaves pós-quântica **X25519MLKEM768** (combinação de curva elíptica X25519 com ML-KEM-768 / Kyber-768), garantindo proteção contra ataques de interceptação retroativa (*Harvest Now, Decrypt Later*).
- **Relatório Completo:** 📄 **[Relatório de Análise TLS](tls_analysis.md)**

### 2.5 Fase 05 — Investigação de Incidente (Malware FormBook)

- **Cenário de Infecção:** Investigação do tráfego malicioso do infostealer **FormBook** (*Cenário First to Last*).
- **Identificação de Alvo (100% de Precisão):**
  - IP: `172.16.8.49`
  - MAC: `00:12:f0:28:d4:34`
  - Hostname: `DESKTOP-5NLV63K`
  - Conta de Usuário: `rvance`
  - Nome Completo: `Raymond Vance` (descoberto via pacote **SAMR QueryUserInfo** no Active Directory).
- **Mapeamento de C2:** Extração de **15 domínios e IPs de C2** ativos com padrão de beaconing cíclico de ~8 minutos.
- **Relatório Completo:** 📄 **[Relatório do Incidente FormBook](incident_report.md)**

---

## 3. Matriz Consolidada de Habilidades e Competências Demonstradas

| Categoria | Competência Técnica Demonstrada |
| :--- | :--- |
| **Análise de Tráfego** | Extração avançada de campos via CLI (`tshark`) e GUI (`Wireshark`). |
| **Protocolos de Rede** | Profundo conhecimento de DNS (A/AAAA/NXDOMAIN), TCP (Flow Control/Handshake) e TLS 1.3. |
| **Forense em Active Directory** | Mapeamento de usuários e máquinas via vazamento de metadados em Kerberos, NBNS e SAMR (RPC). |
| **Malware Traffic Analysis** | Identificação de assinaturas de C2, User-Agents falsos, beaconing e exfiltração em query strings. |
| **Frameworks de Segurança** | Mapeamento de TTPs no **MITRE ATT&CK** e recomendações de resposta no **NIST CSF**. |

---

## 4. Conclusão Executiva

O laboratório atingiu com êxito todos os objetivos propostos. Foi demonstrado que a visibilidade e a análise profunda do tráfego de rede permitem não apenas compreender a saúde e os parâmetros das comunicações legítimas, mas também identificar com precisão infecções complexas por malware, rastrear os ativos e usuários afetados e fundamentar ações imediatas de contenção para equipes de SOC / Blue Team.

---

### 📂 Navegação pelos Relatórios Individuais

- 📄 **[Relatório de Análise DNS](dns_analysis.md)**
- 📄 **[Relatório de Análise TCP](tcp_analysis.md)**
- 📄 **[Relatório de Análise TLS](tls_analysis.md)**
- 📄 **[Relatório do Incidente FormBook](incident_report.md)**
- 📄 **[Lições Aprendidas & MITRE ATT&CK](../lessons_learned.md)**
