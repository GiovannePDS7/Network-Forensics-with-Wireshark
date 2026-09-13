# 🦈 Network Forensics with Wireshark

Home lab de cibersegurança focado em forense de rede, análise de tráfego e investigação de incidentes usando **Wireshark** e **tshark** sobre protocolos reais de rede (DNS, TCP, TLS) e simulação de resposta a incidentes de malware.

O projeto simula o fluxo de trabalho de um analista de **SOC / Blue Team**: captura de tráfego, dissecação protocolo por protocolo, extração de IOCs e produção de relatórios técnicos de investigação.

---

## 📌 Visão Geral do Projeto

Este repositório contém todo o ambiente, capturas PCAP, evidências em screenshots e relatórios analíticos gerados durante as 6 fases do laboratório:

1. **[Fase 01 — Captura de Tráfego Real](wireshark-incident-response-lab/README.md#-fase-01--captura-de-tráfego-real):** Validação do ambiente Kali/WSL2, geração de tráfego real e captura inicial (`lab_capture.pcapng`).
2. **[Fase 02 — Análise de DNS](wireshark-incident-response-lab/reports/dns_analysis.md):** Dissecação de consultas/respostas DNS, comportamento dual-stack (A/AAAA), latência de resolução e diagnóstico de falhas (NXDOMAIN e DNS search suffixes).
3. **[Fase 03 — Análise de TCP](wireshark-incident-response-lab/reports/tcp_analysis.md):** Análise de handshakes 3-way, controle de fluxo (Window Scaling, MSS), análise de streams TCP e diagnóstico de retransmissões/Dup ACKs.
4. **[Fase 04 — Análise de TLS](wireshark-incident-response-lab/reports/tls_analysis.md):** Inspeção de handshakes TLS 1.3 (Client/Server Hello), análise de cipher suites e identificação de troca de chaves híbrida pós-quântica (**X25519MLKEM768**).
5. **[Fase 05 — Investigação de Incidente](wireshark-incident-response-lab/reports/incident_report.md):** Investigação do cenário real *"First to Last"* (malware FormBook), identificando o host e usuário comprometidos (`DESKTOP-5NLV63K` / `Raymond Vance`) via Kerberos/SAMR e extraindo 15 domínios de C2 e IOCs.
6. **[Fase 06 — Síntese e Lições Aprendidas](wireshark-incident-response-lab/lessons_learned.md):** Mapeamento no framework **MITRE ATT&CK** e recomendações defensivas para equipes de SOC.

---

## 💻 Ambiente Técnico & Topologia

- **Sistema Operacional:** Kali Linux rodando em WSL2 (Windows Host)
- **Ferramentas:** Wireshark, tshark, tcpdump, dig, curl, netcat, unzip
- **Topologia de Rede:** `Kali (WSL2) → Adaptador vEthernet → Windows (Host) → Roteador → Internet → Servidor Destino`

![Topologia do Laboratório](wireshark-incident-response-lab/architecture/topology.png)

---

## 📂 Estrutura do Repositório

```text
Network-Forensics-with-Wireshark/
├── README.md                                # Documentação principal
└── wireshark-incident-response-lab/
    ├── README.md                            # Guia completo do laboratório por fases
    ├── commands_and_concepts.md             # Guia técnico de comandos executados e fundamentos teóricos
    ├── lessons_learned.md                   # Síntese técnica, lições aprendidas e MITRE ATT&CK
    ├── architecture/
    │   └── topology.png                     # Diagrama de topologia da rede
    ├── pcaps/
    │   ├── lab_capture.pcapng               # Captura real gerada no Kali/WSL2 (Fases 1-4)
    │   └── incident/
    │       ├── 2026-08-09-traffic-analysis-exercise.pcap # PCAP de infecção do FormBook
    │       └── README.md                    # Instruções e detalhes do cenário de incidente
    ├── reports/                             # Relatórios técnicos detalhados
    │   ├── dns_analysis.md                  # Relatório de análise do protocolo DNS
    │   ├── tcp_analysis.md                  # Relatório de análise do protocolo TCP
    │   ├── tls_analysis.md                  # Relatório de análise do protocolo TLS
    │   ├── incident_report.md               # Relatório técnico de investigação do incidente
    │   └── final_report.md                  # Relatório executivo consolidado do projeto
    └── screenshots/                         # Capturas de tela organizadas por fase
        ├── phase1_general_capture/
        ├── phase2_dns/
        ├── phase3_tcp/
        ├── phase4_tls/
        └── phase5_incident/
```

---

## 📑 Relatórios & Guias Técnicos

- **[Guia Técnico de Comandos & Conceitos Teóricos](wireshark-incident-response-lab/commands_and_concepts.md)**
- **[Relatório de Análise DNS](wireshark-incident-response-lab/reports/dns_analysis.md)**
- **[Relatório de Análise TCP](wireshark-incident-response-lab/reports/tcp_analysis.md)**
- **[Relatório de Análise TLS](wireshark-incident-response-lab/reports/tls_analysis.md)**
- **[Relatório de Investigação de Incidente (FormBook)](wireshark-incident-response-lab/reports/incident_report.md)**
- **[Relatório Executivo Final](wireshark-incident-response-lab/reports/final_report.md)**
- **[Lições Aprendidas & MITRE ATT&CK](wireshark-incident-response-lab/lessons_learned.md)**

---

## 🎯 Autor & Propósito

Desenvolvido por **Giovanne Santos** como projeto prático de portfólio para demonstrar habilidades em **Network Forensics**, **Traffic Analysis** e **Incident Response** voltadas para atuação em equipes de **SOC / Blue Team**.
