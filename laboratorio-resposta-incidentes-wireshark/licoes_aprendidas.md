# 💡 Síntese Técnica e Lições Aprendidas (Lessons Learned)

**Projeto:** Network Forensics with Wireshark  
**Autor:** Giovanne Santos (Analyst / Blue Team)  
**Data:** 2026-09-12  

---

## 1. Introdução

Este documento reúne as principais lições aprendidas, descobertas técnicas inesperadas, particularidades de ambiente e conhecimentos práticos adquiridos durante a execução das 6 fases do **Wireshark Incident Response Lab**. O objetivo é servir como uma referência técnica rápida para futuras investigações forenses e análises de tráfego de rede.

---

## 2. Lições Aprendidas por Camada e Protocolo

### 2.1 Captura de Rede e Virtualização (WSL2 / Kali Linux)

- 💡 **A Pegadinha do `-i eth0` no WSL2:** Durante a Fase 01, tentar capturar pacotes apenas na interface `eth0` não registrava o tráfego DNS local para o gateway (`10.255.255.254`). Isso ocorreu porque a arquitetura de rede virtualizada do WSL2 roteia requisições locais por uma interface virtual de loopback/vEthernet interna separada.
- 🔧 **Solução / Boa Prática:** Em ambientes virtualizados ou conteinerizados, sempre iniciar capturas diagnósticas utilizando a opção **`-i any`** (ou escutar em todas as interfaces) para evitar pontos cegos.
- 📦 **Encapsulamento SLL:** Capturas realizadas com `-i any` no Linux geram quadros no formato *Linux cooked capture v1 (SLL)* em vez de Ethernet puro. O tshark e o Wireshark tratam isso nativamente sem perda de dados das camadas superiores (IP, TCP, UDP).

### 2.2 Resolução de Nomes e Diagnóstico de Erros (DNS)

- 🔍 **Mecanismo de Sufixo de Busca (Search Suffix):** Quando ocorre um erro de digitação (ex: `example.com80`), o sistema operacional não apenas falha na primeira tentativa, mas realiza automaticamente requisições adicionais anexando o sufixo de busca local da rede (`example.com80.hitronhub.home`).
- 🚩 **Sinais de Threat Hunting em DNS:** Surtos de respostas `NXDOMAIN` (rcode 3) seguidos de sufixos locais são um excelente indicador para identificar erros humanos vs. algoritmos de geração de domínios (**DGA**) utilizados por botnets e malwares.
- ⚖️ **Mecanismo Happy Eyeballs (Dual-Stack):** Clientes modernos realizam consultas `A` (IPv4) e `AAAA` (IPv6) de forma paralela. Embora o resolvedor retorne ambos os endereços, a pilha de rede decide qual protocolo utilizar com base em métricas de latência e conectividade local.

### 2.3 Dinâmica e Confiabilidade de Transporte (TCP)

- ⏱️ **Medição do Handshake (RTT):** O intervalo entre o envio do pacote `SYN-ACK` pelo servidor e o recebimento do `ACK` do cliente fornece a medição de latência mais precisa do caminho de rede (*Round Trip Time*).
- 🔄 **Entendendo Duplicate ACKs Solitários:** A presença de um único pacote `[TCP Dup ACK]` isolado (como visto no pacote 35 da captura) não indica perda de dados severa ou ataque, mas sim pequenas variações de tempo (*jitter*) no processamento de pacotes pelo hipervisor. O algoritmo de **Retransmissão Rápida (Fast Retransmit)** exige pelo menos **3 ACKs duplicados consecutivos** para ser acionado.

### 2.4 Criptografia Moderna e Pós-Quântica (TLS 1.3)

- 🚀 **Eficiência do TLS 1.3:** O handshake TLS 1.3 é concluído em apenas **1-RTT** (uma ida e volta de pacotes), em comparação aos 2-RTTs exigidos pelo TLS 1.2.
- 🛡️ **Pioneirismo em Criptografia Pós-Quântica (PQC):** A identificação da suíte de troca de chaves **X25519MLKEM768** no tráfego real para a Cloudflare demonstrou a adoção prática do algoritmo **ML-KEM-768 (Kyber-768)** padronizado pelo NIST. Isso evidencia a urgência em monitorar o aumento do tamanho de payloads em handshakes TLS devido a vetores quânticos (1120 bytes no ML-KEM vs ~32 bytes no X25519 tradicional).

### 2.5 Resposta a Incidentes e Metadados do Active Directory (FormBook C2)

- 📇 **O "Vazamento" de Metadados Legítimos:** Não é necessário ter acesso a ferramentas de EDR no endpoint para identificar um usuário e computador infectados. Protocolos de infraestrutura como **Kerberos** e **SAMR (RPC)** revelam:
  - `DESKTOP-5NLV63K$` → Nome do Computador no AD.
  - `rvance@FIRSTTOLAST.TECH` → Nome de Usuário logado.
  - `Raymond Vance` → Nome Completo do Usuário (retornado no pacote **SAMR QueryUserInfo**).
- 🎭 **Anomalia de User-Agent:** O malware FormBook utilizou um User-Agent fixo e antigo (`Firefox 39 / Windows 8`). O cruzamento de dados de rede com o inventário real de ativos permite identificar instantaneamente clientes falsificados.
- 🔄 **Domain Cycling:** A resiliência do C2 baseia-se em ciclar por múltiplos domínios (15 domínios no caso investigado). O bloqueio de apenas um domínio não interrompe o ataque; a contenção exige o bloqueio da lista completa ou o isolamento imediato do host.

---

## 3. Síntese do Mapeamento MITRE ATT&CK

| Tática | Técnica | ID MITRE | Aplicação Prática no Lab |
| :--- | :--- | :--- | :--- |
| **Command and Control** | Web Protocols | `T1071.001` | Análise de beaconing HTTP GET do FormBook |
| **Command and Control** | Fallback Channels | `T1008` | Identificação da lista circular de 15 domínios de C2 |
| **Defense Evasion** | Masquerading | `T1036` | Detecção de User-Agent falsificado de browser antigo |
| **Exfiltration** | Exfiltration Over C2 Channel | `T1041` | Extração de dados via parâmetros codificados na URL |
| **Command and Control** | Data Encoding | `T1132` | Identificação de parâmetros codificados em Base64 |

---

## 4. Recomendações Defensivas para o SOC

1. **Monitoramento Integrado Endpoint + Rede:** Integrar alertas de tráfego de rede (SIEM/Zeek) com dados do EDR para associar requisições maliciosas ao processo executável exato.
2. **Regras de Detecção de User-Agent Incompatível:** Implementar alertas de SIEM para monitorar requisições HTTP onde a versão do sistema operacional declarada no User-Agent divirja do sistema operacional real da estação.
3. **Filtro DNS de Domínios Recém-Registrados (NRDs):** Bloquear temporariamente resoluções para domínios criados há menos de 30 dias para neutralizar infraestruturas descartáveis de C2.
4. **Inspeção de Anomalias em Consultas SAMR/RPC:** Monitorar consultas em massa via SAMR no Active Directory vindas de estações de trabalho comuns.

---

## 5. Conclusão

A realização deste laboratório permitiu consolidar a prática da análise de pacotes com `tshark` e `Wireshark`, integrando conhecimentos teóricos de protocolos de rede com o fluxo de trabalho real de resposta a incidentes. As lições aprendidas reforçam a importância de uma postura investigativa rigorosa e orientada por dados de evidência.
