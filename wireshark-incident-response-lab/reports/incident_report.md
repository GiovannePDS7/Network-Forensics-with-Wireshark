# 🔴 Relatório Técnico de Investigação de Incidente: Malware FormBook

**Caso / Cenário:** "First to Last" (malware-traffic-analysis.net)  
**Classificação:** Incidente Confirmado — Infecção por Infostealer (FormBook)  
**Analisado por:** SOC Analyst / Blue Team  
**Data da Análise:** 2026-09-12  
**Arquivo PCAP:** `2026-08-09-traffic-analysis-exercise.pcap`  

---

## 1. Sumário Executivo

Durante o monitoramento de segurança do SOC, múltiplos alertas de comunicação com servidores de **Command and Control (C2)** associados à família de malware **FormBook** foram disparados. A análise forense do tráfego de rede capturado confirmou o comprometimento do host Windows da rede interna.

Esta investigação identificou com precisão de 100% o host comprometido, seu endereço físico (MAC), o nome de máquina no Active Directory, a conta de usuário logada e o nome completo do colaborador associado. Além disso, foram mapeados 15 domínios/IPs de C2 ativamente contactados pela ameaça.

---

## 2. Visão Geral da Infraestrutura Alvo

```text
Rede Local (LAN): 172.16.8.0/24
Domínio Active Directory: firsttolast.tech
Domain Controller (DC): 172.16.8.2 (FIRSTTOLAST-DC)
Gateway Padrão: 172.16.8.1
```

---

## 3. Respostas Oficiais do Incidente (Tabela de Evidências)

| Pergunta da Investigação | Evidência Identificada | Protocolo de Origem | Método / Comando de Extração |
| :--- | :--- | :--- | :--- |
| **IP do Host Infectado** | `172.16.8.49` | HTTP | `tshark -Y "http.request" -T fields -e ip.src` |
| **Endereço MAC** | `00:12:f0:28:d4:34` | Ethernet (L2) | `tshark -Y "ip.src==172.16.8.49" -T fields -e eth.src` |
| **Hostname do Host** | `DESKTOP-5NLV63K` | Kerberos | `kerberos.CNameString` (`DESKTOP-5NLV63K$`) |
| **Nome de Usuário** | `rvance` | Kerberos | `kerberos.CNameString` (`rvance@FIRSTTOLAST.TECH`) |
| **Nome Completo** | `Raymond Vance` | SAMR (RPC) | **SAMR QueryUserInfo** (Quadro 2947 / `samr.Full Name`) |

---

## 4. Análise Técnica Aprofundada

### 4.1 Identificação do Host e Usuário via Protocolos Microsoft (Kerberos e SAMR)

A identificação do dispositivo e do usuário foi realizada sem a necessidade de telemetria de endpoint, aproveitando o vazamento legítimo de metadados dos protocolos do Active Directory:

1. **Identificação do Hostname:** O filtro Kerberos revelou a requisição de ticket da conta de computador `DESKTOP-5NLV63K$`. O sufixo `$` confirma tratar-se do objeto de computador cadastrado no domínio.
2. **Identificação do Usuário:** Requisições Kerberos subsequentes autenticaram a conta de usuário `rvance`.
3. **Identificação do Nome Completo via SAMR:** Ao inspecionar as chamadas de procedimento remoto (RPC), localizou-se o par de mensagens **SAMR QueryUserInfo** nos quadros 2946 (requisição) e 2947 (resposta). A resposta retornou os atributos da conta do Active Directory:
   - `Account Name: rvance`
   - `Full Name: Raymond Vance`

### 4.2 Indicadores de Comprometimento (IOCs) e Comportamento do FormBook

#### A. User-Agent Falso e Inconsistente

Todas as requisições HTTP maliciosas utilizaram uma string de User-Agent fixa e hardcoded:

```http
User-Agent: Mozilla/5.0 (Windows NT 6.2; rv:39.0) Gecko/20100101 Firefox/39.0
```

- **Inconsistência:** O identificador `Windows NT 6.2` refere-se ao Windows 8, incompatível com a versão moderna do Windows presente na máquina.
- **Anacronismo:** O Firefox 39 foi lançado em 2015, configurando uma assinatura clássica de comunicação do FormBook.

#### B. Padrão de Beaconing e Domain Cycling

O malware implementa um mecanismo resiliente de **Domain Cycling**:

- Percorre uma lista circular de **15 domínios de C2**.
- Realiza de 7 a 8 requisições HTTP GET consecutivas por domínio em intervalos de **~2.6 segundos**.
- Cada volta completa na lista de 15 domínios leva **~8 minutos** (23:13:23 → 23:21:07 UTC), reiniciando automaticamente o ciclo.
- Cada domínio possui um URI de caminho fixo de 4 caracteres (ex: `/ujvq/`, `/irpw/`).
- As requisições finais de cada ciclo contêm parâmetros de exfiltração: `?2kn1=<blob_codificado>&kbBSJ=Ep6t_fJ_`.

#### C. Lista Completa de Domínios e IPs de C2 (IOCs)

| Domínio de C2 | Endereço IP Destino | URI Utilizada |
| :--- | :--- | :--- |
| `www.independent.ie` | `172.64.155.76` | `/ujvq/` |
| `www.grinswakebthu.info` | `146.59.71.167` | `/irpw/` |
| `www.taibeinan.cc` | `38.182.168.246` | `/path/` |
| `www.legenda-sochi.com` | `45.130.41.161` | `/path/` |
| `www.titanium303.com` | `172.67.162.153` | `/path/` |
| `www.21207628.shop` | `121.54.163.148` | `/path/` |
| `www.kentmediallc.com` | `199.192.27.50` | `/path/` |
| `www.earthframe.site` | `66.29.149.91` | `/path/` |
| `www.p3x63q.garden` | `183.90.186.205` | `/path/` |
| `www.z61gqw.beer` | `156.247.51.39` | `/path/` |
| `www.www-bet456.co` | `172.67.219.130` | `/path/` |
| `www.moxom.online` | `81.2.196.19` | `/path/` |
| `www.thvwzs.com` | `104.21.76.210` | `/path/` |
| `www.devinnovationhab.team` | `104.21.42.23` | `/path/` |
| `www.amlgames.site` | `89.110.89.25` | `/path/` |

---

## 5. Cronologia do Ataque (Timeline)

```text
23:08:13 UTC — Host 172.16.8.49 conecta à rede (teste de conectividade NCSI da Microsoft).
23:08:27 UTC — Autenticação Kerberos/SAMR observada no DC (sessão do usuário Raymond Vance).
23:12:47 UTC — Consultas legítimas de atualização (ctldl.windowsupdate.com).
23:13:23 UTC — 🚩 PRIMEIRO BEACON MALICIOSO (www.independent.ie) — Início do tráfego C2 visível.
23:13:23 → 23:21:07 UTC — Execução contínua do ciclo de beaconing pelos 15 domínios de C2 (~8 min/ciclo).
23:20:19 UTC — Reinício do ciclo de C2 (reaparecimento de www.independent.ie).
```

> 💡 **Nota Forense sobre o Vetor de Entrada:**
>
> A autenticação do usuário (23:08) ocorreu **~5 minutos antes** do primeiro beacon de C2 (23:13). Isso indica que a máquina já se encontrava infectada antes da captura de rede iniciar. Sem logs de endpoint (EDR/Sysmon), o vetor inicial de infecção (ex: phishing com anexo malicioso ou download via navegador) não pode ser visualizado apenas no tráfego de rede.

---

## 6. Mapeamento no MITRE ATT&CK

| Tática | Técnica | ID MITRE | Evidência Observada |
| :--- | :--- | :--- | :--- |
| **Command and Control** | Application Layer Protocol: Web Protocols | `T1071.001` | Tráfego C2 via HTTP GET não criptografado na porta 80 |
| **Command and Control** | Fallback Channels | `T1008` | Lista redundante de 15 domínios alternativos de C2 |
| **Defense Evasion** | Masquerading | `T1036` | Uso de User-Agent falso (Firefox 39 / Windows 8) |
| **Exfiltration** | Exfiltration Over C2 Channel | `T1041` | Dados roubados transmitidos no parâmetro `2kn1=` |
| **Command and Control** | Data Encoding | `T1132` | Payloads codificados em Base64 anexados na URL |
| **Credential Access** | Credentials from Password Stores | `T1555` | Comportamento típico do FormBook (Infostealer) |

---

## 7. Recomendações de Contenção e Mitigação (SOC Playbook)

### 7.1 Ações Imediatas de Contenção

1. **Isolamento de Rede:** Desconectar o host `172.16.8.49` (`DESKTOP-5NLV63K` / MAC `00:12:f0:28:d4:34`) da rede local imediatamente para interromper a exfiltração de dados.
2. **Revogação de Credenciais:** Resetar a senha do usuário `rvance` (`Raymond Vance`) e invalidar todas as suas sessões e tickets Kerberos ativos no Active Directory.
3. **Bloqueio de IOCs no Firewall/Web Proxy:** Adicionar os 15 domínios e IPs listados na Seção 4.2.C às listas de bloqueio (*Deny List*) do perímetro.

### 7.2 Ações de Erradicação e Recuperação

1. **Remediação do Endpoint:** Realizar a formatação e reinstalação limpa do host `DESKTOP-5NLV63K` a partir de uma imagem confiável.
2. **Análise de Escopo:** Verificar em servidores de e-mail e proxy se outros usuários receberam ou acessaram os mesmos vetores de entrega do malware no mesmo período.

### 7.3 Melhorias Defensivas Estruturais

1. **Implementação de EDR (Endpoint Detection and Response):** Acompanhar a execução de processos e criação de arquivos na máquina para bloquear executáveis maliciosos antes do estabelecimento de tráfego de rede.
2. **Regras de Detecção por Mismatch de User-Agent:** Criar alertas no SIEM para identificar requisições HTTP cujo User-Agent divirja da versão real do sistema operacional da empresa.
3. **Filtro de Domínios Recém-Registrados (NRDs):** Configurar o DNS corporativo para bloquear por padrão a resolução de domínios registrados há menos de 30 dias.
