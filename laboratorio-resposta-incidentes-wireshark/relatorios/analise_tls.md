# 🟠 Relatório Técnico de Análise de Tráfego TLS

**Autor:** Analyst / Blue Team  
**Data da Análise:** 2026-09-12  
**Arquivo de Origem:** `lab_capture.pcapng`  
**Ferramentas Utilizadas:** `tshark`, `wireshark`  

---

## 1. Sumário Executivo

Este relatório apresenta os resultados da investigação do protocolo **TLS (Transport Layer Security)** realizada na Fase 04 do laboratório. A análise focou na dissecação das mensagens do handshake **TLS 1.3**, validação das suítes de criptografia (*Cipher Suites*) negociadas e na descoberta de mecanismos modernos de **criptografia pós-quântica (PQC)** aplicados no tráfego real para `example.com`.

---

## 2. Metodologia e Filtros Utilizados

### 2.1 Isolamento de Mensagens de Handshake TLS

> 🔧 **Nota de Compatibilidade:** O filtro de alto nível `tls.handshake` pode não retornar resultados em versões específicas do tshark. Utilizou-se o filtro de menor nível equivalente para o tipo de conteúdo Handshake (22):

```bash
tshark -r lab_capture.pcapng -Y "tls.record.content_type==22"
```

### 2.2 Inspecção Detalhada de Quadros Específicos

```bash
# Inspecionar Client Hello (Pacote 34)
tshark -r lab_capture.pcapng -Y "frame.number==34" -V

# Inspecionar Server Hello (Pacote 36)
tshark -r lab_capture.pcapng -Y "frame.number==36" -V | grep -A 30 "Transport Layer Security"
```

---

## 3. Dissecação do Handshake TLS 1.3

### 3.1 Client Hello (Pacote 34)

- **Encapsulamento de Camada de Enlace (SLL):** Devido à captura ter sido iniciada com a flag `-i any`, os pacotes utilizam o formato *Linux cooked capture v1 (SLL)*.
- **Versão da Camada de Registro (Record Layer):** `TLS 1.0 (0x0301)` — Mantida apenas para compatibilidade com middleboxes legados.
- **Campo de Versão Legada (Handshake Layer):** `TLS 1.2 (0x0303)` — Depreciado segundo as especificações do TLS 1.3 (RFC 8446). A indicação real de suporte é feita via extensão `supported_versions`.
- **Extension `supported_versions`:** Contém o identificador `TLS 1.3 (0x0304)`.
- **SNI (Server Name Indication):** `example.com` (permite ao servidor identificar qual certificado apresentar).
- **Suítes de Criptografia Oferecidas:** 90 suítes no total (180 bytes).
  - *Prioridade do Cliente:* As 3 primeiras suítes oferecidas são exclusivas do TLS 1.3:
    1. `TLS_AES_256_GCM_SHA384`
    2. `TLS_CHACHA20_POLY1305_SHA256`
    3. `TLS_AES_128_GCM_SHA256`
  - *Fallback:* As demais 87 suítes pertencem ao TLS 1.2, mantidas para compatibilidade retroativa.

### 3.2 Server Hello (Pacote 36)

- **Suíte de Criptografia Selecionada:** `TLS_AES_256_GCM_SHA384 (0x1302)`. O servidor atendeu à primeira preferência do cliente.
- **Método de Compressão:** `null (0)`. A compressão TLS foi desativada no padrão TLS 1.3 para mitigar ataques de canal lateral como **CRIME** e **BREACH**.
- **Session ID:** O servidor apenas ecoou o valor recebido (`f275743b...`), mantido apenas para conformidade de formato sem função no TLS 1.3.

---

## 4. Destaque de Segurança: Troca de Chaves Híbrida Pós-Quântica

Um dos achados mais relevantes desta análise foi a identificação da extensão `key_share` no Server Hello utilizando o grupo de troca de chaves **X25519MLKEM768**.

### 🔒 Como Funciona a Criptografia Híbrida Pós-Quântica

1. **Componente Clássico (X25519):** Criptografia de curva elíptica de alto desempenho que garante a segurança contra atacantes clássicos no presente.
2. **Componente Pós-Quântico (ML-KEM-768):** Antigo algoritmo **Kyber-768**, recém-padronizado pelo **NIST (FIPS 203)**, resistente a computadores quânticos operando o algoritmo de Shor.
3. **Payload Elevado:** Devido aos vetores do algoritmo pós-quântico, a chave negociada atinge **1120 bytes** (em comparação a ~32 bytes do X25519 puro).
4. **Defesa Contra Ataques "Harvest Now, Decrypt Later":** Essa implementação protege a comunicação atual contra adversários que estejam interceptando e armazenando tráfego criptografado para descriptografá-lo no futuro quando computadores quânticos viáveis estiverem disponíveis.

---

## 5. Relevância Forense e Threat Hunting

1. **Fingerprinting JA3 / JA4:** A combinação de Cipher Suites, extensões e versões oferecidas no *Client Hello* forma uma assinatura única (Hash JA3/JA4) que permite identificar o software cliente (ex: cURL, Python, malware específico) independentemente do User-Agent.
2. **Inspeção de SNI para Detecção de C2:** O campo SNI trafega em texto claro no TLS 1.3 tradicional, permitindo identificar o domínio de destino mesmo em conexões criptografadas.
3. **Detecção de Ferramentas por Cipher Suites Legadas:** Softwares maliciosos ou scripts legados frequentemente enviam apenas suítes de criptografia antigas e fracas (ex: `RC4`, `3DES`, `RSA key exchange` sem Perfect Forward Secrecy).

---

## 6. Conclusão

A análise do tráfego TLS confirmou o estabelecimento de uma sessão HTTPS moderna sobre TLS 1.3 para `example.com`, empregando cifragem simétrica de alta segurança (`AES-256-GCM`) e proteção avançada contra ameaças quânticas emergentes (`X25519MLKEM768`).
