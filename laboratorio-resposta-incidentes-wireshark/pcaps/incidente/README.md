# 🔴 PCAP de Incidente: Cenário "First to Last" (FormBook Malware)

Este diretório contém o arquivo PCAP utilizado para a **Fase 05 — Investigação de Incidente** do laboratório.

---

## 📦 Detalhes do Arquivo

- **Arquivo PCAP:** `2026-08-09-traffic-analysis-exercise.pcap`
- **Fonte Original:** [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2026/08/09/index.html)
- **Data do Exercício:** 09 de Agosto de 2026
- **Senha do Arquivo Zip (se re-extrair):** `infected_20260809`
- **Família de Malware:** Infostealer **FormBook**

---

## 🖥️ Topologia da Rede do Exercício

```text
Rede Local (LAN): 172.16.8.0/24
Domínio Active Directory: firsttolast.tech
Domain Controller (DC): 172.16.8.2 (FIRSTTOLAST-DC)
Gateway Padrão: 172.16.8.1
```

---

## ❓ Questões Respondidas na Análise

1. **IP do Cliente Infectado:** `172.16.8.49`
2. **Endereço MAC:** `00:12:f0:28:d4:34`
3. **Hostname:** `DESKTOP-5NLV63K`
4. **Conta de Usuário:** `rvance`
5. **Nome Completo do Usuário:** `Raymond Vance`

Para o relatório de investigação completo com a lista de 15 domínios de C2 e mapeamento no MITRE ATT&CK, consulte:

📄 **[Relatório Técnico de Incidente](../../relatorios/relatorio_incidente.md)**
