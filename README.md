# 🧩 Wazuh Rule Coverage Analyzer

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Last Commit](https://img.shields.io/github/last-commit/<your-username>/wazuh-rule-coverage-analyzer)
![Pull Requests](https://img.shields.io/github/issues-pr/<your-username>/wazuh-rule-coverage-analyzer?color=yellow)
![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-orange)
![Built with ❤️](https://img.shields.io/badge/Built%20with-%E2%9D%A4-red)

**I created this Python tool to help companies ensure complete defensive visibility by mapping Wazuh detection rules to the MITRE ATT&CK framework.**  

It helps organizations verify that safeguards exist for every known adversary technique, exposing detection gaps before attackers can exploit them.

---

## Overview
Modern SOC teams manage hundreds of detection rules, yet few know which attack techniques are truly covered.  

**The Wazuh Rule Coverage Analyzer** automates that process by parsing Wazuh rulesets, mapping them to MITRE ATT&CK tactics, and generating an interactive report that highlights coverage completeness across all stages of an attack.

---

## Key Features
- 📂 **Rule Parsing** — Extracts rule IDs, descriptions, and groups from Wazuh XML or JSON files.  
- 🎯 **MITRE ATT&CK Mapping** — Correlates rules with ATT&CK tactics and techniques to verify detection scope.  
- 🧠 **Gap Identification** — Highlights uncovered or weakly mapped techniques for immediate improvement.  
- 📊 **Visual Reports** — Generates color-coded HTML and CSV outputs that visualize detection coverage.  
- 🔄 **Continuous Validation** — Can integrate into CI pipelines to monitor detection completeness over time.  

---

## Why It Matters
Every defensive control should map back to a known adversary behavior.  
This tool gives security teams measurable confidence that their environment is protected across the entire MITRE ATT&CK matrix — ensuring no critical technique is left unmonitored.

---

## 🧰 Tech Stack
| Tool | Purpose |
|------|----------|
| 🐍 **Python** | Core scripting and data analysis |
| 🧱 **Wazuh** | Detection rule parsing and rule metadata |
| 🕸️ **MITRE ATT&CK** | Framework for mapping adversary techniques |
| 🧾 **Pandas** | Data transformation and tabular reporting |
| 🧩 **lxml** | XML rule parsing |

---

## Example Output
- Interactive HTML report with color-coded rule coverage by MITRE tactic  
- CSV export of rule-to-technique mappings for data visualization or dashboard integration  
<img width="1779" height="1249" alt="image" src="https://github.com/user-attachments/assets/b0c21900-7895-498a-a634-0f30d8c09ce8" />

---

## Author
Created by **Avigail Laing**: a cybersecurity student and blue team analyst passionate about detection engineering and defensive automation.

---

## 🌐 Useful Links
🔗 [MITRE ATT&CK Framework](https://attack.mitre.org/)  
🔗 [Wazuh Documentation](https://documentation.wazuh.com/)  
🔗 [Python Docs](https://docs.python.org/3/)  

---
