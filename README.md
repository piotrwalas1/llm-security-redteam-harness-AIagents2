# 🛡️ LLM Security Red-Team Harness (AI Agents 2)

Ten projekt przedstawia zaawansowany system oparty na architekturze wielu agentów (multi-agent system) zarządzanych przez **orkiestratora**, zaprojektowany w celu bezpiecznego przetwarzania zapytań i ochrony modeli językowych (LLM) przed złośliwymi atakatami.

> ℹ️ **Uwaga:** Repozytorium to skupia się na architekturze obronnej (agenci i orkiestracja). Symulacje ataków oraz scenariusze typu *Red-Team* (w tym próby *Prompt Injection*, *Jailbreak* itp.) zostały wydzielone i są obsługiwane w osobnym repozytorium.

---

## 🏗️ Architektura Systemu i Komponenty

System opiera się na współpracy wyspecjalizowanych agentów AI zarządzanych centralnie:

1. **Agent Sprawdzający Bezpieczeństwo (Security Screening Agent / Guardrail):**
   * **Rola:** Pierwsza linia obrony systemu. Analizuje każde przychodzące zapytanie pod kątem potencjalnych zagrożeń (np. próby wstrzykiwania instrukcji, jailbreak, socjotechnika) zanim trafi ono do dalszego przetwarzania.
2. **Orkiestrator (Orchestrator Agent):**
   * **Rola:** Zarządza przepływem zadań, koordynuje komunikację pomiędzy poszczególnymi agentami oraz podejmuje decyzje o dalszym routingu zapytania w zależności od wyniku analizy bezpieczeństwa.
3. **Pozostałe komponenty (np. Evaluation / Reporting):**
   * **Rola:** Odpowiadają za rejestrowanie anomalii, generowanie raportów ze zdarzeń oraz kontrolowanie poprawności odpowiedzi systemu.

---

## 🚀 Główne Funkcjonalności

- **Architektura Multi-Agentowa:** Podział zadań pomiędzy wyspecjalizowane podsystemy AI z centralnym zarządzaniem (orkiestratorem).
- **Automatyczna filtracja zagrożeń:** Wykrywanie i blokowanie prób *Prompt Injection*, *Jailbreak*, wycieku promptów systemowych (*Prompt & Instruction Leakage*) oraz prób obejścia zabezpieczeń (*Evasion & Obfuscation*).
- **Moduł Raportowania:** Rejestrowanie i kategoryzacja anomalii oraz nieautoryzowanych prób dostępu.

##  📊 Kategorię Chronionych Wektorów Ataku
**System chroni przed m.in. następującymi zagrożeniami:**

Direct & Indirect Prompt Injection: Próby bezpośredniego lub ukrytego (np. w plikach, JSON-ach) nadpisania instrukcji systemowych.

System Prompt & Instruction Leakage: Próby wyciągnięcia ukrytych promptów systemowych i konfiguracji.

Evasion & Obfuscation: Omijanie filtrów za pomocą kodowania (Base64, ROT13) lub nietypowych języków.

Sensitive Info / PII Extraction: Próby wyłudzenia danych osobowych, kluczy API oraz haseł.

Roleplay & Social Engineering: Próby manipulacji modelem poprzez udawane scenariusze.

Unsafe Code Execution: Próby skłonienia systemu do wykonania niebezpiecznych poleceń.

---

## 💻 Wymagania i Instalacja

### Wymagania wstępne
* **Python 3.8+**
* Dostęp do API odpowiedniego modelu LLM (np. OpenAI, Ollama itp.)

### Instrukcja instalacji

1. **Sklonuj repozytorium:**
   ```bash
   git clone [https://github.com/piotrwalas1/llm-security-redteam-harness-AIagents2.git](https://github.com/piotrwalas1/llm-security-redteam-harness-AIagents2.git)
   cd llm-security-redteam-harness-AIagents2
   ```
   **Uruchamiamy w takiej kolejności**
* python sut.py
  * python app.py 
