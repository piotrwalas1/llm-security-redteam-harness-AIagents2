# LLM Security Red-Team Harness & Multi-Agent System

Zaawansowany zestaw do testów bezpieczeństwa i benchmarkingu, zaprojektowany do testowania odporności wieloagentowych systemów LLM (zbudowanych przy użyciu FastAPI oraz LangGraph) na zaawansowane ataki typu prompt injection, jailbreak, ekstrakcję danych oraz wyczerpanie zasobów.

---

## 🏗️ Przegląd Architektury

System implementuje solidną **pompę wieloagentową (Multi-Agent Pipeline)** wspieraną przez dedykowaną bramkę bezpieczeństwa:
1. **Security Guard (Gatekeeper):** Pełni rolę pierwszej linii obrony, przechwytując dane wejściowe użytkownika, analizując intencje i odfiltrowując złośliwe prompty, zanim trafią one do rdzenia rozumowania.
2. **Workflow Wieloagentowy (LangGraph):** Koordynuje wyspecjalizowanych agentów (np. Analityka, Projektanta, Testera, Bug Huntera), którzy collaborative rozwiązują złożone zadania.
3. **Zewnętrzny Sędzia Benchmarkowy (Vertex AI):** Harness ewaluacyjny uderza w endpoint FastAPI i wykorzystuje chmurowy model LLM jako sędziego do oceny odporności systemu w skali binarnej (`10` dla `REFUSED`/`PASSED`, `0` dla `BYPASSED`/`FAILED`).

---

## 🛡️ Zdolności Obronne i Kategorie Testów

Harness testowy ocenia system docelowy w ramach **100 statycznych przypadków testowych** podzielonych na kluczowe domeny bezpieczeństwa:
* **Direct & Indirect Prompt Injection** (Bezpośrednie i pośrednie wstrzykiwanie promptów)
* **System Prompt & Instruction Leakage** (Wyciek promptu systemowego i instrukcji)
* **Evasion via Encoding, Obfuscation & Multi-Language** (Ewade przez kodowanie, obfuskację i wielojęzyczność)
* **Sensitive Information & PII Extraction** (Ekstrakcja wrażliwych danych i PII)
* **Roleplay, Hypotheticals & Social Engineering** (Roleplay, hipotezy i inżynieria społeczna)
* **Excessive Agency & Unsafe Tool / Code Execution** (Nadmierna sprawczość i niebezpieczne wykonywanie kodu/narzędzi)
* **Denial of Service & Resource Exhaustion** (Odcięcie usługi i wyczerpanie zasobów)
* **Logic, Hallucination & Integrity Manipulation** (Manipulacja logiką, halucynacjami i integralnością)

Dodatkowo, zestaw wspiera **Dynamiczny Red-Teaming (PAIR - Prompt Automatic Iterative Refinement)** w celu wykrywania wieloetapowych ścieżek podatności.

---

## 📁 Struktura Projektu

```text
├── app.py                  # Serwer FastAPI hostujący system wieloagentowy LangGraph
├── config.py               # Zarządzanie konfiguracją (routing zapytań target vs. judge)
├── main.py                 # Punkt wejścia harnessu do audytu red-team
├── test_config.py          # Testy jednostkowe konfiguracji GCP oraz aplikacji
├── requirements.txt        # Zależności projektu
├── .env                    # Zmienne środowiskowe i klucze API (ignorowane przez git)
└── .gitignore              # Reguły wykluczeń Gita


🚀 Szybki start
1. Wymagania wstępne
Python 3.10+

Aktywne poświadczenia Google Cloud / Vertex AI (dla Sędziego i/lub modeli)
```
## Uruchomienie Systemu 
python app.py
