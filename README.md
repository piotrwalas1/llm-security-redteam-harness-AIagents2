# 📊 LLM Requirements & Functional Testing Harness (v5.0)

![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=for-the-badge&logo=fastapi)
![LangGraph](https://img.shields.io/badge/LangGraph-Orchestration-orange?style=for-the-badge)
![Google GenAI](https://img.shields.io/badge/Google_GenAI-Gemini_2.5_Flash-4285F4?style=for-the-badge&logo=google)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)

Zautomatyzowane środowisko klasy produkcyjnej przeznaczone do **analizy wymagań biznesowych (User Stories)**, wykrywania luk logicznych oraz **automatycznej generacji i wykonywania testów funkcjonalnych** na systemach opartych o modele językowe (LLM).

System wykorzystuje architekturę wieloagentową (**Multi-Agent Graph Orchestration**) opartą o **LangGraph** oraz komunikację w czasie rzeczywistym poprzez **Server-Sent Events (SSE)**.

---

## 💡 Główne Funkcjonalności

- **📋 Analiza Wymagań Biznesowych (Requirements Analyst):** Automatyczna parsacja dokumentów PDF lub tekstu surowego. Agent wykrywa luki w User Stories, spójność logiki biznesowej oraz braki w przypadkach brzegowych (*Edge Cases*).
- **🧪 Automatyczny Generator Testów (Test Designer):** Przekształcanie wyekstrahowanych wymagań w strukturyzowane przypadki testowe (`US-TC-xxx`) z oczekiwaną odpowiedzią systemu (`ALLOW`).
- **⚙️ Wykonanie Testów na Żywo (SUT Runner & Reviewer):** Automatyczne wysyłanie zapytań testowych do docelowego środowiska (SUT) na porcie `8001`, ewaluacja czasów odpowiedzi oraz weryfikacja poprawności biznesowej (`PASSED` / `FALSE_POSITIVE` / `INCONCLUSIVE`).
- **🛡️ Strażnik Bezpieczeństwa Wejścia (Harness Guard):** Wbudowana pierwsza linia obrony weryfikująca, czy przesłany plik z wymaganiami lub prompt ręczny nie zawiera prób ataku (*Prompt Injection*, *Jailbreak*, *Social Engineering*).
- **🔄 Podgląd Pracy Agentów na Żywo (SSE Streaming UI):** Asynchroniczny interfejs webowy dostarczający natychmiastowy feedback z każdego węzła grafu bez przeładowywania strony.
- **⚡ Awaryjny Tryb Heurystyczny (Degraded Mode):** Możliwość działania systemu bez podłączonego klucza GCP/Vertex API (z wykorzystaniem wbudowanych algorytmów heurystycznych i regex).

---

## 🏗️ Architektura Grafu Agentów (LangGraph Workflow)

Przepływ danych w systemie jest realizowany jako skompilowany graf skierowany (`StateGraph`):
[ RAW INPUT / PDF ]
                            |
                            v
                  +-------------------+
                  | 🔍 Harness Guard  |
                  +-------------------+
                            |
                Is Attack / Guard Fail?
               /                     \
         (TAK) /                     \ (NIE)
              v                       v
  +----------------------+   +--------------------------+
  | ⚖️ QA Reviewer       |   | 📋 Requirements Analyst |
  | (REJECTED_ATTACK)    |   +--------------------------+
  +----------------------+                |
              |                           v
              |              +--------------------------+
              |              | 🧪 Test Designer          |
              |              +--------------------------+
              |                           |
              |                           v
              |              +--------------------------+
              |              | ⚙️ SUT Runner            |
              |              +--------------------------+
              |                           |
              |                           v
              |              +--------------------------+
              \------------->| ⚖️ QA Reviewer            |
                             +--------------------------+
                                          |
                                          v
                                       [ END ]

### Role Agentów w Grafie:
1. **`harness_guard_node`:** Skanuje wejście pod kątem wstrzyknięć kodu i prób manipulacji instrukcjami.
2. **`requirements_analyst_node`:** Analizuje User Stories przy użyciu modelu Gemini 2.5 Flash.
3. **`test_designer_node`:** Generuje pojedyncze scenariusze testowe z intencją `ALLOW`.
4. **`test_runner_node`:** Wytwarza żądania HTTP POST do endpointu `/api/v1/evaluate` w SUT i rejestruje logi egzekucji.
5. **`qa_reviewer_node`:** Agreguje statystyki wykonania, mierzy wskaźnik zaliczenia (*Pass Rate*) oraz tworzy podsumowanie sesji audytowej.

---

## 📦 Struktura Projektu

```text
├── agents.py           # Logika węzłów LangGraph, definicje stanów Pydantic/TypedDict i agentów LLM
├── app.py              # Główna aplikacja FastAPI (UI + Stream SSE endpoint /run-stream)
├── sut.py              # Produkcyjny serwer SUT (System Under Test) z dwuwarstwową ochroną Pre-Guard
├── README.md           # Dokumentacja projektu
└── .env                # Zmienne środowiskowe (np. GCP_PROJECT_ID)
💻 Wymagania i Uruchomienie
Wymagania wstępne
Python: 3.10 lub nowszy

Dostęp do API: Konto Google Cloud z aktywnym Projektem i Vertex AI API (opcjonalnie dla pełnego trybu LLM)

1. Instalacja zależności
Sklonuj repozytorium i zainstaluj niezbędne pakiety Python:
git clone [https://github.com/piotrwalas1/llm-security-redteam-harness-AIagents2.git](https://github.com/piotrwalas1/llm-security-redteam-harness-AIagents2.git)
cd llm-security-redteam-harness-AIagents2

pip install fastapi uvicorn pypdf jinja2 python-dotenv langchain-google-genai langgraph pydantic requests
🚀 Uruchomienie Systemu (Krok po Kroku)
Dla pełnego działania testów funkcjonalnych wymagane jest uruchomienie dwóch niezależnych usług:

Krok 1: Uruchomienie serwera docelowego (SUT)
Serwer SUT symuluje produkcyjny system bankowy/biznesowy z modelem Gemini 2.5 Flash oraz filtry bezpieczeństwa.
python sut.py
📍 Panel Główny UI dostępny pod adresem: http://127.0.0.1:8000

🖥️ Obsługa Interfejsu Przeglądarki
Otwórz w przeglądarce adres http://127.0.0.1:8000.

Wgraj dokument PDF z wymaganiami biznesowymi (np. user_story_Santander.pdf) LUB wpisz tekst wymagań w polu tekstowym.

Kliknij przycisk 🚀 Uruchom zespół agentów.

Obserwuj w czasie rzeczywistym:

Status analizy bezpieczeństwa wejścia.

Wnioski analityka wymagań biznesowych.

Wygenerowane przypadki testowe US-TC-xxx.

Wyniki testów HTTP przesłanych do SUT wraz z uzasadnieniem.

Historię poprzednich sesji audytowych z wskaźnikami powodzenia.

🧪 Przykładowe Zapytanie Testowe do SUT (API Endpoint)
Serwer SUT przyjmuje strukturyzowane zapytania JSON:
curl -X POST "[http://127.0.0.1:8001/api/v1/evaluate](http://127.0.0.1:8001/api/v1/evaluate)" \
     -H "Content-Type: application/json" \
     -d '{"prompt": "Jako użytkownik chcę zalogować się do bankowości za pomocą biometrii."}'
     Przykładowa odpowiedź SUT:
     {
  "output": "Funkcja logowania biometrycznego jest dostępna w zakładce Ustawienia -> Bezpieczeństwo.",
  "blocked": false,
  "guard_decision": "SAFE"
}
🤝 Autor i Licencja
Autor: Piotr Wałas

Repozytorium: saucedemo-sorting-tests / llm-security-redteam-harness

Licencja: MIT
