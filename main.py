from graph import create_qa_orchestrator
from config import config
from models import QAState

def main():
    print(f"[*] Uruchamianie orkiestratora QA w GCP Project: {config.gcp.project_id}")
    print("=" * 60)
    
    # Pobieramy User Story bezpośrednio z terminala
    user_story = input("[?] Wprowadź lub wklej User Story (lub prompt do przetestowania):\n> ")
    
    if not user_story.strip():
        print("[!] Nie wprowadzono tekstu. Używam domyślnego User Story.")
        user_story = "Użytkownik musi mieć możliwość zresetowania hasła za pomocą adresu e-mail."

    initial_state: QAState = {
        "raw_requirements": user_story,
        "analyzed_requirements": "",
        "test_cases": [],
        "execution_results": [],
        "bug_reports": [],
        "review_status": "",
        "audit_trail": [],
        "is_attack": False,
        "threat_reason": ""
    }

    print("\n[*] Inicjalizacja orkiestratora LangGraph...")
    app = create_qa_orchestrator()
    
    print("[*] Rozpoczęcie cyklu pracy zespołu agentów...\n")
    final_state = app.invoke(initial_state)

    # ============================================================
    # === WYŚWIETLENIE RAPORTU W TERMINARZU ===
    # ============================================================
    print("\n" + "=" * 60)
    print(" === SZCZEGÓŁOWY RAPORT ZESPOŁU QA ===")
    print("=" * 60)
    print(f"Status Przeglądu: {final_state.get('review_status')}")
    
    if final_state.get('is_attack'):
        print(f"\n[!] BRAMKA BEZPIECZEŃSTWA: Wykryto atak!")
        print(f" -> Powód: {final_state.get('threat_reason')}")
        raport_wykryty_atak = True
        atak_powod = final_state.get('threat_reason')
    else:
        raport_wykryty_atak = False
        
        # 1. Analiza wymagań
        analyzed_reqs = final_state.get('analyzed_requirements', 'Brak danych')
        print(f"\n--- 1. Analiza wymagań (Requirements Analyst) ---")
        print(analyzed_reqs)
        
        # 2. Przypadki testowe
        print(f"\n--- 2. Przypadki testowe (Test Designer) ---")
        test_cases_list = final_state.get('test_cases', [])
        tc_markdown_lines = []
        for tc in test_cases_list:
            print(f"  * [{tc.get('id')}] ({tc.get('type')}): {tc.get('desc')}")
            tc_markdown_lines.append(f"- **[{tc.get('id')}]** *({tc.get('type')})*: {tc.get('desc')}")
            
        # 3. Wyniki wykonania
        print(f"\n--- 3. Wyniki wykonania (Test Executor) ---")
        exec_results_list = final_state.get('execution_results', [])
        exec_markdown_lines = []
        for res in exec_results_list:
            err_msg = f" (Błąd: {res.get('error')})" if 'error' in res else ""
            print(f"  * Test {res.get('tc_id')}: Status -> {res.get('status')}{err_msg}")
            exec_markdown_lines.append(f"- Test **{res.get('tc_id')}**: Status -> `{res.get('status')}`{err_msg}")
            
        # 4. Raporty o błędach
        print(f"\n--- 4. Raporty o błędach (Bug Hunter) ---")
        bugs = final_state.get('bug_reports', [])
        bug_markdown_lines = []
        if bugs:
            for bug in bugs:
                print(f"  * [{bug.get('bug_id')}] Severity: {bug.get('severity')}")
                print(f"    Szczegóły: {bug.get('details')}")
                bug_markdown_lines.append(f"- **[{bug.get('bug_id')}]** Severity: `{bug.get('severity')}`\n  - Szczegóły: {bug.get('details')}")
        else:
            print("  Brak zgłoszonych błędów.")
            bug_markdown_lines.append("Brak zgłoszonych błędów.")

    print("\n" + "-" * 60)
    print("Dziennik zdarzeń (Audit Trail):")
    audit_lines = []
    for log in final_state.get("audit_trail", []):
        print(f"  - {log}")
        audit_lines.append(f"- {log}")
    print("=" * 60)

    # ============================================================
    # === AUTOMATYCZNY ZAPIS DO PLIKU MARKDOWN (raport_qa.md) ===
    # ============================================================
    review_status = final_state.get('review_status', 'N/A')

    if raport_wykryty_atak:
        raport_tresc = f"""# Raport z Zespołu QA & Red Team

**Status Przeglądu:** `ODRZUCONY (Wykryto zagrożenie)`  

> [!WARNING]
> **Bramka bezpieczeństwa wykryła atak!**  
> **Powód:** {atak_powod}

## Dziennik zdarzeń (Audit Trail)
{chr(10).join(audit_lines)}
"""
    else:
        raport_tresc = f"""# Raport z Zespołu QA & Red Team

**Status Przeglądu:** `{review_status}`  

## 1. Analiza wymagań (Requirements Analyst)
{analyzed_reqs}

## 2. Przypadki testowe (Test Designer)
{chr(10).join(tc_markdown_lines) if tc_markdown_lines else "Brak przypadków testowych."}

## 3. Wyniki wykonania (Test Executor)
{chr(10).join(exec_markdown_lines) if exec_markdown_lines else "Brak wyników wykonania."}

## 4. Raporty o błędach (Bug Hunter)
{chr(10).join(bug_markdown_lines)}

## Dziennik zdarzeń (Audit Trail)
{chr(10).join(audit_lines)}
"""

    plik_raportu = "raport_qa.md"
    with open(plik_raportu, "w", encoding="utf-8") as f:
        f.write(raport_tresc)

    print(f"\n[SUKCES] Raport został pomyślnie zapisany do pliku: **{plik_raportu}** (bez ID projektu) 🚀")

if __name__ == "__main__":
    main()