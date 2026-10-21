import argparse
import json
import logging
from agents import create_security_benchmark_graph

# Konfiguracja logowania
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def main():
    parser = argparse.ArgumentParser(description="LLM Security Red-Team Harness & Multi-Agent System")
    parser.add_argument(
        "--mode", 
        type=str, 
        default="static", 
        choices=["static", "dynamic"],
        help="Tryb audytu bezpieczeństwa: static (100 testów) lub dynamic (PAIR)"
    )
    parser.add_argument(
        "--target-url",
        type=str,
        default="http://127.0.0.1:8000/api/v1/evaluate",
        help="Adres URL docelowego serwera FastAPI z zespołem agentów"
    )
    args = parser.parse_args()

    logging.info(f"Uruchamianie audytu w trybie: [{args.mode.upper()}]")
    logging.info(f"Docelowy endpoint agentów: {args.target_url}")

    # 1. Inicjalizacja skompilowanego grafu LangGraph
    app_graph = create_security_benchmark_graph()

    # 2. Ustawienie początkowego stanu (Initial State)
    initial_state = {
        "target_url": args.target_url,
        "test_cases": [],
        "test_results": [],
        "bug_reports": [],
        "review_status": "PENDING",
        "audit_summary": {}
    }

    # 3. Uruchomienie przepływu agentowego
    logging.info("Rozpoczęcie egzekucji grafu wieloagentowego...")
    final_state = app_graph.invoke(initial_state)

    # 4. Przygotowanie i zapis raportu końcowego (redteam_report.json)
    report_data = {
        "mode": args.mode,
        "review_status": final_state.get("review_status"),
        "summary": final_state.get("audit_summary", {}),
        "bug_reports": [bug.model_dump() for bug in final_state.get("bug_reports", [])],
        "detailed_results": [res.model_dump() for res in final_state.get("test_results", [])]
    }

    report_filename = "redteam_report.json"
    with open(report_filename, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4, ensure_ascii=False)

    logging.info(f"Audyt zakończony pomyślnie! Raport zapisano do pliku: {report_filename}")
    
    # Podsumowanie w konsoli
    summary = report_data["summary"]
    logging.info(f"--- PODSUMOWANIE AUDYTU ---")
    logging.info(f"Wszystkich testów: {summary.get('total_tests', 0)}")
    logging.info(f"Odparte (PASSED): {summary.get('passed', 0)}")
    logging.info(f"Przełamane (BYPASSED): {summary.get('bypassed', 0)}")
    logging.info(f"Wskaźnik podatności (Bypass Rate): {summary.get('bypass_rate_percent', 0)}%")
    logging.info(f"Wykryte błędy (Bugs): {summary.get('bugs_found', 0)}")

if __name__ == "__main__":
    main()