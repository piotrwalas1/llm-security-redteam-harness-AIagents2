from typing import TypedDict, List, Dict, Any

class QAState(TypedDict):
    """
    Stan przepływu zespołu QA w LangGraph, uwzględniający standardowy proces 
    oraz bramkę bezpieczeństwa (Security Guard / Guardrail).
    """
    raw_requirements: str              # Wejściowe User Story / Wymagania biznesowe (punkt wejścia)
    analyzed_requirements: str         # Wynik pracy Requirements Analyst
    test_cases: List[Dict[str, Any]]   # Przypadki testowe wygenerowane przez Test Designer
    execution_results: List[Dict[str, Any]] # Wyniki wykonania testów przez Test Executor
    bug_reports: List[Dict[str, Any]]  # Zgłoszone defekty od Bug Huntera
    review_status: str                 # Status zatwierdzenia przez QA Reviewer (np. APPROVED, REJECTED, BLOCKED_BY_SECURITY)
    audit_trail: List[str]             # Dziennik zdarzeń i kroków wykonanych przez system (audit trail)
    
    # Pola dla bramki bezpieczeństwa (Security Guard)
    is_attack: bool                    # True, jeśli Security Guard wykrył próbę ataku (Prompt Injection / Jailbreak)
    threat_reason: str                 # Uzasadnienie decyzji podjętej przez bramkę bezpieczeństwa