from langgraph.graph import StateGraph, END
from models import QAState
from agents import QAAgentTeam

def route_after_guard(state: QAState) -> str:
    """Funkcja decyzyjna dla LangGraph weryfikująca wynik bramki bezpieczeństwa."""
    if state.get("is_attack", False):
        return "blocked"
    return "analyst"

def security_block_node(state: QAState) -> QAState:
    """Węzeł uruchamiany w przypadku wykrycia złośliwego ataku na system agentów."""
    print("\n[!] PROCES ZABLOKOWANY: Wykryto próbę ataku (Prompt Injection / Jailbreak)!")
    state["review_status"] = "BLOCKED_BY_SECURITY"
    state["audit_trail"].append("Proces przerwany przez bramkę bezpieczeństwa.")
    return state

def create_qa_orchestrator():
    """Tworzy skompilowany graf LangGraph dla zespołu QA z wbudowaną ochroną Security Guard."""
    agents = QAAgentTeam()
    
    workflow = StateGraph(QAState)


    workflow.add_node("guard", agents.security_guard)
    workflow.add_node("analyst", agents.requirements_analyst)
    workflow.add_node("designer", agents.test_designer)
    workflow.add_node("executor", agents.test_executor)
    workflow.add_node("bug_hunter", agents.bug_hunter)
    workflow.add_node("reviewer", agents.qa_reviewer)
    workflow.add_node("blocked", security_block_node)

    # Ustawienie punktu wejścia na bramkę bezpieczeństwa
    workflow.set_entry_point("guard")

    # Warunkowe rozgałęzienie po sprawdzeniu wejścia przez Guardrail
    workflow.add_conditional_edges(
        "guard",
        route_after_guard,
        {
            "analyst": "analyst",
            "blocked": "blocked"
        }
    )

    # Standardowy, sekwencyjny przepływ dla bezpiecznych danych
    workflow.add_edge("analyst", "designer")
    workflow.add_edge("designer", "executor")
    workflow.add_edge("executor", "bug_hunter")
    workflow.add_edge("bug_hunter", "reviewer")
    workflow.add_edge("reviewer", END)
    
    # Zablokowany proces kończy działanie natychmiast
    workflow.add_edge("blocked", END)

    # Kompilacja grafu do postaci wykonywalnej
    return workflow.compile()