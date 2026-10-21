from langgraph.graph import StateGraph, END
from agents import (
    SecurityBenchmarkState,
    test_designer_node,
    test_runner_node,
    bug_hunter_node,
    qa_reviewer_node
)

def create_qa_orchestrator():
    """
    Tworzy skompilowany graf LangGraph zgodny z nową architekturą benchmarku bezpieczeństwa,
    zapewniając pełną kompatybilność z app.py i starymi odwołaniami.
    """
    workflow = StateGraph(SecurityBenchmarkState)

    # Dodanie nowych, rzetelnych węzłów z agents.py
    workflow.add_node("test_designer", test_designer_node)
    workflow.add_node("test_runner", test_runner_node)
    workflow.add_node("bug_hunter", bug_hunter_node)
    workflow.add_node("qa_reviewer", qa_reviewer_node)

    # Definicja przepływu (Arrange -> Act -> Assert -> Review)
    workflow.set_entry_point("test_designer")
    workflow.add_edge("test_designer", "test_runner")
    workflow.add_edge("test_runner", "bug_hunter")
    workflow.add_edge("bug_hunter", "qa_reviewer")
    workflow.add_edge("qa_reviewer", END)

    # Kompilacja grafu do postaci wykonywalnej
    return workflow.compile()