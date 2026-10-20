import os
import io
import datetime
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from pypdf import PdfReader
from graph import create_qa_orchestrator
from config import config
from models import QAState

app = FastAPI(title="QA & Red Team Multi-Agent Harness Dashboard")

class PromptRequest(BaseModel):
    prompt: str

# Pamięć podręczna na historię testów w obecnej sesji serwera (maksymalnie 15 ostatnich wpisów)
TEST_HISTORY = []

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title>QA & Red Team Security Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e1e; color: #d4d4d4; margin: 0; padding: 20px; }
        .container { max-width: 1000px; margin: auto; background: #252526; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
        h1, h2 { color: #4ec9b0; text-align: center; }
        textarea, input[type="file"] { width: 100%; padding: 12px; margin-top: 10px; margin-bottom: 20px; background: #333333; border: 1px solid #444; color: #fff; border-radius: 4px; box-sizing: border-box; font-size: 14px; }
        textarea { height: 100px; resize: vertical; }
        button { background-color: #0e639c; color: white; border: none; padding: 12px 20px; font-size: 16px; border-radius: 4px; cursor: pointer; width: 100%; font-weight: bold; transition: background 0.2s; }
        button:hover { background-color: #1177bb; }
        .loading { display: none; text-align: center; margin-top: 20px; color: #ce9178; font-weight: bold; }
        .result-box { margin-top: 20px; background: #1e1e1e; padding: 20px; border-radius: 6px; border: 1px solid #3c3c3c; white-space: pre-wrap; font-family: Consolas, monospace; font-size: 13px; max-height: 300px; overflow-y: auto; }
        .success-info { background: #264f78; color: #fff; padding: 10px; border-radius: 4px; margin-bottom: 15px; font-size: 14px; }
        
        /* Styl tabeli historii */
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #1e1e1e; border-radius: 6px; overflow: hidden; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; font-size: 13px; }
        th { background-color: #333333; color: #4ec9b0; }
        .badge-attack { background-color: #f14c4c; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
        .badge-safe { background-color: #238636; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
        .badge-approved { background-color: #1f6feb; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ QA & Red Team Security Dashboard</h1>
        
        <div class="success-info">
            💡 <strong>Dashboard na żywo:</strong> Formularz poniżej pozwala testować prompty, a tabela na dole pokazuje historię testów (w tym te uruchamiane automatycznie ze skryptu w terminalu).
        </div>

        <form action="/run-agent" method="post" enctype="multipart/form-data" onsubmit="showLoading()">
            <label for="user_story"><strong>Wprowadź User Story / Prompt do przetestowania:</strong></label>
            <textarea name="user_story" placeholder="Wpisz wymaganie lub prompt ataku..."></textarea>
            
            <label for="file"><strong>Lub prześlij dokument (PDF, TXT, MD):</strong></label>
            <input type="file" name="file" accept=".pdf,.txt,.md">
            
            <button type="submit">🚀 Uruchom Zespół Agentów</button>
        </form>

        <div id="loading" class="loading">⏳ Agenci pracują nad analizą i testami (to może chwilę potrwać)...</div>

        {{ current_result_section }}

        <h2>📊 Historia testów w obecnej sesji</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 15%;">Czas</th>
                    <th style="width: 45%;">Prompt (Fragment)</th>
                    <th style="width: 20%;">Security Guard</th>
                    <th style="width: 20%;">Status / Wynik</th>
                </tr>
            </thead>
            <tbody>
                {{ history_rows }}
            </tbody>
        </table>
    </div>

    <script>
        function showLoading() {
            document.getElementById('loading').style.display = 'block';
        }
    </script>
</body>
</html>
"""

def execute_agent_workflow(prompt_text: str, source: str = "Web UI") -> dict:
    initial_state: QAState = {
        "raw_requirements": prompt_text,
        "analyzed_requirements": "",
        "test_cases": [],
        "execution_results": [],
        "bug_reports": [],
        "review_status": "",
        "audit_trail": [],
        "is_attack": False,
        "threat_reason": ""
    }

    app_graph = create_qa_orchestrator()
    final_state = app_graph.invoke(initial_state)
    
    # Zapisz do historii sesji
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    is_attack = final_state.get("is_attack", False)
    status = "ODRZUCONY (Atak)" if is_attack else final_state.get('review_status', 'N/A')
    
    history_entry = {
        "time": timestamp,
        "prompt": prompt_text[:70] + ("..." if len(prompt_text) > 70 else ""),
        "is_attack": is_attack,
        "status": status,
        "reason": final_state.get("threat_reason", "")
    }
    
    TEST_HISTORY.insert(0, history_entry) # Najnowsze na górze
    if len(TEST_HISTORY) > 15: # Ogranicz do 15 ostatnich wpisów
        TEST_HISTORY.pop()
        
    return final_state

def render_history_html() -> str:
    if not TEST_HISTORY:
        return "<tr><td colspan='4' style='text-align: center; color: #888;'>Brak historii testów w tej sesji. Uruchom coś!</td></tr>"
    
    rows = []
    for h in TEST_HISTORY:
        if h["is_attack"]:
            guard_badge = "<span class='badge-attack'>Wykryto Atak 🚨</span>"
            status_badge = f"<span class='badge-attack'>{h['status']}</span>"
        else:
            guard_badge = "<span class='badge-safe'>Czysto ✅</span>"
            status_badge = f"<span class='badge-approved'>{h['status']}</span>"
            
        rows.append(f"""
            <tr>
                <td>{h['time']}</td>
                <td><code>{h['prompt']}</code></td>
                <td>{guard_badge}</td>
                <td>{status_badge}</td>
            </tr>
        """)
    return "".join(rows)

@app.get("/", response_class=HTMLResponse)
async def home():
    history_html = render_history_html()
    return HTML_TEMPLATE.replace("{{ current_result_section }}", "").replace("{{ history_rows }}", history_html)

@app.post("/run-agent", response_class=HTMLResponse)
async def run_agent(user_story: str = Form(None), file: UploadFile = File(None)):
    final_prompt = ""
    
    if file and file.filename:
        filename = file.filename.lower()
        file_bytes = await file.read()
        if filename.endswith(".pdf"):
            pdf_reader = PdfReader(io.BytesIO(file_bytes))
            extracted_text = [page.extract_text() for page in pdf_reader.pages if page.extract_text()]
            final_prompt = "\n".join(extracted_text)
        else:
            final_prompt = file_bytes.decode("utf-8", errors="ignore")
    elif user_story and user_story.strip():
        final_prompt = user_story.strip()
    else:
        final_prompt = "Użytkownik musi mieć możliwość zresetowania hasła za pomocą adresu e-mail."

    final_state = execute_agent_workflow(final_prompt, source="Web UI")
    review_status = final_state.get('review_status', 'N/A')
    
    if final_state.get('is_attack'):
        atak_powod = final_state.get('threat_reason')
        report_text = f"=== RAPORT ZESPOŁU QA & RED TEAM ===\n\nStatus Przeglądu: ODRZUCONY (Wykryto zagrożenie)\n\n[!] BRAMKA BEZPIECZEŃSTWA WYKRYŁA ATAK!\nPowód: {atak_powod}"
    else:
        analyzed_reqs = final_state.get('analyzed_requirements', 'Brak danych')
        tc_texts = [f"- [{tc.get('id')}] ({tc.get('type')}): {tc.get('desc')}" for tc in final_state.get('test_cases', [])]
        exec_texts = [f"- Test {res.get('tc_id')}: Status -> {res.get('status')}" for res in final_state.get('execution_results', [])]
        bug_texts = [f"- [{bug.get('bug_id')}] Severity: {bug.get('severity')}" for bug in final_state.get('bug_reports', [])]

        report_text = f"""=== RAPORT ZESPOŁU QA & RED TEAM ===
Status Przeglądu: {review_status}

--- 1. ANALIZA WYMAGAN ---
{analyzed_reqs}

--- 2. PRZYPADKI TESTOWE ---
{chr(10).join(tc_texts) if tc_texts else 'Brak'}

--- 3. WYNIKI WYKONANIA ---
{chr(10).join(exec_texts) if exec_texts else 'Brak'}

--- 4. RAPORTY O BŁĘDACH ---
{chr(10).join(bug_texts) if bug_texts else 'Brak błędów'}
"""

    with open("raport_qa.md", "w", encoding="utf-8") as f:
        f.write(report_text)

    current_result_section = f"""
    <div class="result-box">
        <h2>Wynik ostatniego uruchomienia:</h2>
        {report_text}
    </div>
    """

    history_html = render_history_html()
    return HTML_TEMPLATE.replace("{{ current_result_section }}", current_result_section).replace("{{ history_rows }}", history_html)

# --- API DLA SKRYPTU RED TEAM ---
@app.post("/api/v1/evaluate")
async def evaluate_prompt_api(payload: PromptRequest):
    if not payload.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt nie może być pusty.")
    
    final_state = execute_agent_workflow(payload.prompt, source="API RedTeam")
    
    return {
        "is_attack": final_state.get("is_attack", False),
        "threat_reason": final_state.get("threat_reason", ""),
        "review_status": final_state.get("review_status", ""),
        "audit_trail": final_state.get("audit_trail", [])
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)