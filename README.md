
# 🛡️ ThreatPipe v2: Autonomous SIFT IR Agent with MCP

> **FIND EVIL! Hackathon Submission** | Pattern: Multi-Agent Framework (LangGraph) + Custom MCP Server

An autonomous AI incident response agent that classifies logs, investigates artifacts with SIFT tools via a guarded MCP server, self-corrects through 4-lens cross-referencing, and predicts attacker next moves using a persistent behavioral graph.

---

## 📐 Architecture Diagram

![ThreatPipe v2 Architecture](images/archi.svg)

*🛑 **Red solid boxes** = Architectural Guardrails (code-enforced, cannot be bypassed by LLM)*
*🔵 **Blue dotted boxes** = Prompt-Based (LLM reasoning, can vary)*
*⚪ **Gray boxes** = Deterministic Code (regex, rules, filesystem checks — no LLM)*

---

## ✨ Key Features

- 🧠 **LLM-Guided Triage:** Uses Mistral to instantly identify suspicious logs from noisy datasets.
- 🔬 **Real SIFT Tool Execution:** Runs actual forensic tools (`strings`, `file`, `grep`, `fls`) via subprocess.
- 🛑 **MCP Architectural Guardrails:** Agent physically cannot run destructive commands (`rm`, `dd`) due to a strict MCP tool allowlist.
- 🔄 **Self-Correcting Loop:** If confidence is low, the agent autonomously retries with an alternate SIFT tool (up to 3 cycles).
- 👁️ **4-Lens Cross-Referencing:** Forces the LLM to analyze evidence from Hacker, Temporal, Kill Chain, and Analyst perspectives before giving a verdict.
- 🕸️ **Persistent Hacker Mindset Graph:** Tracks attacker IPs across sessions, calculates risk scores, and predicts their next MITRE ATT&CK move.
- 📊 **Interactive SOC Dashboard:** Streamlit UI to upload logs, view verdicts, and explore attack graphs.

---

## 🐧 System Requirements

**✅ Recommended OS: Debian / Ubuntu (Native SIFT Environment)**
This project is designed to run on the SANS SIFT Workstation, which is built on Ubuntu (Debian-based). It will run smoothly on any Debian/Ubuntu system where SIFT forensic tools are available in the `PATH`.

> ⚠️ **Note for Windows/macOS Users:** The core pipeline will run, but SIFT tools like `fls`, `mmls`, and `mactime` may not be available natively. For the full experience, use a Debian/Ubuntu VM or WSL2.

### Prerequisites
- Python 3.10+
- Mistral API Key ([Get one here](https://console.mistral.ai/))
- Git

---

## 🚀 Quick Start (5 Minutes)

### 1. Clone the Repository
```bash
git clone https://github.com/Prathameshsci369/ThreatPipe-v2-Autonomous-SIFT-IR-Agent-with-MCP.git
cd ThreatPipe-v2
```

### 2. Run the One-Click Setup
This script will create a virtual environment, install Python dependencies, create forensic test files on disk, and generate test attack logs.

```bash
chmod +x setup.sh
./setup.sh
```

### 3. Set your API Key
```bash
export MISTRAL_API_KEY='your-mistral-api-key-here'
```

### 4. Launch the Dashboard 📊
```bash
source venv/bin/activate
streamlit run dashboard.py
```
Open your browser to `http://localhost:8501`, upload the generated `realistic_attack.log`, and click **🚀 Run Analysis**!

---

## 💻 CLI & MCP Server Usage

### Run the CLI Pipeline
To run the full pipeline directly in your terminal:
```bash
source venv/bin/activate
export MISTRAL_API_KEY='your-mistral-api-key-here'
python stream_run.py realistic_attack.log
```

### Run the MCP Server 🌐
To expose ThreatPipe as a REST API for external tools (like Claude Desktop or curl):
```bash
source venv/bin/activate
uvicorn mcp_server:app --host 0.0.0.0 --port 9000 --reload
```

**Test the MCP Server:**
```bash
curl -X POST http://localhost:9000/investigate \
  -H "Content-Type: application/json" \
  -d '{"log_line": "192.168.1.55 - - [16/Apr/2026:03:14:25] \"GET /uploads/shell.php?cmd=whoami HTTP/1.1\" 200"}'
```

---

## 🔒 Security & MCP Guardrails

In incident response, evidence integrity is paramount. ThreatPipe enforces safety through **architectural guardrails**, not just prompt-based instructions.

### How the MCP Tool Layer Protects Evidence
Instead of giving the LLM an open shell (`execute_shell_cmd`), `agent.py` routes all tool requests through `mcp_tools.py`:

1. **🛑 Tool Allowlist:** The agent can only call read-only forensic tools (`strings`, `file`, `grep`, `fls`, `sha256sum`, `volatility`). Destructive commands (`rm`, `dd`, `shred`, `mkfs`) are physically impossible to execute because they are not in the `ALLOWED_SIFT_TOOLS` dictionary.
2. **✂️ Output Truncation:** SIFT tools can dump megabytes of text, crashing the LLM's context window. The MCP layer truncates output to 5KB before returning it to the agent.
3. **🛡️ Path Validation:** Prevents path traversal attacks by validating artifact paths before execution.

> *If the LLM hallucinates a destructive command, the MCP server blocks it. If the model ignores read-only rules, the architecture enforces them.*

---

## 📁 Project Structure

```
ThreatPipe-v2/
├── agent.py                  # 🧠 LangGraph 5-node pipeline + self-correction loop
├── mcp_tools.py              # 🛑 MCP Tool Layer (architectural guardrails)
├── mcp_server.py             # 🌐 FastAPI MCP Server (REST endpoints)
├── dashboard.py              # 📊 Streamlit SOC Dashboard
├── stream_run.py             # ⌨️ CLI pipeline orchestrator
├── log_stream.py             # 🔍 Stage 1: LLM log classifier
├── trigger_parser.py         # ⚙️ Raw log → StructuredTrigger (9 formats)
├── tool_selector.py          # 🛠️ Deterministic SIFT tool selection
├── stage_classifier.py       # 🎯 Attack stage classification (MITRE-aligned)
├── hacker_mindset_graph.py   # 🕸️ Persistent attacker behavior graph
├── mindset_analyzer.py       # 🚨 LLM campaign analysis + SOC alerts
├── evidence_graph.py         # 🔗 Per-session forensic graph (SQLite + NetworkX)
├── schemas.py                # 📋 Pydantic models + LangGraph state
├── config.py                 # ⚙️ YAML config + LLM factory
├── config.yaml               # 📄 Configuration values
├── logger.py                 # 📝 Structured logging system
├── setup_test_evidence.py    # 🏗️ Creates real forensic files on disk
├── generate_test_logs.py     # 📝 Generates realistic attack logs
├── setup.sh                  # 🚀 One-click setup script
├── requirements.txt          # 📦 Python dependencies
├── LICENSE                   # ⚖️ MIT License
├── architecture_diagram.md   # 📐 Architecture + security boundaries
├── dataset_documentation.md  # 📊 Dataset details
├── accuracy_report.md        # 🎯 Accuracy self-assessment
└── images/
    └── archi.svg             # 🖼️ Architecture diagram image
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built with ❤️ for the <strong>FIND EVIL! Hackathon</strong>
</p>


