# MatrixGPT

Autonomous adversarial security war game demo. Red Team agents **actively exploit** vulnerabilities while Blue Team agents detect attacks and patch in real time.

## 🚀 Features

### Red Team
- **Active Exploitation**: Exploits vulnerabilities 3-5 times with real HTTP requests
- **Smart Attack Suggestions**: LLM suggests follow-up attacks based on findings
- **Pre-Scan System**: Efficiently discovers vulnerabilities before LLM analysis
- **Iterative Strategy**: Chains attacks for maximum impact

### Blue Team
- **Log Analysis**: Detects attack patterns in application logs
- **Automated Patching**: Generates and applies security fixes
- **Real-time Response**: Responds to attacks as they happen

### UI
- **Real-time Vulnerability Display**: Color-coded severity cards (CRITICAL/HIGH/MEDIUM)
- **Battle History**: Review past battles and their findings
- **WebSocket Updates**: Live event streaming during battles
- **Port Scan Info**: Shows discovered ports and tested endpoints

## 📋 Prerequisites

- Python 3.11+
- OpenAI API key with access to models (codex-mini-latest recommended)
- Git

## 🛠️ Quick Start

### 1. Clone and Setup

```bash
git clone https://github.com/vedantatrivedi/matrix-gpt.git
cd matrix-gpt
```

### 2. Start Sample App (Vulnerable Target)

```bash
cd sample-app
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The vulnerable app will run on **http://localhost:8001**

### 3. Start Orchestrator (in new terminal)

```bash
cd orchestrator
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Set your OpenAI API key
export OPENAI_API_KEY=sk-...  # On Windows: set OPENAI_API_KEY=sk-...

# Start the orchestrator
python -m orchestrator.main
```

Or use the convenience script:
```bash
python start_server.py
```

The orchestrator will run on **http://localhost:8000**

### 4. Open the UI

Navigate to **http://localhost:8000** in your browser.

Click **"Start Battle"** to begin!

## 🎮 How to Use

1. **Start a Battle**: Click "Start Battle" in the UI
2. **Watch Real-time**: See Red Team discover and exploit vulnerabilities
3. **View Vulnerabilities**: Check the color-coded vulnerability panel at the bottom
4. **Monitor Logs**: Watch both teams' activities in real-time
5. **Review Results**: Battle history is automatically saved

## ⚙️ Configuration

### Environment Variables

```bash
# Required
export OPENAI_API_KEY=sk-...

# Optional - Defaults are optimized for cost/performance
export TARGET_URL=http://localhost:8001          # Target application URL
export RED_TEAM_MODEL=codex-mini-latest          # Red Team model
export BLUE_TEAM_MODEL=codex-mini-latest         # Blue Team model
export RUN_MODE=demo                              # demo or prod
```

### Model Configuration

Default models are set to `codex-mini-latest` for optimal cost/performance.

You can customize in `orchestrator/agents/red_team.py` and `orchestrator/agents/blue_team.py`:
- `codex-mini-latest` - Fast, cost-effective (recommended)
- `gpt-4o-mini` - More capable, higher cost
- `gpt-4o` - Most capable, highest cost

## 🧪 Testing & Development

### Run Test Battle

Monitor token usage and optimization behavior:

```bash
python run_test_battle.py
```

### Run Tests

```bash
pytest tests/ -v
```

## 📚 Documentation

- **[ACTIVE_EXPLOITATION.md](ACTIVE_EXPLOITATION.md)** - How the active exploitation system works
- **[IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md)** - Implementation details
- **[OPTIMIZATION_COMPLETE.md](OPTIMIZATION_COMPLETE.md)** - Token optimization strategies

## 🏗️ Architecture

```
┌─────────────────┐         ┌─────────────────┐
│  Sample App     │◄────────│  Orchestrator   │
│  (Port 8001)    │         │  (Port 8000)    │
│                 │         │                 │
│  - Vulnerable   │         │  - Red Team     │
│  - Logs attacks │         │  - Blue Team    │
└─────────────────┘         │  - UI/WebSocket │
                            └─────────────────┘
```

### Red Team Flow

1. **Pre-Scan**: Discovers open ports and vulnerable endpoints
2. **LLM Analysis**: Parses findings and plans exploitation
3. **Active Exploitation**: Executes attacks 3-5 times per vulnerability
4. **Attack Suggestions**: Identifies follow-up attack vectors
5. **Structured Output**: Returns JSON with exploited vulnerabilities

### Blue Team Flow

1. **Log Monitoring**: Checks application logs for attack patterns
2. **Detection**: Identifies suspicious activity (SQL injection, XSS, etc.)
3. **Response**: Generates patches for discovered vulnerabilities
4. **Mitigation**: Applies fixes to secure the application

## 🐛 Troubleshooting

### Battle doesn't start
- Check that sample app is running on port 8001
- Verify OPENAI_API_KEY is set correctly
- Check logs in `logs/orchestrator.log`

### No vulnerabilities detected
- Ensure sample app is running
- Check Red Team logs in `logs/agents.log`
- Verify target URL is accessible

### Database errors
- Database files are included in repo for easier testing
- To reset: `rm orchestrator/matrixGPT.db` and restart

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

Check out the open PRs for active development!

## 📄 License

MIT License - See LICENSE file for details

## 🔗 Links

- **Repository**: https://github.com/vedantatrivedi/matrix-gpt
- **Issues**: https://github.com/vedantatrivedi/matrix-gpt/issues
