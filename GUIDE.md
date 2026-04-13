# 📖 Argos Technical Guide

Welcome to the official documentation for **Argos — the hundred-eyed guardian**. This guide provides a deep dive into the features, configuration, and internal mechanics of the Argos File Integrity Monitoring (FIM) tool.

---

## 🏛 How It Works

Argos operates on the principle of **Snapshot Comparison**. 

1.  **Baseline Mode**: You scan a "known-good" directory. Argos computes cryptographic hashes and behavioral fingerprints for every file and stores them in a tamper-evident database.
2.  **Check Mode**: You scan the directory again later. Argos compares the current state against the baseline.
3.  **Semantic Analysis**: If a Python file changes, Argos doesn't just see a hash mismatch; it analyzes the code's structure (AST) to detect new functions, imports, or logic shifts.
4.  **Audit Trail**: Every action is recorded in an append-only ledger where each entry is cryptographically chained to the previous one.

---

## 🚀 Installation

Ensure you have **Python 3.8+** installed.

### Standard Installation
```bash
pip install git+https://github.com/youruser/argos.git
```

### Development Mode
```bash
git clone https://github.com/youruser/argos.git
cd argos
pip install -e .
```

---

## 🛠 Command Reference

### `argos init [DIRECTORY]`
Establish a baseline for a directory.
- `--name [NAME]`: Name the snapshot (default: "default").
- `--algo [sha256|sha512]`: Choose hashing algorithm.
- `--db [PATH]`: Custom path for the SQLite database.

### `argos check [DIRECTORY]`
Compare the current state against a baseline.
- `--baseline [NAME]`: The baseline to compare against.
- `--explain`: **AI Mode.** Uses Groq to explain *why* a change might be suspicious.
- `--output [terminal|json|csv|html]`: Format the report.

### `argos watch [DIRECTORY]`
Continuous monitoring mode. Argos will run a check every X seconds.
- `--interval [SECONDS]`: Frequency of scans (default: 60).
- `--explain`: Enable AI explanations for real-time monitoring.

### `argos update [DIRECTORY]`
Update a baseline to reflect the current state (useful after intentional deployments).

### `argos report`
Display the **Tamper-Evident Audit Ledger**. This shows who ran what scan and when.

### `argos verify-chain`
Verifies the cryptographic integrity of the audit ledger. If someone edits the database manually, this command will detect the break in the chain.

---

## ⚙️ Configuration

### `.argos.yml`
You can place a `.argos.yml` in your project root to set defaults.
```yaml
algorithm: sha512
exclude_patterns:
  - "logs/*"
  - "*.tmp"
include_extensions:
  - ".py"
  - ".js"
  - ".env"
watch_interval: 30
```

### `.argosignore`
Standard gitignore-style file to exclude files/folders from scans.
```text
# Exclude heavy dependencies
node_modules/
venv/
*.log
.DS_Store
```

---

## 👁 The AI Eye (Groq Integration)

Argos integrates with **Groq (Llama 3.3)** to provide semantic context for security anomalies. 

### Setup
1. Get a free API key at [console.groq.com](https://console.groq.com).
2. Set it in your environment:
   ```bash
   export GROQ_API_KEY="your_actual_key"
   ```

### What it detects:
- **Entropy Shifts**: Detects if a file was encrypted (ransomware) or filled with random data (malware).
- **Semantic Logic**: If you change a function name or add a suspicious import (e.g., `os`, `subprocess`), Argos's AI explains the risk in plain English.

---

## 🔒 Security Architecture

### Tamper-Evident Ledger
Argos uses a **Cryptographic Hash Chain** for its audit log. 
- Each entry contains a `record_hash`.
- The `record_hash` of Entry N is computed from: `(Entry N data + Hash of Entry N-1)`.
- If any previous entry is deleted or modified, the entire chain after it becomes invalid.

Use `argos verify-chain` to ensure your audit trail is untainted.
