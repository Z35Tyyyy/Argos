---

## Quick Start

Once Argos is installed, follow this three-step methodology to secure a directory:

1.  **Initialize the Baseline**: Establish the "Known-Good" state of your target directory.
    ```bash
    argos init /path/to/project --name v1.0
    ```
2.  **Continuous Monitoring**: Initiate the Watch engine to detect real-time drifts.
    ```bash
    argos watch /path/to/project
    ```
3.  **Audit and Explain**: Perform a deep-audit with AI-assisted classification of anomalies.
    ```bash
    argos check /path/to/project --explain
    ```

---

## Architecture Overview

Argos operates on a stateless-scan/stateful-comparison model. The system establishes a "Baseline" by computing immutable fingerprints for all target assets. Subsequent "Checks" compare the current environment against this baseline to identify drifts.

### Operation Pipeline
1. **Baseline Initialization**: Recursive traversal of the target directory to establish cryptographic and behavioral identity.
2. **Snapshot Comparison**: Delta analysis between the active state and a stored baseline.
3. **Semantic Inspection**: Deep analysis of code structural changes using Abstract Syntax Trees (AST).
4. **Behavioral Classification**: Heuristic evaluation of changes to determine intent and risk.
5. **Ledger Append**: Recording the event in an append-only, cryptographically chained audit log.

---

## Technical Specifications

### Cryptographic Foundation
Argos supports SHA-256 and SHA-512 algorithms for content hashing. The selection is configurable based on the required collision resistance and performance profiles of the target environment.

### Tamper-Evident Ledger
The audit log (Ledger) is implemented as a hash chain. Each entry $N$ contains a hash of its own data concatenated with the hash of entry $N-1$. This ensures that any modification, deletion, or reordering of the audit history results in a detectable break in the chain.

---

## Installation and Deployment

### Requirements
- Python 3.8 or higher
- SQLite 3.x

### Standard Installation
Install the package directly from the repository source:
```bash
pip install git+https://github.com/Z35Tyyyy/Argos.git
```

### Development/Source Deployment
For contributors or environments requiring source modifications:
```bash
git clone https://github.com/Z35Tyyyy/Argos.git
cd Argos
pip install -e .
```

### Recommended Deployment (Isolated Environment)
To avoid system-wide dependency conflicts and ensure binary availability on Windows, it is strongly recommended to use a Python Virtual Environment:

1.  **Initialize Environment**:
    ```bash
    python -m venv venv
    ```
2.  **Activation**:
    *   **PowerShell**: `.\venv\Scripts\Activate.ps1`
    *   **CMD**: `.\venv\Scripts\activate.bat`
    *   **Linux/macOS**: `source venv/bin/activate`
3.  **Local Installation**:
    ```bash
    pip install .
    ```

---

---

## Global Configuration

### Groq AI Integration
To enable the AI-assisted explanation feature (`--explain`), you must provide a valid Groq API key. Argos looks for this key in the `GROQ_API_KEY` environment variable.

#### Temporary (Session-only)
##### Windows (PowerShell)
```powershell
$env:GROQ_API_KEY = "your_api_key_here"
```

##### Windows (CMD)
```cmd
set GROQ_API_KEY=your_api_key_here
```

##### Unix/macOS (Bash/Zsh)
```bash
export GROQ_API_KEY="your_api_key_here"
```

#### Persistent Setup (Windows)
1. Search for **Environment Variables** in the Start Menu.
2. Under "User variables", click **New**.
3. Variable name: `GROQ_API_KEY`.
4. Variable value: Paste your key from [console.groq.com](https://console.groq.com).
5. Restart your terminal.

---

## Command Line Interface

### argos init [DIRECTORY]
Establishes a baseline snapshot for the specified directory.
- `--name [NAME]`: Identifier for the baseline (default: "default").
- `--algo [sha256|sha512]`: Selection of cryptographic hashing algorithm.
- `--db [PATH]`: Path to the SQLite baseline database.

### argos check [DIRECTORY]
Performs a comparison between the active filesystem and a baseline.
- `--baseline [NAME]`: Specifies the baseline identifier to use for comparison.
- `--explain`: Enables AI-assisted semantic analysis of modifications (requires GROQ_API_KEY).
- `--output [terminal|json|csv|html]`: Sets the report serialization format.
- `--db [PATH]`: Path to the SQLite baseline database.

### argos watch [DIRECTORY]
Initiates continuous monitoring mode.
- `--baseline [NAME]`: Specifies the baseline identifier to use.
- `--interval [SECONDS]`: Frequency of recursive scans (default: 60 seconds).
- `--explain`: Enables AI-assisted analysis for real-time monitoring.
- `--db [PATH]`: Path to the SQLite baseline database.

### argos update [DIRECTORY]
Promotes the current filesystem state to the baseline. Intended for use after authorized deployments or system updates.
- `--baseline [NAME]`: Specifies the baseline identifier to update.
- `--db [PATH]`: Path to the SQLite baseline database.

### argos report
Displays the historical audit ledger.
- `--db [PATH]`: Path to the SQLite baseline database.
- `--since [TIMESTAMP]`: Filter entries by ISO timestamp.
- `--format [terminal|json|html]`: Serialization format for the ledger report.

### argos verify-chain
Performs a full cryptographic validation of the audit ledger chain.
- `--db [PATH]`: Path to the SQLite baseline database.

---

## Intelligent Classification Model

Argos utilizes a multi-factor classification engine to assign risk severity to detected modifications.

### CRITICAL (Risk Level: High)
Modifications categorized as Critical indicate a high probability of malicious intent or severe system instability.
- **System Perimeter Breach**: Modifications within protected directories (e.g., /etc, /bin, System32).
- **Executable Entropy/Signature Drift**: Changes to binaries or executable scripts.
- **Risky Logic Injections**: Addition of dynamic execution calls (exec, eval, os.system) in Python code.
- **Ransomware Indicators**: Entropy shifts exceeding 2.0, suggesting unauthorized encryption.

### SUSPICIOUS (Risk Level: Medium)
Modifications that represent unusual behavior requiring manual audit.
- **Credential/Secret Access**: Modifications to files containing security-sensitive keywords (token, key, password).
- **Network Capability Addition**: Import of networking modules into scripts previously lacking network access.
- **Subtle Obfuscation**: Entropy shifts between 1.0 and 2.0.

### ROUTINE (Risk Level: Low)
Standard maintenance activity, documentation updates, or non-security-sensitive code refactoring.

---

## Behavioral Fingerprinting

### Shannon Entropy Analysis
Argos measures the randomness of file data to detect encrypted or obfuscated payloads.
- **Range 0.0-4.0**: Patterned data (source code, text).
- **Range 6.0-8.0**: Compressed, encrypted, or packed binary data.

### AST-Based Logic Tracking
For Python assets, Argos utilizes the `ast` module to perform non-textual diffing. This allows the system to distinguish between harmless formatting changes and significant functional logic shifts.

---

## System Configuration

### .argos.yml
A project-level configuration file for defining scan defaults.
```yaml
algorithm: sha512
exclude_patterns:
  - "logs/*"
  - "*.tmp"
watch_interval: 30
```

### .argosignore
Git-style ignore patterns for excluding specific assets from the monitoring perimeter.
```text
node_modules/
venv/
*.log
```

---

## Audit Ledger Integrity

Argos provides a mathematical guarantee of audit trail continuity. Use the `verify-chain` command to ensure that the historical record of file modifications has not been tampered with.

---

## License

Distributed under the MIT License. See `LICENSE` for details.

---

Built with <3 by z35tyyyy