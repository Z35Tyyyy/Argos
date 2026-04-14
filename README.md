# 👁 Argos — The Hundred-Eyed Guardian

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![AI: Groq](https://img.shields.io/badge/AI-Groq%20Llama%203.3-cyan.svg)](https://groq.com/)

**Argos** is a production-quality File Integrity Monitoring (FIM) tool designed for modern infrastructure. Named after the giant from Greek mythology who had a hundred eyes, Argos is always watching, using cryptographic chaining and AI-powered behavioral analysis to protect your system's perimeter.

---

## ✨ Features at a Glance

| Feature | Description |
| :--- | :--- |
| **🛡 Cryptographic Hash Chain** | Tamper-evident audit ledger using SHA-256/512. |
| **🧠 AI Behavioral Analysis** | Integration with Groq (Llama 3.3) for semantic anomaly detection. |
| **📂 Semantic Diffing** | Understands code structural changes (Imports, Functions) via AST analysis. |
| **⏱ Continuous Watch** | High-performance background monitoring with configurable intervals. |
| **📊 Multi-Format Reports** | Export your findings in Terminal (Rich), JSON, CSV, or HTML. |

---

## 🧭 Navigation Guide

<table width="100%">
  <tr>
    <td width="30%" valign="top">
      <h3>GUIDE</h3>
      <ul>
        <li><a href="GUIDE.md#🏛-how-it-works">How It Works</a></li>
        <li><a href="GUIDE.md#🚀-installation">Installation</a></li>
        <li><a href="GUIDE.md#⚙️-configuration">Configuration</a></li>
        <li><a href="GUIDE.md#👁-the-ai-eye-groq-integration">The AI "Eye"</a></li>
      </ul>
      <h3>COMMANDS</h3>
      <ul>
        <li><code>argos init</code></li>
        <li><code>argos check</code></li>
        <li><code>argos watch</code></li>
        <li><code>argos report</code></li>
        <li><code>argos verify-chain</code></li>
      </ul>
    </td>
    <td width="70%" valign="top">
      <h3>🚀 Quick Start</h3>
      <p>Initialize your first baseline and start monitoring in seconds.</p>
      <pre><code># Install Argos
pip install git+https://github.com/youruser/argos.git

# Establish a "known-good" baseline
argos init /path/to/project --name v1.0

# Check for unauthorized changes
argos check /path/to/project --explain</code></pre>
    </td>
  </tr>
</table>

---

## 🧠 Intelligent Classification

Argos doesn't just watch for changes; it understands them. Every modification is passed through a multi-stage classification engine that assigns a **Severity Tag** based on behavioral risk.

### 🔴 CRITICAL
*High-risk anomalies that require immediate investigation.*
- **System Tampering**: Modifications in protected directories like `/etc/`, `/bin/`, or Windows `System32`.
- **Executable Modification**: Any change to binary files or executable scripts (validated via binary signatures and extensions).
- **Risky Logic (Python)**: Addition of dangerous functions like `eval()`, `exec()`, or `os.system()` detected via AST analysis.
- **Entropy Spikes**: Sudden increases in data randomness (Delta > 2.0), typically indicating **ransomware encryption** or malware packing.

### 🟡 SUSPICIOUS
*Unusual patterns that warrant manual review.*
- **Secret Access**: Modifications to files containing keywords like `auth`, `token`, `key`, `password`, or `.env`.
- **Network Exfiltration**: Addition of connectivity modules (e.g., `socket`, `requests`, `httpx`) to code that previously lacked them.
- **Moderate Shifts**: Changes in entropy between 1.0 and 2.0, suggesting obfuscation or large data injections.

### 🟢 ROUTINE
*Normal development and maintenance activity.*
- Documentation updates, docstring changes, or standard refactoring that doesn't trigger security heuristics.

---

## 🔍 Behavioral Fingerprinting

Argos uses advanced techniques to look "inside" files rather than just comparing hashes.

### 📊 Shannon Entropy Analysis
Argos calculates the randomness of file contents on a scale of 0.0 to 8.0.
- **Low (0-4)**: Structured text, source code.
- **High (6-8)**: Encrypted data, compressed archives, or compiled binaries.
- **Detection**: By tracking entropy shifts over time, Argos can detect ransomware even if the file extension remains unchanged.

### 🌳 Python AST Analysis
For `.py` files, Argos performs deep semantic inspection:
- **Function/Class Tracking**: Detects when new functional blocks are added.
- **Import Auditing**: Keeps a ledger of third-party dependencies used by the script.
- **Call Graph Inspection**: Flags "risky" function calls that could be used for remote code execution.

### 🪟 Cross-Platform Precision (Windows Support)
Unlike standard tools that rely on the unreliable Unix `execute` bit on Windows, Argos uses **Signature-based Detection**:
- **Binary Check**: Inspects file headers for null-byte signatures.
- **Extension Awareness**: Recognizes platform-specific executables (`.exe`, `.bat`, `.ps1`, `.vbs`).
- **Path Normalization**: Ensures that security rules work identically across Windows and Linux environments.

---

## 🔒 Security In-Depth

Argos is built for environments where the audit trail itself might be an attack target. The **Tamper-Evident Ledger** ensures that if an attacker gains access to the system and tries to delete the logs of their file modifications, the cryptographic chain will break, alerting administrators immediately during the next `verify-chain` check.

[Read the Security Architecture →](GUIDE.md#🔒-security-architecture)

---

## 📄 License
Distributed under the MIT License. See `LICENSE` for more information.

---
<p align="center">
  Built with ❤️ by the z35tyyyy
</p>