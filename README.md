# AI GuardDuty Finding Explainer

AI-powered AWS GuardDuty finding explainer for security teams.

## Overview

Translates high-severity GuardDuty findings into plain-English explanations with exact AWS CLI remediation steps.
Reduces security triage time for engineers unfamiliar with GuardDuty finding types.

## Features

- **Plain-English Explanations**: Translates technical security findings into actionable insights
- **Exact Remediation**: Provides real AWS CLI commands that can be copied and executed
- **Severity Classification**: CRITICAL / HIGH / MEDIUM / LOW ratings
- **Escalation Guidance**: YES/NO for immediate security team paging

## Stack

- Python
- Ollama (localhost:11434)
- llama3.2 model

## Setup

1. Ensure Ollama is running with llama3.2 model:
   ```bash
   ollama run llama3.2
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Run

```bash
py main.py
```

This will explain four sample GuardDuty finding scenarios:
- credential_exfil
- port_probe
- crypto_mining
- cloudtrail_disabled