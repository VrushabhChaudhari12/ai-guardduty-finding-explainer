# AI GuardDuty Finding Explainer

> **AWS GuardDuty findings are cryptic. This tool makes them actionable.** Translates high-severity security findings into plain-English with exact AWS CLI remediation commands — reducing security triage time from 30+ minutes to seconds.

---

## The Problem This Solves

GuardDuty finding types like `UnauthorizedAccess:IAMUser/TorIPCaller` or `Backdoor:EC2/XORDDOS` are meaningless to engineers unfamiliar with AWS security. On-call engineers waste time looking up finding types, assessing severity, and drafting CLI remediation steps. This tool eliminates that manual process.

```bash
# Before: 30 minutes of documentation research + manual triage
# After:
python main.py --severity 7.0  # Explains all HIGH severity findings instantly
```

---

## Example Output

For a `UnauthorizedAccess:IAMUser/MaliciousIPCaller` finding (severity 8.0):

```
FINDING TYPE: Unauthorized API calls from known malicious IP
SEVERITY: HIGH (8.0/10)

WHAT HAPPENED:
An IAM user made API calls from an IP address in GuardDuty's threat intelligence
list. The calls targeted S3 and IAM services, suggesting credential exfiltration.

WHY IT MATTERS:
Compromised credentials can lead to data exfiltration, privilege escalation, and
persistent unauthorized access to your AWS environment.

IMMEDIATE ACTIONS:
1. Disable the compromised IAM user immediately
2. Rotate all access keys for the affected user
3. Review CloudTrail for actions taken with these credentials

AWS CLI COMMANDS:
aws iam update-login-profile --user-name [USER] --no-password-reset-required
aws iam delete-access-key --access-key-id [KEY_ID] --user-name [USER]
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=[USER]
```

---

## Supported Finding Types

| Category | Example Findings | Auto-Generated Remediation |
|----------|-----------------|----------------------------|
| **IAM / Credentials** | MaliciousIPCaller, TorIPCaller, ConsoleLoginSuccess | Disable user, rotate keys, review CloudTrail |
| **EC2 / Network** | PortProbeUnprotectedPort, XORDDOS, SSHBruteForce | Modify security groups, isolate instance |
| **S3** | UnauthorizedAccess, BucketPublicAccessGranted | Update bucket policy, enable Block Public Access |
| **Malware** | Execution:EC2/MaliciousFile | Quarantine instance, trigger GuardDuty scan |

---

## Architecture

```
GuardDuty finding JSON
        |
        v
  explainer.py
        +── Severity check: skip if < MIN_SEVERITY (default: 4.0)
        +── Build prompt with finding type, severity, resource info
        |
        v
  LLM call (Ollama/GPT-4)
        |
        +── Validate 6 required sections present
        +── Loop detection + exponential backoff retry
        |
        v
  reporter.py  ─── Format report + save to output/
        |
        v
  Plain-English explanation + AWS CLI commands
```

---

## Engineering Quality

| Feature | Implementation |
|---------|---------------|
| Config management | `config.py` — all settings via env vars with typed defaults |
| Structured logging | Python `logging` — timestamp, level, finding type, severity |
| Severity filtering | Configurable `MIN_SEVERITY` threshold (default 4.0) |
| Section validation | 6 required sections checked on every LLM response |
| Retry logic | Exponential backoff (2^n seconds), max 3 retries |
| Loop detection | Deduplicates identical outputs |
| CLI interface | `argparse` — `--severity`, `--output-json`, `--finding-types` |
| Error isolation | Per-finding try/except, continues processing on failures |

---

## Quick Start

### 1. Install Ollama + model
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama run llama3.2
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the explainer
```bash
# All mock findings
python main.py

# Only HIGH severity findings (7.0+)
python main.py --severity 7.0

# Export to JSON
python main.py --output-json findings-report.json
```

### 4. Configure (optional)
```bash
export MIN_SEVERITY=5.0      # Skip LOW severity findings
export LOG_LEVEL=DEBUG       # Verbose logging
export MODEL=llama3.2        # LLM model selection
```

---

## Project Structure

```
ai-guardduty-finding-explainer/
├── main.py              # CLI entry point — argparse, orchestration
├── explainer.py         # LLM call, section validation, retry + loop detection
├── prompts.py           # System prompt + finding-context message builder
├── config.py            # Centralized config with env var overrides
├── mock_findings.py     # Simulated GuardDuty findings (10 real finding types)
├── reporter.py          # Format and save explanations to output directory
└── requirements.txt     # openai
```

---

## Why This Matters (Resume Context)

This project demonstrates AI-assisted SecOps for a high-value on-call pain point:
- **Security domain knowledge**: understanding of GuardDuty finding taxonomy, IAM compromise patterns, EC2 network threats
- **Structured output validation**: 6 required sections validated per response — ensures actionable content every time
- **Real AWS CLI remediation**: generated commands use actual AWS CLI syntax with placeholder substitution (`[USER]`, `[KEY_ID]`, `[INSTANCE_ID]`)
- **Production safety**: severity filtering prevents noise, retry with backoff handles LLM latency spikes
- **On-call use case**: designed for 3am incident response — fast, unambiguous, actionable
