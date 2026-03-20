"""
Reporter - Formats and prints GuardDuty finding explanations in security report format
"""

from datetime import datetime


def print_security_report(explanation, finding_id):
    """
    Print a formatted security report to console.

    Args:
        explanation: Dictionary with fields: FINDING_TYPE, SEVERITY, WHAT, ATTACK, IMPACT, REMEDIATION, ESCALATE
        finding_id: ID of the GuardDuty finding
    """
    severity = explanation.get("SEVERITY", "UNKNOWN").strip().upper()
    escalate = explanation.get("ESCALATE", "NO").strip().upper()
    finding_type = explanation.get("FINDING_TYPE", "UNKNOWN").strip()

    # Determine header based on severity
    if "CRITICAL" in severity:
        header_color = "\033[91m"  # Red
        header_text = "CRITICAL SECURITY FINDING"
    elif "HIGH" in severity:
        header_color = "\033[91m"  # Red
        header_text = "HIGH SEVERITY FINDING"
    elif "MEDIUM" in severity:
        header_color = "\033[93m"  # Yellow
        header_text = "MEDIUM SEVERITY FINDING"
    else:
        header_color = "\033[92m"  # Green
        header_text = "LOW SEVERITY FINDING"

    reset_ansi = "\033[0m"

    # Header
    header = "=" * 70
    print(header)
    print(f"{header_color}{'='*15} {header_text} {'='*15}{reset_ansi}")
    print(header)

    # Finding info
    print(f"\n*Finding ID:* {finding_id}")
    print(f"*Finding Type:* {finding_type}")

    # ESCALATE status prominent for CRITICAL/HIGH
    if "CRITICAL" in severity or "HIGH" in severity:
        if escalate == "YES":
            print(f"\n{header_color}*** ESCALATE: YES - PAGE SECURITY TEAM IMMEDIATELY ***{reset_ansi}")
        else:
            print(f"\n*ESCALATE:* {escalate}")

    # Divider
    divider = "-" * 70

    # Explanation fields
    print(divider)
    print(f"\n*SEVERITY:* {severity}")
    print(f"\n*WHAT:* {explanation.get('WHAT', 'N/A')}")
    print(f"\n*ATTACK:* {explanation.get('ATTACK', 'N/A')}")
    print(f"\n*IMPACT:* {explanation.get('IMPACT', 'N/A')}")

    # REMEDIATION with each command on its own line
    print(f"\n*REMEDIATION:*")
    remediation = explanation.get("REMEDIATION", "")
    # Split by newlines or numbered steps
    for line in remediation.split("\n"):
        line = line.strip()
        if line:
            print(f"  {line}")

    # ESCALATE for non-CRITICAL/HIGH
    if "CRITICAL" not in severity and "HIGH" not in severity:
        print(f"\n*ESCALATE:* {escalate}")

    # Footer with timestamp
    print("\n" + divider)
    footer = "=" * 70
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f" _Analysis completed at {timestamp}_ ")
    print(footer)
    print()