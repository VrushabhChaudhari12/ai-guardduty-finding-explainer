"""
AI GuardDuty Finding Explainer - Main entry point

Runs all four GuardDuty finding scenarios and prints formatted security reports.
"""

from mock_findings import get_finding
from explainer import explain_finding
from reporter import print_security_report


# Define the scenarios to run
SCENARIOS = [
    "credential_exfil",
    "port_probe",
    "crypto_mining",
    "cloudtrail_disabled",
]


def run_scenario(scenario_name):
    """
    Run a single scenario: get finding, explain, and print report.

    Args:
        scenario_name: The scenario key
    """
    # Get finding JSON
    finding_json = get_finding(scenario_name)

    # Extract finding type and severity for display
    import json
    finding_data = json.loads(finding_json)
    finding_id = finding_data.get("id", "unknown")
    finding_type = finding_data.get("type", "unknown")
    severity = finding_data.get("severity", 0)

    # Print scenario name
    print(f"\n{'='*70}")
    print(f"  SCENARIO: {scenario_name.upper()}")
    print(f"  Finding Type: {finding_type}")
    print(f"  Severity: {severity}")
    print(f"{'='*70}\n")

    # Explain the finding
    result = explain_finding(finding_json)

    # Print security report
    print_security_report(result, finding_id)

    # Add separator between scenarios
    print("\n" + "=" * 70 + "\n")


def main():
    """Run all scenarios sequentially."""
    print("\n" + "=" * 70)
    print("  AI GUARDDUTY FINDING EXPLAINER")
    print("=" * 70 + "\n")

    for scenario in SCENARIOS:
        run_scenario(scenario)

    print("\nAll scenarios completed.")


if __name__ == "__main__":
    main()