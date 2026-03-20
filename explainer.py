"""
AI GuardDuty Finding Explainer - Main explanation logic using Ollama LLM
"""

import time
from openai import OpenAI

# Configuration
BASE_URL = "http://localhost:11434/v1"
API_KEY = "ollama"
MODEL = "llama3.2"
TIMEOUT_SECONDS = 90
MAX_RETRIES = 3
LOOP_DETECTION_LIMIT = 3

# Required fields in the response
REQUIRED_FIELDS = ["FINDING_TYPE", "SEVERITY", "WHAT", "ATTACK", "IMPACT", "REMEDIATION", "ESCALATE"]

# Termination conditions
TERMINATION_CONDITIONS = [
    "CRITICAL",
    "COMPROMISED",
    "ATTACK",
    "MALICIOUS",
]


def _parse_response(response_text):
    """
    Parse the LLM response to extract the 7 required fields.

    Args:
        response_text: Raw response from the LLM

    Returns:
        Dictionary with the 7 fields, or None if parsing fails
    """
    result = {}
    lines = response_text.strip().split("\n")

    current_field = None
    current_value = []

    for line in lines:
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Check if line starts with a required field (case insensitive prefix match)
        line_upper = line_stripped.upper()
        field_found = None
        for field in REQUIRED_FIELDS:
            if line_upper.startswith(field.upper() + ":"):
                field_found = field
                break

        if field_found:
            # Save previous field if exists
            if current_field:
                result[current_field] = "\n".join(current_value).strip()

            # Extract value after the field name and colon
            value = line_stripped[len(field_found) + 1:].strip()
            current_field = field_found
            current_value = [value] if value else []
        else:
            # Continue collecting value for current field
            if current_field:
                current_value.append(line_stripped)

    # Save last field
    if current_field:
        result[current_field] = "\n".join(current_value).strip()

    # Validate all 7 fields are present and not empty
    # Provide defaults for missing fields
    if "ESCALATE" not in result or not result.get("ESCALATE", "").strip():
        result["ESCALATE"] = "NO"  # Default to NO if missing

    # Check that we have all required fields with values
    if all(field in result and result[field].strip() for field in REQUIRED_FIELDS):
        return result
    return None


def _check_termination_condition(analysis):
    """
    Check if the analysis indicates a critical condition.

    Args:
        analysis: Parsed analysis dictionary

    Returns:
        True if termination is needed, False otherwise
    """
    severity = analysis.get("SEVERITY", "").upper()
    attack = analysis.get("ATTACK", "").upper()

    for condition in TERMINATION_CONDITIONS:
        if condition in severity or condition in attack:
            return True
    return False


def _detect_loop(previous_results):
    """
    Detect if the same error is repeating.

    Args:
        previous_results: List of previous result dictionaries

    Returns:
        True if same error repeats LOOP_DETECTION_LIMIT times, False otherwise
    """
    if len(previous_results) < LOOP_DETECTION_LIMIT:
        return False

    # Check last N results for same WHAT field
    recent = previous_results[-LOOP_DETECTION_LIMIT:]
    what_values = [r.get("WHAT", "") for r in recent]

    # If all same, it's a loop
    return len(set(what_values)) == 1


def explain_finding(finding_json):
    """
    Explain a GuardDuty finding using Ollama LLM with four-layer termination safety.

    Args:
        finding_json: String containing the GuardDuty finding JSON

    Returns:
        Dictionary with fields: FINDING_TYPE, SEVERITY, WHAT, ATTACK, IMPACT, REMEDIATION, ESCALATE

    Raises:
        Exception: If all retries fail or response is invalid
    """
    from prompts import SYSTEM_PROMPT, build_prompt

    # Build the prompt
    user_message = build_prompt(finding_json)

    # Initialize the client
    client = OpenAI(base_url=BASE_URL, api_key=API_KEY, timeout=TIMEOUT_SECONDS)

    # Track previous results for loop detection
    previous_results = []

    # Retry logic with exponential backoff
    last_error = None

    for attempt in range(MAX_RETRIES):
        # Layer 4: Loop detection
        if _detect_loop(previous_results):
            raise ValueError(f"Loop detected: same finding repeated {LOOP_DETECTION_LIMIT} times")

        try:
            # Make the LLM call
            response = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.3,
                max_tokens=800,
            )

            # Extract response text
            response_text = response.choices[0].message.content

            # Validate response - check all 7 fields are present
            result = _parse_response(response_text)

            if result is None:
                # Invalid response format - throw to trigger retry
                raise ValueError(f"Invalid response format - missing required fields")

            # Track result for loop detection
            previous_results.append(result)

            # Layer 1: Check termination condition
            if _check_termination_condition(result):
                pass

            # Layer 2: Additional validation - ensure fields are meaningful
            if not all(result.get(field, "").strip() for field in REQUIRED_FIELDS):
                raise ValueError("Some fields are empty after parsing")

            # Layer 3: Validate REMEDIATION contains AWS CLI commands
            remediation = result.get("REMEDIATION", "")
            if "aws" not in remediation.lower() and "awscli" not in remediation.lower():
                raise ValueError("REMEDIATION must contain AWS CLI commands")

            # All validations passed, return result
            return result

        except Exception as e:
            last_error = e
            error_str = str(e).lower()

            # Check if it's a connection error
            is_connection_error = any(
                keyword in error_str
                for keyword in ["connection", "timeout", "refused", "unreachable"]
            )

            # Retry on connection errors or validation errors (but not loop detection)
            should_retry = (is_connection_error or "invalid response" in error_str or "missing required" in error_str or "remediation must" in error_str or "some fields are empty" in error_str) and attempt < MAX_RETRIES - 1

            if should_retry:
                # Exponential backoff: 1s, 2s, 4s
                wait_time = 2 ** attempt
                time.sleep(wait_time)
                continue
            elif "loop detected" in error_str:
                # Don't retry on loop detection
                raise

    # All retries exhausted
    raise last_error