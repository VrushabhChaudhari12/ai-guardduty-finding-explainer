"""
Main explainer logic for AI GuardDuty Finding Explainer.
Translates high-severity findings into plain-English with AWS CLI remediation steps.
"""
import logging
import time
from openai import OpenAI

import config
from prompts import SYSTEM_PROMPT, build_prompt

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger(__name__)


def explain_finding(finding: dict) -> str:
    """
    Generate a plain-English explanation with remediation steps for a GuardDuty finding.

    Args:
        finding: GuardDuty finding dictionary with type, severity, description, and resource info

    Returns:
        Structured explanation string with sections: FINDING TYPE, SEVERITY,
        WHAT HAPPENED, WHY IT MATTERS, IMMEDIATE ACTIONS, AWS CLI COMMANDS
    """
    severity = finding.get("Severity", 0)
    if severity < config.MIN_SEVERITY:
        log.info(
            "Skipping finding with severity %.1f (below threshold %.1f)",
            severity,
            config.MIN_SEVERITY,
        )
        return f"[SKIPPED] Severity {severity} below threshold {config.MIN_SEVERITY}"

    user_message = build_prompt(finding)

    client = OpenAI(
        base_url=config.BASE_URL,
        api_key=config.API_KEY,
        timeout=config.TIMEOUT_SECONDS,
    )

    previous_outputs: list[str] = []
    retry_count = 0

    while retry_count < config.MAX_RETRIES:
        try:
            log.info(
                "Explaining finding '%s' severity=%.1f (attempt %d/%d)",
                finding.get("Type", "unknown"),
                severity,
                retry_count + 1,
                config.MAX_RETRIES,
            )
            response = client.chat.completions.create(
                model=config.MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                temperature=config.TEMPERATURE,
                max_tokens=config.MAX_TOKENS,
            )

            explanation = response.choices[0].message.content.strip()

            # Validate required sections are present
            missing = [
                s for s in config.REQUIRED_SECTIONS
                if s not in explanation.upper()
            ]
            if missing:
                log.warning("Missing required sections: %s. Retrying...", missing)
                retry_count += 1
                time.sleep(2 ** retry_count)
                continue

            # Loop detection
            if explanation in previous_outputs:
                log.warning("Loop detected: identical output. Retrying...")
                previous_outputs.clear()
                retry_count += 1
                time.sleep(2 ** retry_count)
                continue

            previous_outputs.append(explanation)
            if len(previous_outputs) >= config.LOOP_DETECTION_THRESHOLD:
                log.warning("Loop detection threshold reached. Using last output.")
                return explanation

            log.info("Explanation generated successfully")
            return explanation

        except Exception as exc:
            log.error("Error during explanation: %s", exc)
            retry_count += 1
            if retry_count >= config.MAX_RETRIES:
                raise RuntimeError(
                    f"Failed after {config.MAX_RETRIES} retries: {exc}"
                ) from exc
            wait_time = 2 ** retry_count
            log.info("Retrying in %d seconds...", wait_time)
            time.sleep(wait_time)

    raise RuntimeError(
        f"Failed to explain finding after {config.MAX_RETRIES} retries"
    )
