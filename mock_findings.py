"""
Mock AWS GuardDuty findings for testing the finding explainer
"""

import json
from datetime import datetime, timedelta

SCENARIOS = {
    "credential_exfil": {
        "id": "4c1a5b3d8e7f2a9c1d3e5f7b2a8c4d6e",
        "type": "UnauthorizedAccess:IAMUser/AnomalousBehavior",
        "severity": 8.0,
        "title": "IAM user making API calls from unusual country",
        "description": "API activity from a new remote country was observed for the IAM user \"admin-deploy-user\". This could indicate a compromised credential.",
        "resource_type": "AccessKey",
        "resource_id": "AKIAIOSFODNN7EXAMPLE",
        "region": "us-east-1",
        "account_id": "123456789012",
        "created_at": "2024-03-15T09:30:00Z",
        "count": 1,
        "action": {
            "actionType": "API_CALL",
            "api": "DescribeInstances",
            "serviceName": "ec2.amazonaws.com"
        },
        "actor": {
            "userName": "admin-deploy-user",
            "ipAddress": "185.220.101.45",
            "country": "Netherlands",
            "city": "Amsterdam"
        }
    },
    "port_probe": {
        "id": "7f2c9e1b4a8d5e3c6f9b2a1d8e5c7f3b",
        "type": "Recon:EC2/PortProbeUnprotectedPort",
        "severity": 2.0,
        "title": "EC2 instance port 22 being probed",
        "description": "EC2 instance i-0abc123def456 has port 22 (SSH) exposed to the internet and is being probed by a known scanner IP 45.33.32.156.",
        "resource_type": "Instance",
        "resource_id": "i-0abc123def456789",
        "region": "us-east-1",
        "account_id": "123456789012",
        "created_at": "2024-03-15T14:15:00Z",
        "count": 156,
        "action": {
            "actionType": "PORT_PROBE",
            "portProbeStatus": "DETECTED",
            "remoteIpAddress": "45.33.32.156"
        },
        "network": {
            "protocol": "tcp",
            "port": 22,
            "blocked": False
        }
    },
    "crypto_mining": {
        "id": "9e3d7c2b5f8a1e4d7c3b6a9f2e5d8c1b",
        "type": "CryptoCurrency:EC2/BitcoinTool.B",
        "severity": 8.0,
        "title": "EC2 instance communicating with Bitcoin mining pool",
        "description": "EC2 instance i-0def456abc789012 is communicating with known Bitcoin mining pool IP address 78.47.139.32. This could indicate cryptocurrency mining activity.",
        "resource_type": "Instance",
        "resource_id": "i-0def456abc789012",
        "region": "us-west-2",
        "account_id": "123456789012",
        "created_at": "2024-03-15T18:45:00Z",
        "count": 1,
        "action": {
            "actionType": "NETWORK_CONNECTION",
            "connectionDirection": "OUTBOUND",
            "remoteIpAddress": "78.47.139.32"
        },
        "network": {
            "protocol": "tcp",
            "port": 8333,
            "blocked": False
        }
    },
    "cloudtrail_disabled": {
        "id": "2b8e5f1c4a9d7e3f6c2b5a8d1e4f7c9b",
        "type": "Stealth:IAMUser/CloudTrailLoggingDisabled",
        "severity": 5.0,
        "title": "CloudTrail logging disabled",
        "description": "IAM user \"security-admin\" has disabled CloudTrail logging in the account. This could be an attacker trying to hide their activities.",
        "resource_type": "AccessKey",
        "resource_id": "AKIAJ7EXAMPLE2M2GHA",
        "region": "us-east-1",
        "account_id": "123456789012",
        "created_at": "2024-03-15T20:00:00Z",
        "count": 1,
        "action": {
            "actionType": "API_CALL",
            "api": "StopLogging",
            "serviceName": "cloudtrail.amazonaws.com"
        },
        "actor": {
            "userName": "security-admin",
            "ipAddress": "10.0.5.100",
            "country": "United States"
        }
    }
}


def get_finding(scenario):
    """
    Get GuardDuty finding JSON for a given scenario.

    Args:
        scenario: One of 'credential_exfil', 'port_probe', 'crypto_mining', 'cloudtrail_disabled'

    Returns:
        Formatted JSON string of the finding
    """
    finding = SCENARIOS.get(scenario, SCENARIOS["credential_exfil"])
    return json.dumps(finding, indent=2)