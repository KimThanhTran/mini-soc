"""The MITRE ATT&CK names the shipped rules refer to (Enterprise matrix, tactic order of the matrix)."""

TACTICS = [
    ("reconnaissance", "Reconnaissance"), ("resource_development", "Resource Development"),
    ("initial_access", "Initial Access"), ("execution", "Execution"), ("persistence", "Persistence"),
    ("privilege_escalation", "Privilege Escalation"), ("defense_evasion", "Defense Evasion"),
    ("credential_access", "Credential Access"), ("discovery", "Discovery"), ("lateral_movement", "Lateral Movement"),
    ("collection", "Collection"), ("command_and_control", "Command and Control"), ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]

TECHNIQUES = {
    "T1078": "Valid Accounts",
    "T1098": "Account Manipulation",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1133": "External Remote Services",
    "T1190": "Exploit Public-Facing Application",
    "T1548.003": "Sudo and Sudo Caching",
    "T1595": "Active Scanning",
    "T1595.002": "Vulnerability Scanning",
}
