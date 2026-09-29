# QRadar Rules

This directory contains 10 QRadar rule definitions organized by MITRE ATT&CK tactic (execution, credential access, defense evasion, discovery, exfiltration, lateral movement, persistence, privilege escalation, process creation, system integrity).

Rule schema is aligned with the reference structure from [imile224/QRADAR-RULES](https://github.com/imile224/QRADAR-RULES): `id`, `title`, `status`, `description`, `author`, `date`, `tags`, `mitre`, `logsource`, `qradar`, `aql`, `falsepositives`, `level`.

## Structure

```text
qradar/
├── rules/                  # 10 JSON rule definitions
├── deploy_qradar.py        # Future QRadar Ariel API integration
├── requirements.txt
└── README.md
```

## Current state

- GitHub Actions validates all JSON files on push and pull request.
- The API integration code is present but safely skips execution while secrets are absent.
- No QRadar host, API key, SEC token, or deployment secret is configured yet.
- No rule has been validated in a QRadar lab.

## Future GitHub configuration

When the QRadar lab is available, configure:

- `QRADAR_HOST` — repository secret
- `QRADAR_SEC_TOKEN` — repository secret
- `QRADAR_VERIFY_SSL` — repository secret (`true` recommended with a trusted certificate)
- `QRADAR_API_VERSION` — repository variable, after confirming the installed QRadar version

The current script submits each rule's AQL to the Ariel Search API and confirms that it executes. Ariel search execution does **not** create native CRE correlation rules. Native CRE or content-extension deployment must be implemented after the QRadar version and supported API/import method are confirmed.
