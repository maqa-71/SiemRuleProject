# SIEM Detection Rules

Detection-as-Code repository for Splunk and IBM QRadar.

## Structure

```text
.github/workflows/
├── deploy_splunk.yml
└── deploy_qradar.yml

splunk/
└── rules/
    ├── 01_lsass_memory_dump.yml
    ├── 02_kerberoasting.yml
    ├── ...
    └── 15_webshell_in_webroot.yml

qradar/
└── README.md
```

## Current status

- Splunk: 15 separate YAML rule files, all in `draft` status and disabled until lab validation.
- QRadar: rule content and API deployment are not configured yet.

## Workflow

1. Edit the relevant YAML rule in GitHub.
2. Pull requests validate all rule files and required fields.
3. After merge to `main`, a self-hosted runner creates or updates each Splunk saved search through the REST API.
4. Splunk is a deployment target; GitHub remains the source of truth.

## Required GitHub secrets

- `SPLUNK_HOST`
- `SPLUNK_TOKEN`
- `SPLUNK_VERIFY_SSL`

Never commit credentials, tokens, private keys or sensitive logs.
