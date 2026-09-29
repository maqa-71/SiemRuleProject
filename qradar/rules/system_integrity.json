{
  "id": "QRADAR-RULE-010",
  "title": "System Integrity Violation Detected",
  "status": "production",
  "description": "Detects system integrity violations including kernel module loading and rootkit installation indicators.",
  "author": "SOC Team",
  "date": "2025/04/05",
  "tags": ["attack.defense_evasion", "attack.t1014", "attack.t1542"],
  "mitre": {
    "tactic": "Defense Evasion",
    "technique": "T1014",
    "subtechnique": "T1542"
  },
  "logsource": {
    "product": "linux",
    "service": "auditd"
  },
  "qradar": {
    "rule_name": "SOC-010: System Integrity Violation",
    "severity": "CRITICAL",
    "credibility": 10,
    "relevance": 10,
    "response_action": "create_offense"
  },
  "aql": "SELECT QIDNAME(qid) as EventName, sourceIP, destinationIP, username, LOGSOURCENAME(logsourceid) as LogSource, payload, starttime FROM events WHERE LOGSOURCENAME(logsourceid) ILIKE '%LinuxServer%' AND (payload ILIKE '%insmod%' OR payload ILIKE '%modprobe%' OR payload ILIKE '%/boot/grub%' OR payload ILIKE '%/lib/modules%') ORDER BY starttime DESC LAST 300 SECONDS",
  "falsepositives": ["Authorized kernel updates", "System package installations"],
  "level": "critical"
}
