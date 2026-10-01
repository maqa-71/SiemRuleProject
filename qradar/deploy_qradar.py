#!/usr/bin/env python3
"""
QRadar Rule Deploy Script — JSON to AQL
GitHub Actions CI/CD Pipeline
"""

import os
import re
import json
import requests
import glob
import sys
import time
import urllib3
from datetime import datetime, timedelta

# Git-in sistem fayllarına (/etc/gitconfig) toxunub "Permission Denied" xətası 
# verməməsi üçün mühit dəyişənlərini skript daxilində set edirik.
os.environ['GIT_CONFIG_NOSYSTEM'] = '1'
os.environ['GIT_CONFIG_GLOBAL'] = '/tmp/.gitconfig'

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

QRADAR_HOST  = os.environ.get('QRADAR_HOST', '')
QRADAR_TOKEN = os.environ.get('QRADAR_SEC_TOKEN', '')

if not QRADAR_HOST or not QRADAR_TOKEN:
    print("XETA: QRADAR_HOST ve ya QRADAR_SEC_TOKEN tapilmadi!")
    sys.exit(1)

HEADERS = {
    'SEC'     : QRADAR_TOKEN,
    'Accept'  : 'application/json',
    'Version' : '17.0'
}

# ── AQL-i düzəlt ──────────────────────────────────────────────────
def build_aql(aql_template):
    """AQL-i temizle, payload-i fix et ve vaxt elave et"""

    aql = aql_template

    # ORDER BY ve LAST X SECONDS sil
    aql = re.sub(r'ORDER\s+BY\s+\S+\s+\S+', '', aql)
    aql = re.sub(r'LAST\s+\d+\s+SECONDS', '', aql)

    # SELECT-deki payload sutununu UTF8(payload)-e cevir
    select_part = re.search(r'SELECT(.+?)FROM', aql, re.DOTALL | re.IGNORECASE)
    if select_part:
        select_fixed = re.sub(
            r'\bpayload\b',
            'UTF8(payload)',
            select_part.group(1)
        )
        aql = aql[:select_part.start(1)] + select_fixed + aql[select_part.end(1):]

    # WHERE-deki payload ILIKE-lari UTF8(payload)-e cevir
    where_part = re.search(r'WHERE(.+?)$', aql, re.DOTALL | re.IGNORECASE)
    if where_part:
        where_fixed = re.sub(
            r'\bpayload\b',
            'UTF8(payload)',
            where_part.group(1)
        )
        aql = aql[:where_part.start(1)] + where_fixed

    aql = aql.strip().rstrip(';').strip()

    now   = datetime.utcnow()
    start = now - timedelta(hours=1)

    aql_final = (
        f"{aql} "
        f"START '{start.strftime('%Y-%m-%d %H:%M')}' "
        f"STOP '{now.strftime('%Y-%m-%d %H:%M')}'"
    )

    return aql_final

# ── AQL sorğusunu icra et ──────────────────────────────────────────
def run_aql_search(aql_template):
    aql = build_aql(aql_template)
    print(f"   AQL gonderilir...")
    print(f"   {aql[:150]}...")

    headers_post = {
        'SEC'          : QRADAR_TOKEN,
        'Accept'       : 'application/json',
        'Version'      : '17.0',
        'Content-Type' : 'application/x-www-form-urlencoded'
    }

    r = requests.post(
        f'{QRADAR_HOST}/api/ariel/searches',
        headers=headers_post,
        data=f'query_expression={requests.utils.quote(aql)}',
        verify=False
    )

    if r.status_code not in [200, 201]:
        print(f"   XETA: HTTP {r.status_code}")
        print(f"   {r.text[:300]}")
        return None

    search_id = r.json().get('search_id')
    print(f"   Search ID: {search_id}")

    for i in range(20):
        time.sleep(3)
        sr = requests.get(
            f'{QRADAR_HOST}/api/ariel/searches/{search_id}',
            headers=HEADERS,
            verify=False
        )
        status = sr.json().get('status')
        print(f"   Status [{i+1}]: {status}")
        if status == 'COMPLETED':
            break
        elif status == 'ERROR':
            print("   XETA: AQL icra xetasi")
            return None

    rr = requests.get(
        f'{QRADAR_HOST}/api/ariel/searches/{search_id}/results',
        headers=HEADERS,
        verify=False
    )

    if rr.status_code == 200:
        events = rr.json().get('events', [])
        print(f"   {len(events)} event tapildi")
        return events

    print(f"   XETA: Neticeler alinmadi HTTP {rr.status_code}")
    return None

# ── JSON rule-u işlət ─────────────────────────────────────────────
def process_rule(rule_data):
    q        = rule_data.get('qradar', {})
    aql      = rule_data.get('aql', '')
    name     = q.get('rule_name', rule_data.get('title', 'Unnamed'))
    severity = q.get('severity', 'HIGH')
    mitre    = rule_data.get('mitre', {})
    tags     = rule_data.get('tags', [])

    print(f"\n{'='*55}")
    print(f"Rule    : {name}")
    print(f"Severity: {severity}")
    print(f"Tactic  : {mitre.get('tactic', 'N/A')}")
    print(f"MITRE   : {mitre.get('technique', 'N/A')}")
    print(f"Tags    : {', '.join(tags)}")
    print(f"{'='*55}")

    if not aql:
        print("   XETA: AQL tapilmadi!")
        return False

    events = run_aql_search(aql.strip())

    if events is None:
        return False

    if len(events) > 0:
        print(f"\n   XEBERDARLIQ: {len(events)} subheli event!")
        for i, ev in enumerate(events[:3]):
            print(f"\n   [{i+1}]")
            print(f"     Event     : {ev.get('EventName', 'N/A')}")
            print(f"     SourceIP  : {ev.get('sourceIP', 'N/A')}")
            print(f"     Username  : {ev.get('username', 'N/A')}")
            print(f"     LogSource : {ev.get('LogSource', 'N/A')}")
        if len(events) > 3:
            print(f"   ... ve {len(events)-3} event daha")
    else:
        print("   Tehlikeli event tapilmadi")

    return True

# ── Əsas funksiya ──────────────────────────────────────────────────
def main():
    # Git konfiqurasiyasini dummy fayla yönləndiririk ki, /etc/gitconfig kilidlənməsin
    if not os.path.exists('/tmp/.gitconfig'):
        with open('/tmp/.gitconfig', 'w') as f:
            f.write('[user]\n\tname = QRadarDeploy\n\temail = deploy@local\n')

    print("=" * 55)
    print("  QRadar JSON+AQL Deploy — GitHub Actions")
    print("=" * 55)
    print(f"  Host: {QRADAR_HOST}")
    print("=" * 55)

    rule_files = sorted(glob.glob('rules/*.json'))

    if not rule_files:
        print("XETA: rules/ qovlugunda JSON fayl tapilmadi!")
        sys.exit(1)

    print(f"\n{len(rule_files)} JSON rule fayl tapildi.\n")

    ok = fail = 0

    for f in rule_files:
        print(f"\nFayl: {f}")
        try:
            with open(f, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            if not data:
                fail += 1
                continue
            if process_rule(data):
                ok += 1
            else:
                fail += 1
        except json.JSONDecodeError as e:
            print(f"   XETA: JSON xetasi — {e}")
            fail += 1
        except Exception as e:
            print(f"   XETA: {e}")
            fail += 1

    print(f"\n{'='*55}")
    print(f"  Ugurlu : {ok}")
    print(f"  Xetali : {fail}")
    print(f"{'='*55}")
    sys.exit(0)

if __name__ == '__main__':
    main()
