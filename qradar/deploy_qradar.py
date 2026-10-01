#!/usr/bin/env python3
"""
QRadar Rule Deploy — JSON rule-lar -> CRE custom_rule XML -> Extension API -> Install
GitHub Actions CI/CD Pipeline (stdlib + requests)
"""

import os
import re
import io
import json
import glob
import sys
import time
import uuid
import base64
import zipfile
import requests
import urllib3
from xml.sax.saxutils import escape

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Konfiqurasiya ──────────────────────────────────────────────────
QRADAR_HOST  = os.environ.get('QRADAR_HOST', '').strip().rstrip('/')
QRADAR_TOKEN = os.environ.get('QRADAR_SEC_TOKEN', '').strip()
API_VERSION  = os.environ.get('QRADAR_API_VERSION', '20.0').strip()
# AQL filter test sinifi QRadar versiyalarinda ferqli ola biler;
# repo variable (QRADAR_AQL_TEST_CLASS) ile push-suz deyismek olar.
AQL_TEST_CLASS = os.environ.get(
    'QRADAR_AQL_TEST_CLASS',
    'com.q1labs.semsources.cre.tests.AQLFilter_Test'
).strip()
TIMEOUT = 30

if not QRADAR_HOST or not QRADAR_TOKEN:
    print("::error::QRADAR_HOST ve ya QRADAR_SEC_TOKEN tapilmadi!")
    sys.exit(1)
if not QRADAR_HOST.startswith('http'):
    QRADAR_HOST = 'https://' + QRADAR_HOST

HEADERS = {
    'SEC': QRADAR_TOKEN,
    'Accept': 'application/json',
    'Version': API_VERSION,
}

# ── AQL -> WHERE clause ────────────────────────────────────────────
def aql_to_where(aql):
    """SELECT ... FROM events WHERE ... sorgusundan WHERE hissesini gotur."""
    m = re.search(r'\bWHERE\b(.+)$', aql, re.DOTALL | re.IGNORECASE)
    where = m.group(1) if m else aql
    where = re.sub(r'ORDER\s+BY\s+\S+\s+\S+', '', where, flags=re.IGNORECASE)
    where = re.sub(r'LAST\s+\d+\s+(SECONDS|MINUTES|HOURS|DAYS)', '', where, flags=re.IGNORECASE)
    return where.strip().rstrip(';').strip()

# ── JSON rule -> inner rule XML ------------------------------------
def build_rule_xml(idx, rule):
    q        = rule.get('qradar', {})
    name     = q.get('rule_name', rule.get('title', f'Unnamed-{idx}'))
    desc     = rule.get('description', '')
    mitre    = rule.get('mitre', {})
    cred     = q.get('credibility', 5)
    rel      = q.get('relevance', 5)
    where    = aql_to_where(rule.get('aql', ''))
    notes    = f"{desc} | MITRE: {mitre.get('tactic','')} / {mitre.get('technique','')} | {rule.get('id','')}"
    rule_id  = 100001 + idx

    return f'''<rule buildingBlock="false" enabled="true" id="{rule_id}" origin="USER" owner="admin" roleDefinition="false" scope="LOCAL" type="EVENT">
  <name>{escape(name)}</name>
  <notes>{escape(notes)}</notes>
  <testDefinitions>
    <test group="AQL Tests" id="1" name="{escape(AQL_TEST_CLASS)}" uid="0">
      <text>when the event matches this AQL filter query</text>
      <parameter id="1">
        <initialText>Enter an AQL filter query</initialText>
        <selectionLabel>AQL filter query</selectionLabel>
        <userOptions/>
        <userSelection>{escape(where)}</userSelection>
      </parameter>
    </test>
  </testDefinitions>
  <actions flowAnalysisInterval="0" forceOffenseCreation="true" includeAttackerEventsInterval="0" offenseMapping="0"/>
  <responses referenceMap="false" referenceMapOfMaps="false">
    <newevent contributeOffenseName="true" credibility="{int(cred)}" describeOffense="true" description="{escape(name)}" forceOffenseCreation="true" lowLevelCategory="20013" name="{escape(name)}" offenseMapping="0" overrideOffenseName="true" relevance="{int(rel)}"/>
  </responses>
</rule>'''

# ── content export XML + zip ---------------------------------------
def build_extension_zip(rules):
    now = int(time.time() * 1000)
    parts = ['<?xml version="1.0" encoding="UTF-8"?>', '<content>', '<qradarversion>7.5.0</qradarversion>']
    for idx, rule in enumerate(rules):
        inner = build_rule_xml(idx, rule)
        rid = rule.get('id', f'rule-{idx}')
        ruuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f'siemruleproject-qradar-{rid}'))
        b64 = base64.b64encode(inner.encode('utf-8')).decode('ascii')
        parts.append(f'''  <custom_rule>
    <origin>USER</origin>
    <mod_date>{now}</mod_date>
    <rule_data>{b64}</rule_data>
    <uuid>{ruuid}</uuid>
    <link_uuid/>
    <rule_type>0</rule_type>
    <id>{100001 + idx}</id>
    <create_date>{now}</create_date>
  </custom_rule>''')
    parts.append('</content>')
    xml = '\n'.join(parts)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('custom_rule-ContentExport.xml', xml)
    return buf.getvalue(), xml

# ── API helpers -----------------------------------------------------
def api_post(path, **kw):
    kw.setdefault('timeout', TIMEOUT)
    kw.setdefault('verify', False)
    return requests.post(f'{QRADAR_HOST}{path}', **kw)

def api_get(url_or_path, **kw):
    kw.setdefault('timeout', TIMEOUT)
    kw.setdefault('verify', False)
    url = url_or_path if url_or_path.startswith('http') else f'{QRADAR_HOST}{url_or_path}'
    return requests.get(url, **kw)

def poll_task(status_location):
    """Install/preview task bitene qeder gozle. (status, json) qaytarir."""
    for _ in range(60):
        time.sleep(2)
        r = api_get(status_location, headers=HEADERS)
        try:
            body = r.json()
        except Exception:
            body = {}
        status = body.get('status', 'UNKNOWN')
        if status in ('COMPLETED', 'ERROR', 'CANCELLED', 'EXCEPTION'):
            return status, body
    return 'TIMEOUT', {}

# ── Main ------------------------------------------------------------
def main():
    print('=' * 60)
    print('  QRadar Rule Deploy — JSON -> CRE custom_rule -> Install')
    print('=' * 60)
    print(f'  Host: {QRADAR_HOST} | API: {API_VERSION}')
    print(f'  AQL test class: {AQL_TEST_CLASS}')
    print('=' * 60)

    # 1. Pre-flight
    try:
        pf = api_get('/api/help/versions', headers=HEADERS, timeout=15)
        print(f'Pre-flight: HTTP {pf.status_code}')
        if pf.status_code == 401:
            print('::error::Token yanlisdir (401). QRADAR_SEC_TOKEN-i yoxla.')
            sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f'::error::QRadar API-e qosulmaq olmadi: {e}')
        print('  Yoxla: QRADAR_HOST hazirki PUBLIC IP-dir? 443 runner-lara aciqdir?')
        sys.exit(1)

    # 2. Rule-lari oxu
    rules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules')
    files = sorted(glob.glob(os.path.join(rules_dir, '*.json')))
    if not files:
        print(f'::error::{rules_dir} qovlugunda JSON tapilmadi!')
        sys.exit(1)

    rules = []
    for f in files:
        with open(f, encoding='utf-8') as fh:
            d = json.load(fh)
        rules.append(d)
        print(f"  OK: {os.path.basename(f)} -> {d.get('qradar',{}).get('rule_name','?')}")
    print(f'\n{len(rules)} rule yuklendi. XML yaradilir...')

    # 3. XML + zip
    zip_bytes, xml = build_extension_zip(rules)
    with open('/tmp/qradar_extension.zip', 'wb') as fh:
        fh.write(zip_bytes)
    with open('/tmp/qradar_extension.xml', 'w', encoding='utf-8') as fh:
        fh.write(xml)
    print(f'Zip hazirdir: {len(zip_bytes)} bayt')

    # 4. Extension upload
    print('\n[1/3] Extension yuklenir...')
    up_headers = dict(HEADERS)
    up_headers['Content-Type'] = 'application/zip'
    r = api_post('/api/config/extension_management/extensions',
                 headers=up_headers, data=zip_bytes)
    print(f'  HTTP {r.status_code}: {r.text[:400]}')
    if r.status_code not in (200, 201):
        print('::error::Extension upload ugursuz oldu.')
        sys.exit(1)
    ext_id = r.json().get('id')
    print(f'  Extension ID: {ext_id}')

    # 5. Install (overwrite=true -> update destekleyir)
    print('\n[2/3] Install edilir (overwrite=true)...')
    r = api_post(f'/api/config/extension_management/extensions/{ext_id}',
                 headers=HEADERS,
                 params={'action_type': 'INSTALL', 'overwrite': 'true'})
    print(f'  HTTP {r.status_code}: {r.text[:400]}')
    if r.status_code not in (200, 201, 202):
        print('::error::Install baslamadi.')
        sys.exit(1)
    status_location = r.json().get('status_location')
    status, body = poll_task(status_location)
    print(f'  Install status: {status}')
    print(f'  Detal: {json.dumps(body)[:800]}')
    if status != 'COMPLETED':
        print('::error::Install ugursuz oldu. XML/test class formatini yoxla '
              '(QRADAR_AQL_TEST_CLASS repo variable-i ile deyisile biler).')
        sys.exit(1)

    # 6. Verifikasiya — /api/analytics/rules-dan adlari yoxla
    print('\n[3/3] Verifikasiya...')
    vh = dict(HEADERS)
    vh['Range'] = 'items=0-9999'
    r = api_get('/api/analytics/rules', headers=vh)
    deployed = {}
    if r.status_code in (200, 206):
        for rule in r.json():
            deployed[rule.get('name', '')] = rule
    else:
        print(f'  Verifikasiya sorğusu: HTTP {r.status_code} (qeyri-kritik)')

    ok = missing = 0
    for rule in rules:
        name = rule.get('qradar', {}).get('rule_name', rule.get('title', ''))
        hit = deployed.get(name)
        if hit:
            print(f"  VAR : {name} (id={hit.get('id')}, enabled={hit.get('enabled')})")
            ok += 1
        else:
            print(f"  YOX : {name}")
            missing += 1

    print(f'\n{"=" * 60}')
    print(f'  Deploy olunan: {ok}/{len(rules)}')
    print(f'{"=" * 60}')

    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as fh:
            fh.write('## QRadar Rule Deploy\n\n')
            fh.write(f'- Install status: **{status}**\n')
            fh.write(f'- QRadar-da tapilan rule: **{ok}/{len(rules)}**\n')
            fh.write(f'- AQL test class: `{AQL_TEST_CLASS}`\n')

    sys.exit(0 if missing == 0 else 1)

if __name__ == '__main__':
    main()
