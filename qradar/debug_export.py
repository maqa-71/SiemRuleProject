#!/usr/bin/env python3
"""DEBUG: SOC-005 ve (varsa) TEST-AQL rule-unun saxlanilmis XML-ini tam goster."""
import os, io, time, zipfile, base64, re, requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
HOST  = os.environ['QRADAR_HOST'].strip().rstrip('/')
TOKEN = os.environ['QRADAR_SEC_TOKEN'].strip()
VER   = os.environ.get('QRADAR_API_VERSION', '20.0').strip()
if not HOST.startswith('http'): HOST = 'https://' + HOST
H = {'SEC': TOKEN, 'Accept': 'application/json', 'Version': VER}
T = 60
def get(p, **kw):
    kw.setdefault('timeout', T); kw.setdefault('verify', False); kw.setdefault('headers', H)
    url = p if p.startswith('http') else HOST + p
    return requests.get(url, **kw)
def post(p, **kw):
    kw.setdefault('timeout', T); kw.setdefault('verify', False); kw.setdefault('headers', H)
    return requests.post(HOST + p, **kw)

h = dict(H); h['Range'] = 'items=0-9999'
rules = get('/api/analytics/rules?fields=id,name', headers=h).json()
targets = [x for x in rules if x.get('name','') in ('SOC-005: Malicious Code Execution', 'TEST-AQL')]
print('targets:', targets)
for t in targets:
    xp = post('/api/config/extension_management/extension_export_tasks',
              json={"export_contents": [{"content_item_ids": [str(t['id'])], "content_type": "CUSTOM_RULES", "related_content": []}]})
    task_id = xp.json().get('task_id')
    for _ in range(30):
        time.sleep(3)
        st = get(f'/api/config/extension_management/extensions_task_status/{task_id}').json()
        if st.get('status') in ('COMPLETED', 'ERROR', 'CANCELLED', 'EXCEPTION'): break
    dz = get(f'/api/config/extension_management/extension_export_tasks/{task_id}/extension_export',
             headers={'SEC': TOKEN, 'Version': VER, 'Accept': 'application/zip'})
    zf = zipfile.ZipFile(io.BytesIO(dz.content))
    data = zf.read([n for n in zf.namelist() if n.endswith('.xml')][0]).decode('utf-8', 'replace')
    m = re.search(r'<rule_data>([^<]+)</rule_data>', data)
    print(f"\n===== {t['name']} (id={t['id']}) =====")
    print(base64.b64decode(m.group(1)).decode('utf-8', 'replace')[:3000])
