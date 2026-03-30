"""
Lambda: elb-anomaly-detector
Disparado por EventBridge cada día a las 01:00 UTC.
Descarga logs ALB de S3, detecta IPs anómalas mediante análisis de
patrones de comportamiento y notifica al equipo de seguridad en Slack.
"""
import boto3
import gzip
import re
import io
import json
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote
from urllib.request import Request, urlopen

S3_BUCKET         = os.environ["S3_BUCKET"]
S3_PREFIX         = os.environ["S3_PREFIX"]
ALERTS_TABLE      = os.environ["ALERTS_TABLE"]
VALIDATIONS_TABLE = os.environ["VALIDATIONS_TABLE"]
SLACK_BOT_TOKEN   = os.environ["SLACK_BOT_TOKEN"]
SLACK_CHANNEL_ID  = os.environ["SLACK_CHANNEL_ID"]
APP_NAME          = os.environ["APP_NAME"]

# IPs excluidas del análisis (fuentes legítimas conocidas)
EXCLUDED_IPS = set()

# ── Umbrales de detección ────────────────────────────────────────────────
THRESHOLDS = {
    'min_requests':              30,
    'high_rate_rpm':             100,
    'machine_speed_interval_s':  2,
    'machine_speed_consecutive': 60,
    'error_rate_pct':            20.0,
    'path_scan_count':           10,
    'admin_probe_min':           1,
    'min_score_to_alert':        4,
}

PATTERN_SCORES = {
    'P1_high_rate':    2,
    'P2_machine_speed': 2,
    'P3_error_rate':   2,
    'P4_path_scan':    2,
    'P5_admin_probe':  5,
}

ADMIN_RE = re.compile(r'/(admin|wp-admin|administrator|phpmyadmin|manager)(/|$)', re.IGNORECASE)

ALB_LOG_RE = re.compile(
    r'\S+ '
    r'(\S+) '
    r'\S+ '
    r'([\d.]+):\d+ '
    r'\S+ \S+ \S+ \S+ '
    r'(\d+|-) '
    r'\S+ \S+ '
    r'(\d+|-) '
    r'"([^"]*)"'
)


def slack_post(method, payload):
    data = json.dumps(payload).encode('utf-8')
    req  = Request(
        f'https://slack.com/api/{method}',
        data=data,
        headers={
            'Authorization': f'Bearer {SLACK_BOT_TOKEN}',
            'Content-Type':  'application/json; charset=utf-8',
        },
    )
    resp = json.loads(urlopen(req, timeout=10).read())
    print(f"Slack {method}: ok={resp.get('ok')} ts={resp.get('ts', '-')}")
    return resp


def lambda_handler(event, context):
    s3       = boto3.client('s3')
    dynamodb = boto3.resource('dynamodb')
    alerts_table      = dynamodb.Table(ALERTS_TABLE)
    validations_table = dynamodb.Table(VALIDATIONS_TABLE)

    yesterday      = (datetime.utcnow() - timedelta(days=1)).date()
    alert_date_str = str(yesterday)
    prefix         = f"{S3_PREFIX}/{yesterday.year}/{yesterday.month:02d}/{yesterday.day:02d}/"

    print(f"Analizando logs de {yesterday} — s3://{S3_BUCKET}/{prefix}")

    # ── Listar ficheros de log ───────────────────────────────────────────
    paginator = s3.get_paginator('list_objects_v2')
    log_keys  = []
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=prefix):
        for obj in page.get('Contents', []):
            if obj['Key'].endswith('.log.gz'):
                log_keys.append(obj['Key'])

    print(f"Ficheros encontrados: {len(log_keys)}")
    if not log_keys:
        print("Sin logs — análisis omitido")
        return

    # ── Cargar IPs ya validadas ──────────────────────────────────────────
    validated = validations_table.scan(
        FilterExpression=boto3.dynamodb.conditions.Attr('app').eq(APP_NAME),
        ProjectionExpression='ip'
    )
    validated_ips = {item['ip'] for item in validated.get('Items', [])}
    print(f"IPs ya validadas: {len(validated_ips)}")

    # ── Parsear logs ─────────────────────────────────────────────────────
    ip_stats = defaultdict(lambda: {
        'total':       0,
        'post':        0,
        'errors_4xx':  0,
        'errors_5xx':  0,
        'timestamps':  [],
        'paths':       set(),
        'hosts':       set(),
        'admin_hits':  0,
        'admin_urls':  [],
        'rpm_windows': defaultdict(int),
    })

    for key in log_keys:
        obj     = s3.get_object(Bucket=S3_BUCKET, Key=key)
        content = obj['Body'].read()
        with gzip.GzipFile(fileobj=io.BytesIO(content)) as f:
            for raw_line in f:
                line = raw_line.decode('utf-8', errors='replace').strip()
                if not line or line.startswith('#'):
                    continue
                m = ALB_LOG_RE.match(line)
                if not m:
                    continue

                ts_str, client_ip, status_str, _, request_str = m.groups()
                if client_ip in EXCLUDED_IPS:
                    continue

                try:
                    ts = datetime.strptime(ts_str[:19], '%Y-%m-%dT%H:%M:%S')
                except ValueError:
                    continue

                status    = int(status_str) if status_str != '-' else 0
                req_parts = request_str.split(' ', 2)
                if len(req_parts) < 2:
                    continue
                method      = req_parts[0].upper()
                url         = req_parts[1]
                url_decoded = unquote(url)

                path_m = re.search(r'https?://[^/]+(/.+?)(?:\?|$)', url)
                path   = path_m.group(1) if path_m else (url.split('?')[0] if url.startswith('/') else '/')
                segs   = [s for s in path.split('/') if s]
                host   = segs[0].lower() if segs else ''

                st = ip_stats[client_ip]
                st['total'] += 1
                st['timestamps'].append(ts)
                st['paths'].add(path)
                if host:
                    st['hosts'].add(host)
                if method == 'POST':
                    st['post'] += 1
                if 400 <= status < 500:
                    st['errors_4xx'] += 1
                elif status >= 500:
                    st['errors_5xx'] += 1

                minute_key = ts.strftime('%Y-%m-%dT%H:%M')
                st['rpm_windows'][minute_key] += 1

                if status == 200 and (ADMIN_RE.search(url) or ADMIN_RE.search(url_decoded)):
                    st['admin_hits'] += 1
                    if len(st['admin_urls']) < 10:
                        st['admin_urls'].append(f"`{ts_str}` `{path}`")

    print(f"IPs únicas procesadas: {len(ip_stats)}")

    # ── Detección de patrones ────────────────────────────────────────────
    anomalies = []
    for ip, st in ip_stats.items():
        if ip in validated_ips:
            print(f"IP {ip} omitida — ya validada")
            continue

        total     = st['total']
        findings  = []
        score     = 0
        post_pct  = st['post'] / total * 100 if total > 0 else 0
        sorted_ts = sorted(st['timestamps'])

        # P5 — Sondeo admin (siempre alerta)
        if st['admin_hits'] >= THRESHOLDS['admin_probe_min']:
            examples = "\n    ".join(st['admin_urls'])
            findings.append(
                f"*P5 — Admin URL probing:* {st['admin_hits']} request(s) to "
                f"admin paths returned HTTP 200\n    {examples}"
            )
            score += PATTERN_SCORES['P5_admin_probe']

        if total >= THRESHOLDS['min_requests']:

            # P1 — Tasa de peticiones alta
            max_rpm = max(st['rpm_windows'].values()) if st['rpm_windows'] else 0
            if max_rpm >= THRESHOLDS['high_rate_rpm']:
                findings.append(
                    f"*P1 — High request rate:* peak of {max_rpm} req/min "
                    f"(threshold: {THRESHOLDS['high_rate_rpm']} req/min)"
                )
                score += PATTERN_SCORES['P1_high_rate']

            # P2 — Velocidad de máquina
            if len(sorted_ts) >= THRESHOLDS['machine_speed_consecutive']:
                max_run = cur_run = 1
                for i in range(1, len(sorted_ts)):
                    gap = (sorted_ts[i] - sorted_ts[i - 1]).total_seconds()
                    if 0.0 <= gap <= THRESHOLDS['machine_speed_interval_s']:
                        cur_run += 1
                        max_run  = max(max_run, cur_run)
                    else:
                        cur_run = 1
                if max_run >= THRESHOLDS['machine_speed_consecutive']:
                    findings.append(
                        f"*P2 — Machine speed:* {max_run} consecutive requests "
                        f"all ≤{THRESHOLDS['machine_speed_interval_s']}s apart"
                    )
                    score += PATTERN_SCORES['P2_machine_speed']

            # P3 — Tasa de errores alta
            error_total = st['errors_4xx'] + st['errors_5xx']
            if total > 0:
                error_pct = error_total / total * 100
                if error_pct >= THRESHOLDS['error_rate_pct']:
                    findings.append(
                        f"*P3 — High error rate:* {error_total}/{total} requests "
                        f"returned 4xx/5xx ({error_pct:.1f}%)"
                    )
                    score += PATTERN_SCORES['P3_error_rate']

            # P4 — Escaneo de rutas
            if len(st['paths']) >= THRESHOLDS['path_scan_count']:
                findings.append(
                    f"*P4 — Path scanning:* {len(st['paths'])} unique paths requested "
                    f"(possible enumeration or scanning)"
                )
                score += PATTERN_SCORES['P4_path_scan']

        has_admin = st['admin_hits'] >= THRESHOLDS['admin_probe_min']
        if findings and (has_admin or score >= THRESHOLDS['min_score_to_alert']):
            anomalies.append({
                'ip':           ip,
                'score':        score,
                'total':        total,
                'post_pct':     post_pct,
                'error_total':  st['errors_4xx'] + st['errors_5xx'],
                'unique_paths': len(st['paths']),
                'admin_hits':   st['admin_hits'],
                'hosts':        sorted(st['hosts']),
                'findings':     findings,
                'force_critical': has_admin,
            })

    anomalies.sort(key=lambda x: x['score'], reverse=True)
    print(f"Anomalías detectadas: {len(anomalies)}")
    if not anomalies:
        print("Sin anomalías — todo en orden")
        return

    # ── Mensaje de resumen ───────────────────────────────────────────────
    def summary_label(a):
        return ':skull: CRITICAL (admin probe)' if a['force_critical'] else f"score {a['score']}"

    summary_lines = "\n".join(
        f"• `{a['ip']}` — {summary_label(a)} — {len(a['findings'])} pattern(s)"
        for a in anomalies
    )

    resp = slack_post('chat.postMessage', {
        "channel": SLACK_CHANNEL_ID,
        "attachments": [{
            "color": "#cc0000",
            "blocks": [
                {"type": "divider"},
                {"type": "section", "text": {"type": "mrkdwn", "text": (
                    f":male-detective: *ELB SECURITY ALERT — Demo System*\n"
                    f"*Date:* {yesterday}   |   *Suspicious IPs:* {len(anomalies)}\n\n"
                    f"{summary_lines}"
                )}},
                {"type": "divider"},
            ]
        }]
    })
    summary_ts = resp.get('ts', '')
    if not summary_ts:
        print("ERROR: no se obtuvo ts del resumen — abortando")
        return

    # ── DynamoDB alertas ─────────────────────────────────────────────────
    ttl_7days = int(time.time()) + 604800
    for a in anomalies:
        alerts_table.put_item(Item={
            'alert_date':     alert_date_str,
            'ip':             a['ip'],
            'summary_ts':     summary_ts,
            'channel_id':     SLACK_CHANNEL_ID,
            'score':          a['score'],
            'risk_label':     'HIGH' if (a['force_critical'] or a['score'] >= 7) else 'MEDIUM' if a['score'] >= 4 else 'LOW',
            'findings_count': len(a['findings']),
            'force_critical': a['force_critical'],
            'hosts':          a['hosts'],
            'checked':        False,
            'ttl':            ttl_7days,
        })
        print(f"DynamoDB: {a['ip']} guardada")

    # ── Mensajes de detalle ──────────────────────────────────────────────
    for a in anomalies[:10]:
        if a['force_critical'] or a['score'] >= 7:
            risk_label, risk_color = "HIGH RISK",   "#cc0000"
        elif a['score'] >= 4:
            risk_label, risk_color = "MEDIUM RISK", "#ff8800"
        else:
            risk_label, risk_color = "LOW RISK",    "#ffcc00"

        icon         = ':rotating_light:' if a['score'] >= 5 else ':warning:'
        findings_txt = "\n".join(a['findings'])
        stats_line   = (
            f"Requests: {a['total']}  |  POST: {a['post_pct']:.1f}%  |  "
            f"Errors: {a['error_total']}  |  "
            f"Unique paths: {a['unique_paths']}  |  "
            f"Admin hits: {a['admin_hits']}  |  "
            f"Hosts: {', '.join(a['hosts']) if a['hosts'] else 'N/A'}"
        )
        check_value = json.dumps({
            'alert_date': alert_date_str,
            'ip':         a['ip'],
            'summary_ts': summary_ts,
            'channel_id': SLACK_CHANNEL_ID,
            'app':        APP_NAME,
            'hosts':      a['hosts'],
        })

        slack_post('chat.postMessage', {
            "channel": SLACK_CHANNEL_ID,
            "attachments": [{
                "color": risk_color,
                "blocks": [
                    {"type": "section", "text": {"type": "mrkdwn", "text": (
                        f"{icon} *{risk_label}* — score: `{a['score']}`\n"
                        f"*IP:* `{a['ip']}`\n\n{findings_txt}\n\n_{stats_line}_"
                    )}},
                    {"type": "divider"},
                    {"type": "actions", "elements": [{
                        "type":      "button",
                        "text":      {"type": "plain_text", "text": "✅ Check", "emoji": True},
                        "action_id": "check_ip",
                        "value":     check_value,
                    }]}
                ]
            }]
        })
        time.sleep(0.3)
