"""
Lambda: elb-anomaly-responder
Recibe callbacks de Slack (botón Check) vía API Gateway HTTP v2.
"""
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key

ALERTS_TABLE         = os.environ["ALERTS_TABLE"]
VALIDATIONS_TABLE    = os.environ["VALIDATIONS_TABLE"]
SLACK_BOT_TOKEN      = os.environ["SLACK_BOT_TOKEN"]
SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]
APP_NAME             = os.environ["APP_NAME"]

dynamodb          = boto3.resource('dynamodb')
alerts_table      = dynamodb.Table(ALERTS_TABLE)
validations_table = dynamodb.Table(VALIDATIONS_TABLE)


def verify_slack_signature(body: bytes, timestamp: str, signature: str) -> bool:
    try:
        if abs(time.time() - int(timestamp)) > 300:
            return False
    except (ValueError, TypeError):
        return False
    base     = f"v0:{timestamp}:{body.decode('utf-8')}"
    computed = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode("utf-8"),
        base.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(computed, signature)


def slack_api(method: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        f"https://slack.com/api/{method}",
        data=data,
        headers={
            "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
            "Content-Type":  "application/json; charset=utf-8",
        },
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def build_summary_text(alert_date: str, items: list, all_checked: bool) -> str:
    if all_checked:
        return (
            f":white_check_mark: *ALERTA ELB CONFIRMADA — Demo System*\n"
            f"*Fecha:* {alert_date}   |   *Todas las IPs revisadas*"
        )
    lines = []
    for item in items:
        ip    = item['ip']
        score = item.get('score', '?')
        fc    = item.get('force_critical', False)
        label = ":skull: CRÍTICO" if fc else f"puntuación {score}"
        line  = f"• `{ip}` — {label} — {item.get('findings_count','?')} patrón(es)"
        if item.get('checked'):
            line = f"• ~`{ip}` — {label}~  :white_check_mark:"
        lines.append(line)
    return (
        f":male-detective: *ALERTA DE SEGURIDAD ELB — Demo System*\n"
        f"*Fecha:* {alert_date}   |   *IPs sospechosas:* {len(items)}\n\n"
        + "\n".join(lines)
    )


def lambda_handler(event, context):
    print(f"Event keys: {list(event.keys())}")

    headers   = event.get("headers", {})
    timestamp = headers.get("x-slack-request-timestamp", "")
    signature = headers.get("x-slack-signature", "")
    raw_body  = event.get("body", "")

    if event.get("isBase64Encoded"):
        body_bytes   = base64.b64decode(raw_body)
        decoded_body = body_bytes.decode("utf-8")
    else:
        body_bytes   = raw_body.encode("utf-8")
        decoded_body = raw_body

    if not verify_slack_signature(body_bytes, timestamp, signature):
        print("ERROR: firma inválida")
        return {"statusCode": 403, "body": "Forbidden"}

    parsed    = urllib.parse.parse_qs(decoded_body)
    payload   = json.loads(parsed.get("payload", ["{}"])[0])
    action    = payload.get("actions", [{}])[0]
    action_id = action.get("action_id", "")
    value     = json.loads(action.get("value", "{}"))

    alert_date   = value.get("alert_date")
    ip           = value.get("ip")
    summary_ts   = value.get("summary_ts")
    channel_id   = value.get("channel_id")
    app          = value.get("app", APP_NAME)
    hotels       = value.get("hotels", [])
    detail_ts    = payload.get("container", {}).get("message_ts", "")
    validated_by = payload.get("user", {}).get("username", "unknown")

    print(f"Action: {action_id} | IP: {ip} | User: {validated_by}")

    if action_id != "check_ip":
        return {"statusCode": 200, "body": "ok"}

    # ── DynamoDB alerts — marcar checkeada ────────────────────────────
    alerts_table.update_item(
        Key={'alert_date': alert_date, 'ip': ip},
        UpdateExpression="SET checked = :t, checked_at = :d",
        ExpressionAttributeValues={
            ':t': True,
            ':d': datetime.now(timezone.utc).isoformat(),
        }
    )
    print(f"DynamoDB alerts: {ip} checkeada")

    # ── DynamoDB validations — upsert ─────────────────────────────────
    existing = validations_table.get_item(Key={'ip': ip, 'app': app}).get('Item')
    if existing:
        existing_hotels = set(existing.get('hotels', []))
        new_hotels      = list(existing_hotels | set(hotels))
        validations_table.update_item(
            Key={'ip': ip, 'app': app},
            UpdateExpression="SET hotels = :h, validated_at = :d, validated_by = :u",
            ExpressionAttributeValues={
                ':h': new_hotels,
                ':d': datetime.now(timezone.utc).isoformat(),
                ':u': validated_by,
            }
        )
    else:
        validations_table.put_item(Item={
            'ip':           ip,
            'app':          app,
            'hotels':       hotels,
            'validated_at': datetime.now(timezone.utc).isoformat(),
            'validated_by': validated_by,
        })
    print(f"DynamoDB validations: {ip} guardada")

    # ── Leer todas las IPs del día ────────────────────────────────────
    resp        = alerts_table.query(KeyConditionExpression=Key('alert_date').eq(alert_date))
    items       = resp.get('Items', [])
    all_checked = all(item.get('checked', False) for item in items)
    print(f"IPs del día: {len(items)} | todas checkeadas: {all_checked}")

    # ── Borrar mensaje de detalle ─────────────────────────────────────
    if detail_ts:
        r = slack_api("chat.delete", {"channel": channel_id, "ts": detail_ts})
        print(f"chat.delete: {r.get('ok')} | {r.get('error','')}")

    # ── Editar mensaje resumen ────────────────────────────────────────
    new_text = build_summary_text(alert_date, items, all_checked)
    r = slack_api("chat.update", {
        "channel": channel_id,
        "ts":      summary_ts,
        "attachments": [{
            "color": "#2eb886" if all_checked else "#cc0000",
            "blocks": [
                {"type": "divider"},
                {"type": "section", "text": {"type": "mrkdwn", "text": new_text}},
                {"type": "divider"},
            ],
        }],
    })
    print(f"chat.update: {r.get('ok')}")

    return {"statusCode": 200, "body": "ok"}
