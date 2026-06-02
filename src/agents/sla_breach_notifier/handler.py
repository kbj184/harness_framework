"""SLA breach 알림 Lambda.

P0-A/B/C action_due 초과 자산 취약점을 추출해 SNS 토픽에 publish.
EventBridge 주기 cron (기본 1시간)로 호출.

ISMS-P 자동 우선순위 갱신 요건 — 24h/48h/72h SLA가 지나면 운영 채널로 알림.
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from typing import Any

import boto3

from src.shared import db as dbm
from src.shared.logging_config import setup_logging

logger = setup_logging()

PRIORITY_LABELS = {
    "P0-A": "P0-A (24h SLA)",
    "P0-B": "P0-B (48h SLA)",
    "P0-C": "P0-C (72h SLA)",
}


def _fetch_breaches(conn) -> list[dict[str, Any]]:
    sql = """
        SELECT v.vuln_no, v.cve_id, v.ssvc_priority, v.action_due,
               v.cvss_score, v.priority_score, v.is_kev, v.matched_pkg,
               m.asset_id_hash, m.hostname, m.primary_ip, m.category_cd,
               m.cpe_vendor, m.cpe_product,
               (CURRENT_DATE - v.action_due) AS overdue_days
          FROM tb_asset_vulnerability v
          JOIN tb_asset_master m ON m.asset_id_hash = v.asset_id_hash
         WHERE v.use_yn = 'Y'
           AND v.status = 'OPEN'
           AND v.ssvc_priority IN ('P0-A','P0-B','P0-C')
           AND v.action_due IS NOT NULL
           AND v.action_due < CURRENT_DATE
         ORDER BY v.ssvc_priority ASC, v.action_due ASC, v.priority_score DESC NULLS LAST
         LIMIT 200
    """
    with conn.cursor() as cur:
        cur.execute(sql)
        cols = [c.name for c in cur.description]
        return [dict(zip(cols, row, strict=False)) for row in cur.fetchall()]


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_priority: dict[str, int] = {}
    for r in rows:
        p = r.get("ssvc_priority") or "?"
        by_priority[p] = by_priority.get(p, 0) + 1
    return {
        "total": len(rows),
        "by_priority": by_priority,
        "p0_a": by_priority.get("P0-A", 0),
        "p0_b": by_priority.get("P0-B", 0),
        "p0_c": by_priority.get("P0-C", 0),
    }


def _format_message(summary: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    lines.append(f"[CMDB SLA Breach 알림] {datetime.now(UTC).isoformat()}")
    lines.append(
        f"총 {summary['total']}건 — P0-A:{summary['p0_a']} / P0-B:{summary['p0_b']} / P0-C:{summary['p0_c']}"
    )
    lines.append("")
    for r in rows[:20]:
        label = PRIORITY_LABELS.get(r.get("ssvc_priority") or "", r.get("ssvc_priority") or "?")
        kev = " [KEV]" if r.get("is_kev") else ""
        lines.append(
            f"- {label}{kev} {r.get('cve_id')} (overdue {r.get('overdue_days')}d) "
            f"asset={r.get('hostname')} ip={r.get('primary_ip')} "
            f"({r.get('cpe_vendor')}/{r.get('cpe_product')}) "
            f"score={r.get('priority_score')}"
        )
    if len(rows) > 20:
        lines.append(f"  ... 외 {len(rows) - 20}건")
    return "\n".join(lines)


def _publish_sns(topic_arn: str, subject: str, message: str, payload: dict[str, Any]) -> str:
    client = boto3.client("sns")
    resp = client.publish(
        TopicArn=topic_arn,
        Subject=subject[:99],
        Message=message,
        MessageAttributes={
            "summary": {"DataType": "String", "StringValue": json.dumps(payload["summary"], ensure_ascii=False)},
        },
    )
    return resp["MessageId"]


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    start = time.monotonic()
    started_at = datetime.now(UTC)
    topic_arn = os.environ.get("SLA_BREACH_TOPIC_ARN", "")
    dry_run = bool(event.get("dry_run", False)) if isinstance(event, dict) else False
    logger.info("SLA breach 알림 시작 (topic=%s, dry_run=%s)", topic_arn, dry_run)

    try:
        cfg = dbm.load_db_config()
        with dbm.connect(cfg) as conn:
            rows = _fetch_breaches(conn)
        summary = _summarize(rows)

        if not rows:
            logger.info("SLA breach 없음 — publish skip")
            return {
                "status": "SUCCESS",
                "started_at": started_at.isoformat(),
                "summary": summary,
                "message_id": None,
                "duration_ms": int((time.monotonic() - start) * 1000),
            }

        message = _format_message(summary, rows)
        subject = f"[CMDB] SLA Breach {summary['total']}건 (P0-A:{summary['p0_a']}/B:{summary['p0_b']}/C:{summary['p0_c']})"

        payload = {"summary": summary, "rows": rows[:50]}
        msg_id: str | None = None
        if topic_arn and not dry_run:
            msg_id = _publish_sns(topic_arn, subject, message, payload)
            logger.info("SNS publish 완료 message_id=%s", msg_id)
        else:
            logger.info("topic 미설정 또는 dry_run — publish skip\n%s", message)

        return {
            "status": "SUCCESS",
            "started_at": started_at.isoformat(),
            "summary": summary,
            "subject": subject,
            "message_id": msg_id,
            "duration_ms": int((time.monotonic() - start) * 1000),
        }
    except Exception as e:
        logger.exception("SLA breach 알림 실패")
        return {
            "status": "FAILED",
            "error": str(e),
            "started_at": started_at.isoformat(),
            "duration_ms": int((time.monotonic() - start) * 1000),
        }
