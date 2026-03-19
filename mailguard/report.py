from dataclasses import asdict
import re

from .domain_reputation import parse_dmarc_policy


def _auth_status(text: str, key: str) -> str | None:
    if not text:
        return None
    vals = re.findall(rf"\b{re.escape(key)}=([a-zA-Z]+)\b", text, flags=re.IGNORECASE)
    if not vals:
        return None
    norm = [v.lower() for v in vals]
    order = [
        "pass",
        "none",
        "neutral",
        "policy",
        "temperror",
        "permerror",
        "softfail",
        "fail",
    ]

    def rank(v: str) -> int:
        return order.index(v) if v in order else 3

    return sorted(norm, key=rank, reverse=True)[0]


def build_report(
    email,
    checked_links,
    qr_checked_links,
    risk,
    level,
    reasons,
    text_analysis=None,
):
    auth_text = (email.auth_results or "").strip()
    spf = _auth_status(auth_text, "spf")
    dkim = _auth_status(auth_text, "dkim")
    dmarc = _auth_status(auth_text, "dmarc")
    dmarc_policy, _ = parse_dmarc_policy(auth_text)

    report = {
        "summary": {
            "subject": email.subject,
            "from": email.from_,
            "to": getattr(email, "to", ""),
            "risk": round(risk, 4),
            "level": level,
            "reasons": reasons,
        },
        "headers": {
            "reply_to": email.reply_to,
            "return_path": email.return_path,
            "received_count": len(email.received),
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "dmarc_policy": dmarc_policy,
            "authentication_results": email.auth_results,
        },
        "links": [asdict(c) for c in checked_links],
        "qr_links": [asdict(c) for c in qr_checked_links],
        "attachments": [
            {
                "name": a.filename,
                "content_type": a.content_type,
                "size": a.size,
                "inline": a.is_inline,
            }
            for a in email.attachments
        ],
    }

    if text_analysis is not None:
        ta = text_analysis
        report["text_analysis"] = {
            "phishing_score": round(ta.phishing_score, 4),
            "signals": ta.signals[:30],
            "language_mix": ta.language_mix,
            "is_contact_form_injection": ta.is_contact_form_injection,
            "has_urgency": ta.has_urgency,
            "has_monetary_lure": ta.has_monetary_lure,
            "has_credential_request": ta.has_credential_request,
            "has_prize_lure": ta.has_prize_lure,
            "has_threat": ta.has_threat,
            "has_call_to_action": ta.has_call_to_action,
            "suspicious_money_amounts": ta.suspicious_money_amounts[:10],
            "ml_score": round(ta.ml_score, 4) if ta.ml_score is not None else None,
            "ml_label": ta.ml_label,
        }

    return report
