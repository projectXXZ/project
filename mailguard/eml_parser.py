from __future__ import annotations

from email import policy
from email.parser import BytesParser
from email.message import Message

from .my_types import Attachment, ParsedEmail


def _get_all(msg: Message, name: str) -> list[str]:
    values = msg.get_all(name, [])
    return [str(v).strip() for v in values if v is not None]


def _get_first(msg: Message, name: str) -> str:
    vals = _get_all(msg, name)
    return vals[0] if vals else ""


def parse_eml_bytes(raw: bytes) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    subject = _get_first(msg, "Subject")
    from_ = _get_first(msg, "From")
    to = _get_first(msg, "To")
    reply_to = _get_first(msg, "Reply-To")
    return_path = _get_first(msg, "Return-Path")
    received = _get_all(msg, "Received")
    auth_results = _get_first(msg, "Authentication-Results")
    date_str = _get_first(msg, "Date")

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []

    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue

        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""

        if disposition in {"attachment", "inline"} or filename:
            attachments.append(
                Attachment(
                    filename=filename,
                    content_type=content_type,
                    size=len(payload),
                    payload=payload,
                    is_inline=(disposition == "inline"),
                    content_id=_get_first(part, "Content-ID"),
                )
            )
            continue

        if content_type == "text/plain":
            try:
                text_parts.append(part.get_content())
            except Exception:
                text_parts.append(payload.decode(errors="replace"))
        elif content_type == "text/html":
            try:
                html_parts.append(part.get_content())
            except Exception:
                html_parts.append(payload.decode(errors="replace"))

    headers = {k: _get_all(msg, k) for k in msg.keys()}

    return ParsedEmail(
        headers=headers,
        subject=subject,
        from_=from_,
        to=to,
        reply_to=reply_to,
        return_path=return_path,
        received=received,
        auth_results=auth_results,
        text="\n".join(text_parts).strip(),
        html="\n".join(html_parts).strip(),
        attachments=attachments,
        date_str=date_str,
    )