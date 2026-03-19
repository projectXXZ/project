from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Literal


@dataclass(frozen=True)
class Attachment:
    filename: Optional[str]
    content_type: str
    size: int
    payload: bytes
    is_inline: bool
    content_id: Optional[str]


@dataclass(frozen=True)
class ParsedEmail:
    headers: dict[str, list[str]]
    subject: str
    from_: str
    to: str
    reply_to: str
    return_path: str
    received: list[str]
    auth_results: str
    text: str
    html: str
    attachments: list[Attachment]
    date_str: str = ""


LinkSource = Literal["text", "html_href", "html_text", "qr"]


@dataclass(frozen=True)
class LinkFound:
    url: str
    source: LinkSource
    visible_text: Optional[str] = None


@dataclass(frozen=True)
class CheckedURL:
    original_url: str
    final_url: str
    final_domain: str
    redirect_count: int
    is_https: bool
    flags: list[str]
    notes: list[str]
