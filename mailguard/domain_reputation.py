from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Optional


@dataclass
class DomainReputation:
    entropy: float
    randomness_score: float
    is_known_esp: bool
    esp_name: Optional[str]
    dmarc_policy: Optional[str]
    has_dmarc: bool


_KNOWN_ESPS: dict[str, str] = {
    "sendgrid.net": "SendGrid",
    "sendgrid.info": "SendGrid",
    "sendgrid.com": "SendGrid",
    "mandrill.com": "Mandrill",
    "mandrillapp.com": "Mandrill",
    "mailchimp.com": "Mailchimp",
    "mailgun.org": "Mailgun",
    "mailgun.com": "Mailgun",
    "sendinblue.com": "Sendinblue",
    "brevo.com": "Brevo",
    "postmarkapp.com": "Postmark",
    "amazonses.com": "AmazonSES",
    "ses.amazonaws.com": "AmazonSES",
    "sparkpostmail.com": "SparkPost",
    "constantcontact.com": "ConstantContact",
    "getresponse.com": "GetResponse",
    "sendsay.ru": "Sendsay",
    "sndsy.ru": "Sendsay",
    "bsndsy.ru": "Sendsay",
    "notisend.ru": "NotiSend",
    "msndr.net": "NotiSend",
    "unisender.com": "UniSender",
    "esputnik.com": "eSputnik",
    "dashamail.com": "DashaMail",
    "mailganer.com": "Mailganer",
    "mailerlite.com": "MailerLite",
    "convertkit.com": "ConvertKit",
    "hubspot.com": "HubSpot",
    "hubspotlinks.com": "HubSpot",
    "intercom.io": "Intercom",
    "freshdesk.com": "Freshdesk",
    "zendesk.com": "Zendesk",
    "emarsys.net": "Emarsys",
    "sailthru.com": "Sailthru",
    "returnpath.com": "ReturnPath",
    "campaignmonitor.com": "CampaignMonitor",
    "crsend.com": "CampaignMonitor",
    "mailjet.com": "Mailjet",
}


TRUSTED_EXTERNAL_PLATFORMS: set[str] = {
    "t.me",
    "telegram.me",
    "telegram.org",
    "telegra.ph",
    "wa.me",
    "whatsapp.com",
    "vk.com",
    "ok.ru",
    "instagram.com",
    "facebook.com",
    "messenger.com",
    "linkedin.com",
    "youtube.com",
    "youtu.be",
    "twitter.com",
    "x.com",
    "discord.gg",
    "discord.com",
    "forms.yandex.ru",
    "yandex.ru",
    "forms.google.com",
    "docs.google.com",
    "drive.google.com",
    "google.com",
    "microsoft.com",
    "office.com",
    "office365.com",
    "teams.microsoft.com",
    "sharepoint.com",
    "icloud.com",
    "apple.com",
    "zoom.us",
    "github.com",
    "gitlab.com",
    "notion.so",
    "figma.com",
    "miro.com",
    "trello.com",
    "slack.com",
    "stackoverflow.com",
    "wikipedia.org",
    "timepad.ru",
    "leader-id.ru",
}


def domain_entropy(domain: str) -> float:
    if not domain:
        return 0.0
    sld = domain.split(".")[0] if "." in domain else domain
    if not sld:
        return 0.0
    freq = Counter(sld.lower())
    total = len(sld)
    return -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)


def domain_randomness_score(domain: str) -> float:
    if not domain:
        return 0.0
    sld = domain.split(".")[0] if "." in domain else domain
    if not sld:
        return 0.0
    sld_low = sld.lower()

    ent = domain_entropy(domain)
    max_ent = math.log2(max(len(set(sld_low)), 2))
    ent_norm = min(ent / max(max_ent, 0.01), 1.0) if max_ent else 0.0

    vowels = set("aeiouаеёиоуыэюя")
    consonant_runs = re.findall(r"[^aeiouаеёиоуыэюя\d\-_]{3,}", sld_low)
    cluster_score = min(len(consonant_runs) * 0.3, 1.0)

    digit_ratio = sum(c.isdigit() for c in sld) / max(len(sld), 1)

    transitions = 0
    prev_is_vowel = None
    for c in sld_low:
        if c.isalpha():
            is_v = c in vowels
            if prev_is_vowel is not None and is_v != prev_is_vowel:
                transitions += 1
            prev_is_vowel = is_v
    alpha_count = sum(c.isalpha() for c in sld_low)
    transition_ratio = transitions / max(alpha_count - 1, 1) if alpha_count > 1 else 0
    transition_penalty = abs(transition_ratio - 0.55) * 1.5
    transition_penalty = min(transition_penalty, 0.5)

    if len(sld) <= 3 or len(sld) >= 20:
        length_penalty = 0.3
    elif len(sld) <= 5:
        length_penalty = 0.1
    else:
        length_penalty = 0.0

    randomness = (
        ent_norm * 0.30
        + cluster_score * 0.25
        + digit_ratio * 0.20
        + length_penalty * 0.10
        + transition_penalty * 0.15
    )
    return min(max(randomness, 0.0), 1.0)


def is_known_esp(domain: str) -> tuple[bool, Optional[str]]:
    if not domain:
        return False, None
    d = domain.lower().strip(".")
    for esp_domain, esp_name in _KNOWN_ESPS.items():
        if d == esp_domain or d.endswith("." + esp_domain):
            return True, esp_name
    return False, None


def detect_esp_from_headers(
    headers: dict[str, list[str]],
) -> tuple[bool, Optional[str]]:
    received = headers.get("Received", [])
    all_received = " ".join(received).lower()

    for esp_domain, esp_name in _KNOWN_ESPS.items():
        if esp_domain in all_received:
            return True, esp_name

    esp_headers: dict[str, Optional[str]] = {
        "X-SG-EID": "SendGrid",
        "X-SG-ID": "SendGrid",
        "X-Mailgun-Sid": "Mailgun",
        "X-PM-Message-Id": "Postmark",
        "X-SES-Outgoing": "AmazonSES",
        "X-MC-User": "Mailchimp",
        "X-Sendsay-ID": "Sendsay",
        "X-Feedback-ID": None,
    }
    for hdr, esp in esp_headers.items():
        vals = headers.get(hdr, [])
        if vals:
            if esp:
                return True, esp
            val_low = " ".join(str(v) for v in vals).lower()
            for ed, en in _KNOWN_ESPS.items():
                if ed.split(".")[0] in val_low:
                    return True, en

    return False, None


def is_trusted_external(domain: str) -> bool:
    if not domain:
        return False
    d = domain.lower().strip(".")
    for td in TRUSTED_EXTERNAL_PLATFORMS:
        if d == td or d.endswith("." + td):
            return True
    return False


def parse_dmarc_policy(auth_results: str) -> tuple[Optional[str], bool]:
    if not auth_results:
        return None, False

    dmarc_match = re.search(r"dmarc\s*=\s*(\w+)", auth_results, re.IGNORECASE)
    if not dmarc_match:
        return None, False

    policy_p = re.search(r"policy\.p\s*=\s*(\w+)", auth_results, re.IGNORECASE)
    if policy_p:
        p = policy_p.group(1).lower()
        if p in ("none", "quarantine", "reject"):
            return p, True

    paren_policy = re.search(
        r"dmarc\s*=\s*\w+\s*\(.*?p\s*=\s*(\w+)", auth_results, re.IGNORECASE
    )
    if paren_policy:
        p = paren_policy.group(1).lower()
        if p in ("none", "quarantine", "reject"):
            return p, True

    return None, True


def analyze_domain(domain: str) -> DomainReputation:
    ent = domain_entropy(domain)
    rnd = domain_randomness_score(domain)
    esp_found, esp_name = is_known_esp(domain)

    return DomainReputation(
        entropy=ent,
        randomness_score=rnd,
        is_known_esp=esp_found,
        esp_name=esp_name,
        dmarc_policy=None,
        has_dmarc=False,
    )
