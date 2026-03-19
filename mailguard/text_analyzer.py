from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TextAnalysis:

    phishing_score: float
    signals: list[str]
    language_mix: list[str]
    is_contact_form_injection: bool
    has_urgency: bool
    has_monetary_lure: bool
    has_credential_request: bool
    has_prize_lure: bool
    has_threat: bool
    has_call_to_action: bool
    text_entropy: float
    suspicious_money_amounts: list[int]
    ml_score: Optional[float] = None
    ml_label: Optional[str] = None


_PHISH_KW_RU: dict[str, float] = {
    "выигрыш": 2.5,
    "выиграл": 2.3,
    "выиграли": 2.3,
    "приз от": 2.5,
    "розыгрыш": 2.0,
    "лотере": 2.5,
    "победител": 2.0,
    "удача принесла": 2.5,
    "бонус": 1.4,
    "подарок": 1.0,
    "подарочн": 1.0,
    "бесплатно": 1.3,
    "бесплатн": 1.3,
    "промоакц": 1.8,
    "промо-акц": 1.8,
    "зачислен": 2.0,
    "зачислено": 2.0,
    "зачислены": 2.0,
    "на ваш счёт": 2.0,
    "на ваш счет": 2.0,
    "готовы к использован": 2.0,
    "доступны вам": 1.8,
    "можно забрать": 2.0,
    "получите": 1.3,
    "перевод средств": 1.5,
    "выплат": 1.0,
    "зарабатыв": 2.2,
    "заработок": 1.8,
    "пассивн": 1.2,
    "доход": 1.0,
    "инвестиц": 1.5,
    "начните зарабат": 2.5,
    "срочно": 1.5,
    "немедленно": 1.8,
    "прямо сейчас": 1.3,
    "последний шанс": 1.8,
    "истекает": 1.5,
    "времени осталось": 1.5,
    "только сегодня": 1.5,
    "заблокир": 2.0,
    "ограничен": 1.0,
    "подозрительн": 1.0,
    "несанкционир": 1.8,
    "взлом": 1.5,
    "деактивир": 1.5,
    "пароль": 1.0,
    "код из смс": 1.8,
    "одноразов": 1.5,
    "войти в аккаунт": 1.3,
    "подтвердите личн": 1.8,
    "введите код": 1.5,
    "введите пароль": 1.5,
    "верификац": 1.3,
    "подтверди": 1.0,
    "перейдите по ссылк": 1.3,
    "нажмите на кнопк": 1.3,
    "завершите регистрац": 1.5,
    "подтвердите участие": 1.5,
    "открой ссылк": 1.2,
    "кликни": 1.2,
    "уважаемый клиент": 0.8,
    "дорогой друг": 0.8,
    "уважаемый пользовател": 0.8,
    "участвуйте в акц": 1.3,
    "участвуй в": 1.0,
}

_PHISH_KW_EN: dict[str, float] = {
    "congratulations": 1.5,
    "winner": 2.0,
    "you won": 2.0,
    "prize": 2.0,
    "lottery": 2.5,
    "bonus": 1.3,
    "free": 0.7,
    "claim": 1.5,
    "selected": 1.0,
    "promotion": 1.5,
    "grand promotion": 2.0,
    "free tries": 2.0,
    "suspended": 1.5,
    "blocked": 1.5,
    "urgent": 1.5,
    "immediately": 1.5,
    "verify your": 1.3,
    "confirm your": 1.0,
    "password": 1.0,
    "security alert": 2.0,
    "account": 0.5,
    "investment": 1.0,
    "earn": 1.0,
    "income": 1.0,
    "hurry": 1.3,
    "act now": 1.5,
    "limited time": 1.3,
    "click here": 1.0,
    "open the link": 1.2,
}

_LEGIT_KW_RU: dict[str, float] = {
    "олимпиад": -1.5,
    "финалист": -1.3,
    "финал": -0.6,
    "участник заключительного": -1.5,
    "университет": -1.0,
    "стипенди": -1.0,
    "магистратур": -0.8,
    "бакалавр": -0.8,
    "расписание": -1.0,
    "лекци": -0.8,
    "семинар": -0.5,
    "курс": -0.3,
    "конференц": -0.5,
    "научн": -0.5,
    "исследован": -0.5,
    "отписаться": -1.0,
    "отписка": -1.0,
    "unsubscribe": -1.0,
    "настройки уведомлений": -1.0,
    "управление подписк": -1.0,
    "грант": -0.8,
    "конкурс грантов": -1.0,
    "добрый день": -0.3,
    "с уважением": -0.3,
    "информационная безопасность": -1.0,
}


def _char_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text.lower())
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)


def _detect_scripts(text: str) -> list[str]:
    scripts: list[str] = []
    if re.search(r"[а-яёА-ЯЁ]", text):
        scripts.append("cyrillic")
    if re.search(r"[a-zA-Z]", text):
        scripts.append("latin")
    if re.search(r"[\u3040-\u309f\u30a0-\u30ff\u4e00-\u9fff]", text):
        scripts.append("cjk")
    if re.search(r"[\u0600-\u06ff]", text):
        scripts.append("arabic")
    if re.search(r"[\u0e00-\u0e7f]", text):
        scripts.append("thai")
    if re.search(r"[\uac00-\ud7af]", text):
        scripts.append("hangul")
    return scripts


def _detect_contact_form_injection(text: str) -> bool:
    low = text.lower()
    patterns = [
        r"wordpress@",
        r"(?:name|имя|nombre)\s*[:=]\s*\S+.*(?:message|сообщение|mensaje)\s*[:=]",
        r"(?:email|e-mail)\s*[:=]\s*\S+@\S+.*(?:message|subject|body)\s*[:=]",
        r"(?:^|\n)\s*from\s*:\s*\S+@\S+.*\n.*(?:subject|message)\s*:",
        r"[\u3040-\u309f\u30a0-\u30ff\u4e00-\u9fff].*(?:http|https)://.*(?:[а-яё]|выигр|приз|бонус|получи)",
    ]
    return any(re.search(p, low, re.IGNORECASE | re.DOTALL) for p in patterns)


def _extract_money_amounts(text: str) -> list[int]:
    amounts: list[int] = []

    for m in re.finditer(
        r"(\d[\d\s\xa0,.]*\d)\s*(?:руб\.?|₽|rub|рублей|рубля|рубль)",
        text,
        re.IGNORECASE,
    ):
        cleaned = re.sub(r"[\s\xa0,.]", "", m.group(1))
        try:
            amounts.append(int(cleaned))
        except ValueError:
            pass

    for m in re.finditer(r"(?:\$|€|£)\s?(\d[\d\s\xa0,.]*\d)", text, re.IGNORECASE):
        cleaned = re.sub(r"[\s\xa0,.]", "", m.group(1))
        try:
            amounts.append(int(cleaned))
        except ValueError:
            pass
    return sorted(set(amounts), reverse=True)


def _money_suspicion(amounts: list[int]) -> float:
    if not amounts:
        return 0.0
    mx = max(amounts)
    if mx >= 100_000:
        return 2.5
    if mx >= 50_000:
        return 1.8
    if mx >= 10_000:
        return 1.0
    if mx >= 5_000:
        return 0.6
    if mx >= 1_000:
        return 0.3
    return 0.1


def _bayesian_score(text: str) -> tuple[float, list[str]]:
    low = text.lower()
    score = 0.0
    signals: list[str] = []

    for kw, weight in _PHISH_KW_RU.items():
        count = len(re.findall(re.escape(kw), low))
        if count > 0:
            contrib = weight * min(count, 3)
            score += contrib
            signals.append(f"phish_ru:«{kw}» x{count} (+{contrib:.1f})")

    for kw, weight in _PHISH_KW_EN.items():
        count = len(re.findall(r"\b" + re.escape(kw) + r"\b", low))
        if count > 0:
            contrib = weight * min(count, 3)
            score += contrib
            signals.append(f"phish_en:«{kw}» x{count} (+{contrib:.1f})")

    for kw, weight in _LEGIT_KW_RU.items():
        count = len(re.findall(re.escape(kw), low))
        if count > 0:
            contrib = weight * min(count, 3)
            score += contrib
            signals.append(f"legit_ru:«{kw}» x{count} ({contrib:.1f})")

    return score, signals


def _emoji_density(text: str) -> float:
    if not text:
        return 0.0
    emoji_pat = re.compile(
        r"[\U0001F300-\U0001F9FF\U00002600-\U000027BF\U0001FA00-\U0001FA6F"
        r"\U0001FA70-\U0001FAFF\U00002702-\U000027B0\U0001F680-\U0001F6FF"
        r"\U0001F1E0-\U0001F1FF]+",
        flags=re.UNICODE,
    )
    emojis = emoji_pat.findall(text)
    total_emoji_chars = sum(len(e) for e in emojis)
    return total_emoji_chars / max(len(text), 1)


def analyze_text(subject: str, text: str, html: str = "") -> TextAnalysis:
    content = f"{subject} {text}".strip()
    low = content.lower()

    bayes_score, signals = _bayesian_score(content)

    languages = _detect_scripts(content)

    is_injection = _detect_contact_form_injection(content)
    if is_injection:
        bayes_score += 2.0
        signals.append("contact_form_injection (+2.0)")

    amounts = _extract_money_amounts(content)
    money_susp = _money_suspicion(amounts)
    if money_susp > 0:
        bayes_score += money_susp
        signals.append(f"money_amounts: {amounts[:5]} (+{money_susp:.1f})")

    if len(languages) >= 3:
        bayes_score += 2.0
        signals.append(f"multi_script_mix: {languages} (+2.0)")
    elif "cjk" in languages and "cyrillic" in languages:
        bayes_score += 1.8
        signals.append(f"cjk_cyrillic_mix: {languages} (+1.8)")
    elif (
        "cjk" in languages or "arabic" in languages or "thai" in languages
    ) and "cyrillic" in languages:
        bayes_score += 1.5
        signals.append(f"exotic_script_with_cyrillic (+1.5)")

    ed = _emoji_density(content)
    if ed > 0.03:
        bonus = min(ed * 30, 1.5)
        bayes_score += bonus
        signals.append(f"high_emoji_density: {ed:.3f} (+{bonus:.1f})")

    has_urgency = bool(
        re.search(
            r"срочн|немедлен|сейчас|сегодня|прямо сейчас|последний шанс|"
            r"urgent|immediately|right now|last chance|hurry|"
            r"в течение \d|осталось \d|только до \d|до \d+ "
            r"(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)",
            low,
        )
    )

    has_credential_request = bool(
        re.search(
            r"парол|пин.?код|код из смс|2fa|одноразов|войти в аккаунт|"
            r"подтвердите личн|verification code|login|password|pin code|"
            r"введите код|введите пароль|отправьте код",
            low,
        )
    )

    has_prize_lure = bool(
        re.search(
            r"выигры|приз(?:ы|ов|а)?\b|розыгрыш|лотере|побед|congratulat|winner|"
            r"you won|вам достал|вы выбраны|selected|удача принесла|"
            r"промо(?:акц|ция)|grand promotion|free tries|"
            r"получите приз|раздаёт техник|раздает техник",
            low,
        )
    )

    has_threat = bool(
        re.search(
            r"заблок|удален|взлом|suspend|restrict|compromis|"
            r"несанкционирован|деактивир|disabled|terminated|"
            r"security alert|подозрительная активн",
            low,
        )
    )

    has_monetary_lure = bool(amounts) or bool(
        re.search(
            r"\d[\d\s,.]+\s*(?:руб|₽|rub|usd|eur|\$|€)|"
            r"зачислен|доступн.*к.*использован|готовы к|"
            r"credited|available.*balance|transfer|"
            r"на.*ваш.*счёт|на.*ваш.*счет",
            low,
        )
    )

    has_call_to_action = bool(
        re.search(
            r"перейдите\s+по\s+ссылк|нажмите\s+на\s+кнопк|"
            r"activate|verify|open\s+the\s+link|"
            r"кликни|нажми|перейди|откройте|"
            r"click here|act now|register now|"
            r"завершите регистрац|подтвердите участие",
            low,
        )
    )

    entropy = _char_entropy(content)

    phishing_score = 1.0 / (1.0 + math.exp(-0.18 * (bayes_score - 4.0)))

    return TextAnalysis(
        phishing_score=phishing_score,
        signals=signals,
        language_mix=languages,
        is_contact_form_injection=is_injection,
        has_urgency=has_urgency,
        has_monetary_lure=has_monetary_lure,
        has_credential_request=has_credential_request,
        has_prize_lure=has_prize_lure,
        has_threat=has_threat,
        has_call_to_action=has_call_to_action,
        text_entropy=entropy,
        suspicious_money_amounts=amounts[:10],
        ml_score=None,
        ml_label=None,
    )


_ZSC_PIPELINE = None
_ZSC_LOADED = False


def _load_zsc():
    global _ZSC_PIPELINE, _ZSC_LOADED
    if _ZSC_LOADED:
        return _ZSC_PIPELINE
    _ZSC_LOADED = True
    try:
        from transformers import pipeline as tf_pipeline

        _ZSC_PIPELINE = tf_pipeline(
            "zero-shot-classification",
            model="MoritzLaurer/mDeBERTa-v3-base-mnli-xnli",
            device=-1,
        )
    except Exception:
        _ZSC_PIPELINE = None
    return _ZSC_PIPELINE


def ml_classify_text(
    text: str, use_ml: bool = True
) -> tuple[Optional[float], Optional[str]]:
    if not use_ml or not text or not text.strip():
        return None, None

    pipe = _load_zsc()
    if pipe is None:
        return None, None

    try:
        snippet = text[:512]
        result = pipe(
            snippet,
            candidate_labels=[
                "фишинговое мошенничество",
                "спам с обещанием денег",
                "легитимное деловое письмо",
                "легитимное уведомление от организации",
                "попытка кражи учётных данных",
            ],
            hypothesis_template="Это {}.",
            multi_label=False,
        )

        phishing_labels = {
            "фишинговое мошенничество",
            "попытка кражи учётных данных",
            "спам с обещанием денег",
        }
        top_label = result["labels"][0]

        phish_prob = sum(
            s
            for l, s in zip(result["labels"], result["scores"])
            if l in phishing_labels
        )

        return float(phish_prob), str(top_label)
    except Exception:
        return None, None
