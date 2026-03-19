import json
import os
import streamlit as st

from mailguard.eml_parser import parse_eml_bytes
from mailguard.url_parser import extract_all_urls, dedupe_links
from mailguard.url_check import check_all_links
from mailguard.qr_tools import extract_qr_links
from mailguard.scoring import overall_score
from mailguard.report import build_report
from mailguard.text_analyzer import analyze_text

st.set_page_config(page_title="MailGuard", layout="wide")
st.title("🛡️ MailGuard — анализатор фишинговых писем (.eml)")

with st.sidebar:
    st.header("⚙️ Настройки")
    online = st.checkbox(
        "Сетевые проверки (редиректы + WHOIS/DNS/TLS + threat intel)",
        value=False,
    )
    use_ml = st.checkbox(
        "🧠 Нейросеть (zero-shot classification)",
        value=False,
        help="Использует модель mDeBERTa для классификации текста. "
        "Требует: pip install transformers torch",
    )
    st.caption(
        "Для threat intel можно задать переменные окружения: "
        "VT_API_KEY и URLHAUS_AUTH_KEY (или URLHAUS_API_KEY)."
    )
    if online:
        vt = bool(os.getenv("VT_API_KEY", "").strip())
        uh = bool(
            os.getenv("URLHAUS_AUTH_KEY", "").strip()
            or os.getenv("URLHAUS_API_KEY", "").strip()
        )
        st.write({"VT_API_KEY": vt, "URLHAUS_KEY": uh})

uploaded = st.file_uploader("Загрузите .eml", type=["eml"])

if not uploaded:
    st.info("Загрузите файл .eml для анализа")
    st.stop()

raw = uploaded.getvalue()
email = parse_eml_bytes(raw)

links = extract_all_urls(email.text, email.html)
links = dedupe_links(links)

qr_links = extract_qr_links(email.attachments)
qr_links = dedupe_links(qr_links)

checked_links = check_all_links(links, online=online)
checked_qr_links = check_all_links(qr_links, online=online)

all_checked = checked_links + checked_qr_links

risk, level, reasons = overall_score(email, all_checked, online=online, use_ml=use_ml)


text_analysis = analyze_text(email.subject or "", email.text or "", email.html or "")
if use_ml:
    from mailguard.text_analyzer import ml_classify_text

    ml_s, ml_l = ml_classify_text(
        f"{email.subject or ''} {(email.text or '')[:800]}",
        use_ml=True,
    )
    text_analysis.ml_score = ml_s
    text_analysis.ml_label = ml_l


st.subheader(f"{level}: {risk:.2f}")


if risk >= 0.85:
    bar_color = "red"
elif risk >= 0.65:
    bar_color = "orange"
elif risk >= 0.40:
    bar_color = "yellow"
else:
    bar_color = "green"
st.progress(min(risk, 1.0))

col1, col2 = st.columns([1, 1])
with col1:
    st.markdown("**📧 Информация о письме**")
    st.write(
        {
            "Subject": email.subject,
            "From": email.from_,
            "To": getattr(email, "to", ""),
            "Reply-To": email.reply_to,
            "Return-Path": email.return_path,
            "Received": len(email.received),
            "Date": getattr(email, "date_str", ""),
        }
    )
with col2:
    st.markdown("**🔐 Аутентификация**")
    if email.auth_results:
        import re

        auth = email.auth_results
        spf_m = re.search(r"spf\s*=\s*(\w+)", auth, re.I)
        dkim_m = re.search(r"dkim\s*=\s*(\w+)", auth, re.I)
        dmarc_m = re.search(r"dmarc\s*=\s*(\w+)", auth, re.I)
        col_spf, col_dkim, col_dmarc = st.columns(3)
        spf_v = spf_m.group(1) if spf_m else "?"
        dkim_v = dkim_m.group(1) if dkim_m else "?"
        dmarc_v = dmarc_m.group(1) if dmarc_m else "?"
        col_spf.metric("SPF", spf_v)
        col_dkim.metric("DKIM", dkim_v)
        col_dmarc.metric("DMARC", dmarc_v)
    else:
        st.info("Authentication-Results отсутствуют")

tabs = st.tabs(
    [
        "📋 Причины",
        "📝 Текст письма",
        "🔗 Ссылки",
        "📱 QR-ссылки",
        "📎 Вложения",
        "🧠 NLP-анализ",
    ]
)

with tabs[0]:
    if not reasons:
        st.success("Сильных фишинговых сигналов не найдено.")
    else:
        for r in reasons:
            if r.startswith("[+") or r.startswith("[+0") or r.startswith("[+1"):
                st.warning("⚠️ " + r)
            elif r.startswith("[-"):
                st.info("✅ " + r)
            else:
                st.write("- " + r)

with tabs[1]:
    st.text_area("text/plain", email.text, height=260)
    if email.html:
        st.text_area("text/html (raw)", email.html[:5000], height=200)

with tabs[2]:
    if not checked_links:
        st.info("Ссылок не найдено.")
    for c in checked_links:
        with st.expander(f"🔗 {c.original_url[:80]}"):
            st.write(f"**Final URL:** {c.final_url}")
            st.write(f"**Domain:** {c.final_domain}")
            st.write(f"**Redirects:** {c.redirect_count} | **HTTPS:** {c.is_https}")
            if c.flags:
                st.write(f"**Flags:** {', '.join(c.flags)}")
            if c.notes:
                st.write(f"**Notes:** {'; '.join(c.notes)}")

with tabs[3]:
    if not checked_qr_links:
        st.info("QR-ссылок не найдено.")
    for c in checked_qr_links:
        with st.expander(f"📱 {c.original_url[:80]}"):
            st.write(f"**Final URL:** {c.final_url}")
            st.write(
                f"**Domain:** {c.final_domain} | **Redirects:** {c.redirect_count}"
            )
            if c.flags:
                st.write(f"**Flags:** {', '.join(c.flags)}")
            if c.notes:
                st.write(f"**Notes:** {'; '.join(c.notes)}")

with tabs[4]:
    if not email.attachments:
        st.info("Вложений не найдено.")
    for a in email.attachments:
        st.write(
            {
                "filename": a.filename,
                "type": a.content_type,
                "size": a.size,
                "inline": a.is_inline,
            }
        )

with tabs[5]:
    st.markdown("**📊 Байесовский NLP-анализ текста**")
    col_a, col_b = st.columns(2)
    col_a.metric("Фишинг-скор", f"{text_analysis.phishing_score:.2f}")
    if text_analysis.ml_score is not None:
        col_b.metric(
            "Нейросеть P(фишинг)",
            f"{text_analysis.ml_score:.2f}",
            help=f"Метка: {text_analysis.ml_label}",
        )
    else:
        col_b.info(
            "Нейросеть не включена"
            if not use_ml
            else "Нейросеть недоступна (pip install transformers torch)"
        )

    st.markdown("**Обнаруженные паттерны:**")
    flags_map = {
        "Приз/выигрыш": text_analysis.has_prize_lure,
        "Денежная приманка": text_analysis.has_monetary_lure,
        "Запрос учётных данных": text_analysis.has_credential_request,
        "Срочность": text_analysis.has_urgency,
        "Угрозы": text_analysis.has_threat,
        "Призыв к действию": text_analysis.has_call_to_action,
        "Инъекция контакт-формы": text_analysis.is_contact_form_injection,
    }
    cols = st.columns(4)
    for idx, (name, val) in enumerate(flags_map.items()):
        with cols[idx % 4]:
            if val:
                st.error(f"🚩 {name}")
            else:
                st.success(f"✅ {name}")

    if text_analysis.suspicious_money_amounts:
        st.write(f"**Денежные суммы:** {text_analysis.suspicious_money_amounts[:10]}")

    if text_analysis.language_mix:
        st.write(f"**Языки/скрипты:** {', '.join(text_analysis.language_mix)}")

    if text_analysis.signals:
        with st.expander("Все NLP-сигналы"):
            for s in text_analysis.signals[:30]:
                st.write(f"- {s}")


report_data = build_report(
    email,
    checked_links,
    checked_qr_links,
    risk,
    level,
    reasons,
    text_analysis=text_analysis,
)
st.download_button(
    "📥 Скачать отчёт (JSON)",
    data=json.dumps(report_data, ensure_ascii=False, indent=2).encode("utf-8"),
    file_name="mailguard_report.json",
    mime="application/json",
)
