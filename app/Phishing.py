import argparse
import base64
import html
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from email import message_from_string
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

HTTP = 80
HTTPS = 443

DATA_DIR = Path(__file__).resolve().parent / "data"

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
# "[^<>]" and the 2000-character limit keep these fast on huge or broken HTML (a 5 MB upload can't stall a worker)
ANCHOR_RE = re.compile(r"<a\s[^<>]*?href\s*=\s*[\"']([^\"'<>]+)[\"'][^<>]*>(.{0,2000}?)</a>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^<>]+>")
# CSS, scripts and HTML comments are not text the reader sees
HIDDEN_RE = re.compile(r"<!--.*?(?:-->|\Z)|<(style|script)\b.*?(?:</\1\s*>|\Z)", re.IGNORECASE | re.DOTALL)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
LATIN_RE = re.compile(r"[a-z]", re.IGNORECASE)
CYRILLIC_GREEK_RE = re.compile(r"[Ͱ-ϿЀ-ӿ]")

PHISHING_THRESHOLD = 50
SUSPICIOUS_THRESHOLD = 25


VERDICT_LABELS = {"phishing": "LIKELY PHISHING", "suspicious": "SUSPICIOUS", "safe": "LIKELY SAFE"}
CATEGORY_CAPS = {"links": 50, "sender": 50, "wording": 30, "attachments": 50, "history": 30}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
                  "did.li", "t.ly", "rb.gy", "s.id", "tiny.cc", "bit.do", "v.gd", "qrco.de", "urlz.fr"}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "work", "loan", "support", "rest",
                   "shop", "best", "sbs", "cfd", "icu", "cyou", "buzz", "monster", "bond", "site", "online", "fail"}
# free hosting that phishing kits use for throw-away login pages
FREE_HOSTING = {"ipfs.io", "dweb.link", "cloudflare-ipfs.com", "r2.dev", "workers.dev", "pages.dev", "vercel.app", "glitch.me",
                "sslip.io", "nip.io", "firebaseapp.com", "web.app", "000webhostapp.com", "weebly.com", "weeblysite.com",
                "wixsite.com", "netlify.app", "herokuapp.com", "ngrok.io", "ngrok-free.app", "square.site", "webflow.io"}
SECOND_LEVEL_SUFFIXES = {"co", "com", "net", "org", "gov", "ac", "edu"}
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s")]
# brands that are also everyday words (live.example.com, home-office.gov.uk): only flagged when the whole domain is imitated
COMMON_WORD_BRANDS = {"live", "office", "outlook", "chase", "zoom"}
# mailing lists rewrite Reply-To and forward replies, so those sender checks don't apply to them
LIST_HEADERS = ("List-Id", "List-Post", "Mailing-List")

# category: (points, patterns). Each pattern is a regular expression matched on whole words of the lower-case text.
SUSPICIOUS_PHRASES = {
    "urgency": (10, [r"urgent(?:ly)?", r"immediately", r"(?:with)?in (?:the next )?(?:24|48|72) ?(?:hours|hrs)",
                     r"you have (?:24|48|72) ?(?:hours|hrs)", r"final (?:notice|warning|reminder)", r"last warning",
                     r"expire[sd]? (?:today|soon|shortly|tomorrow)", r"action required", r"attention required",
                     r"immediate action", r"as soon as possible"]),
    "account threat": (10, [r"account (?:will|may|could) be (?:suspended|closed|deactivated|disabled|terminated|deleted|locked|restricted|blocked)",
                            r"account (?:has been|is|was) (?:temporarily )?(?:suspended|closed|deactivated|disabled|locked|restricted|limited|compromised|blocked|on hold)",
                            r"unusual (?:sign-?in |login )?activity", r"unauthori[sz]ed (?:access|login|sign-?in|transaction|activity)",
                            r"suspicious (?:activity|login|sign-?in)", r"security alert",
                            r"(?:deactivat|suspend|terminat|disabl)\w* (?:of )?your (?:account|mailbox|e-?mail)"]),
    "mailbox problem": (10, [r"password\w*(?: \w+){0,4} expir\w*", r"mailbox (?:is )?(?:almost |nearly )?full",
                             r"(?:storage|quota) (?:is )?(?:almost |nearly )?(?:full|exceeded)",
                             r"(?:incoming|pending|held|blocked|undelivered|suspended) (?:e-?mail )?(?:messages|mails|emails)",
                             r"failed (?:e-?mail )?deliver(?:y|ies)",
                             r"messages? (?:have been|has been|were|are|is) (?:blocked|held|suspended|placed on hold|queued|rejected|on hold)"]),
    "credential request": (15, [r"verify your (?:account|identity|e-?mail|details|information|mailbox)",
                                r"confirm your (?:identity|password|account|details|information|e-?mail)",
                                r"update your (?:payment|billing|account|details|information|password|mailbox)",
                                r"(?:log|sign) ?in to (?:your|verify|confirm|update|keep|continue)", r"reset your password",
                                r"enter your (?:password|credentials|login)", r"keep (?:the )?same password",
                                r"validate your (?:account|e-?mail|mailbox|password|details)", r"re-?activate your",
                                r"social security number", r"credit card number"]),
    "financial lure": (10, [r"you have won", r"claim your (?:prize|reward)", r"lottery", r"gift ?card", r"wire transfer",
                            r"bitcoin", r"inheritance", r"unclaimed funds", r"proof of payment",
                            r"payment (?:confirmation|receipt|notification)"]),
    "delivery lure": (10, [r"(?:package|parcel|shipment)\w*(?: \w+){0,4} (?:undeliver\w*|on hold|held|delayed|returned|arrived|ready)",
                           r"(?:transport|delivery|customs|shipping|redelivery) (?:fee|charge)",
                           r"confirm your (?:address|delivery|shipping)"]),
    "document lure": (5, [r"shared (?:a |an )?(?:document|file|item|folder|pdf)s? with you",
                          r"(?:view|review|sign|open|access|download) (?:the |your |this )?(?:document|invoice|statement|receipt|file|pdf|voice ?mail|fax)s?",
                          r"new (?:voice ?mail|fax)", r"invoice"]),
    "generic greeting": (5, [r"dear (?:customer|user|valued|account holder|member|client|sir|madam|e-?mail user|webmail user)"]),
    "greeting by email address": (10, [r"(?:dear|hello|hi) [\w.+-]+@[\w-]+(?:\.[\w-]+)+"]),
    "call to action": (5, [r"click the link below", r"click (?:the )?(?:button|link) below", r"open the attachment",
                           r"download the attachment"]),
    # fake renewals/charges that push the victim to call a "support" number
    "fake charge": (10, [r"if (?:you )?did(?: not|n.t) (?:make|authori[sz]e|place|recogni[sz]e|request|initiate)",
                         r"(?:call|contact|dial|reach)(?: \w+){0,5}:? (?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}",
                         r"toll[- ]free", r"refund (?:help ?line|department|desk|team|line)"]),
}

DANGEROUS_EXTENSIONS = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".ps1", ".jar",
                        ".msi", ".hta", ".com", ".pif", ".lnk", ".wsf", ".cpl", ".dll", ".reg"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
HTML_EXTENSIONS = {".html", ".htm", ".shtml", ".xhtml", ".mht", ".mhtml", ".svg"}
CONTAINER_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".iso", ".img"}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}

def load_email(filename):
    with open(filename, encoding="utf-8", errors="replace") as f:
        return message_from_string(f.read())

def load_list(path):
    try:
        with open(path, encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip() and not line.strip().startswith('#') }
    except FileNotFoundError:
        return set()

BLOCKLIST = load_list(DATA_DIR / "blocklist.txt")
ALLOWLIST = load_list(DATA_DIR / "allowlist.txt")
BRANDS = {legit.split(".")[0] for legit in ALLOWLIST}

def finding(category, weight, detail):
    return {"category": category, "weight": weight, "detail": detail}

def decode_header_value(value):
    # Used to convert encoded email headers to readable outputs
    try:
        return str(make_header(decode_header(value or "")))
    except Exception:
        return str(value or "")

def parse_address(value):
    # (display name, address). Phishing often sends malformed From headers ("Help Desk 08:41:40 pm <x@evil.com>")
    # that the standard parser mangles, so the "<address>" at the end of the header is taken first.
    value = decode_header_value(value)
    match = re.search(r"<([^<>\s]*@[^<>\s]*)>\s*$", value)
    if match:
        return value[:match.start()].strip().strip('"').strip(), match.group(1)
    return parseaddr(value)

def get_body(msg):
    chunks =[]
    for part in msg.walk():
        #make sure we get to the root of the email and not a container/attached file
        if part.is_multipart() or part.get_filename():
            continue
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        # check if email is encoded, if so decodes it.
        if str(part.get("Content-Transfer-Encoding", "")).strip().lower() in ("base64", "quoted-printable"):
            payload = part.get_payload(decode=True) or b""
            try:
                chunks.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
            except LookupError:
                chunks.append(payload.decode("utf-8", errors="replace"))
        else:
            chunks.append(part.get_payload())
    return "\n".join(chunks)

def registered_domain(host):
    # parses the domain into its standard form for testing
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

def trusted(host):
    # allowlisted domains, and the same brands' country domains (amazon.co.uk, paypal.de)
    domain = registered_domain(host)
    if domain in ALLOWLIST:
        return True
    name, _, suffix = domain.partition(".")
    labels = suffix.split(".")
    country = (len(labels) == 1 and len(suffix) == 2) or (
        len(labels) == 2 and labels[0] in SECOND_LEVEL_SUFFIXES and len(labels[1]) == 2)
    return name in BRANDS and country and labels[-1] not in SUSPICIOUS_TLDS

def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def hostname(link):
    try:
        return (urlsplit(link).hostname or "").lower()
    except ValueError:  # not a valid URL, e.g. "http://["
        return ""

def decode_base64(text):
    # phishing kits base64-encode the victim's address or the real URL, sometimes twice
    for _ in range(2):
        try:
            text = base64.b64decode(text.translate(str.maketrans("-_", "+/")) + "=" * (-len(text) % 4)).decode("utf-8")
        except ValueError:  # not base64, or not text
            return ""
        if "@" in text or text.startswith("http"):
            return text
    return text

def redirect_target(parts):
    # a URL hidden in the query string: google.com/url?q=https://..., or base64-encoded: ?to=aHR0cHM6Ly9...
    for _, value in parse_qsl(parts.query):
        value = unquote(value).strip()
        if value.lower().startswith(("http://", "https://")):
            return value
        if value.startswith("aHR0c"):  # "http" in base64
            decoded = decode_base64(value)
            if decoded.startswith(("http://", "https://")):
                return decoded
    return None

def destination(link):
    # the host a link really leads to, following a redirect hidden in its query string
    try:
        parts = urlsplit(link)
    except ValueError:
        return ""
    target = redirect_target(parts)
    return hostname(target) if target else (parts.hostname or "").lower()

def edit_distance(a,b):
    # measures how many single-character operations are needed to make string a into string b
    previous = list(range(len(b) +1))
    for i, ca in enumerate(a,1):
        current = [i]
        for j, cb in enumerate(b,1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]

def normalize_homoglyphs(text):
    for fake,real in HOMOGLYPHS:
        text = text.replace(fake, real)
    return text

@lru_cache(maxsize=4096)  # newsletters repeat the same hosts many times
def impersonated_brand(host):
    # returns the allowlisted domain that `host` imitates (paypa1.com, paypal.com.evil.xyz, ...), or None.
    if trusted(host) or is_ip(host):
        return None
    domain = registered_domain(host)
    host = normalize_homoglyphs(host.lower())
    tokens = set(re.split(r"[.\-]", host))
    name = normalize_homoglyphs(domain.split(".")[0])
    for legit in sorted(ALLOWLIST):
        brand = legit.split(".")[0]
        # the whole domain is embedded: paypal.com.evil.xyz, outlook-com.evil.biz
        if re.search(rf"(?:^|\.){re.escape(legit)}(?:\.|$)", host.replace("-", ".")):
            return legit
        if len(brand) < 4:
            continue
        one_typo = len(brand) >= 5 and abs(len(brand) - len(name)) <= 1 and edit_distance(brand, name) <= 1
        if (brand in tokens and brand not in COMMON_WORD_BRANDS) or name == brand or one_typo:
            return legit
    return None

def lookalike_words(text):
    # words that mix Latin letters with Cyrillic/Greek look-alikes, e.g. "Сhase" written with a Cyrillic "С"
    return [word for word in re.findall(r"\w+", text) if LATIN_RE.search(word) and CYRILLIC_GREEK_RE.search(word)]

def malicious_link_test(link, redirected=False):
    try:
        parts = urlsplit(link)
        host = (parts.hostname or "").lower()
    except ValueError:
        return []
    if not host:
        return []
    findings = []
    target = redirect_target(parts)
    if target and not redirected:
        target_host = hostname(target)
        if target_host and registered_domain(target_host) != registered_domain(host):
            # an open redirect on a trusted site (google.com/url?q=...) would otherwise hide the destination completely
            weight = 15 if trusted(host) else 10
            findings.append(finding("links", weight, f"Link redirects through {host} to hide its real destination: {target_host}"))
            findings += malicious_link_test(target, redirected=True)
    if trusted(host):
        return findings
    domain = registered_domain(host)
    if host in BLOCKLIST or domain in BLOCKLIST:
        findings.append(finding("links", 40, f"Link goes to a blocklisted domain: {link}"))
    if is_ip(host):
        findings.append(finding("links", 25, f"Link points to a raw IP address: {link}"))
    if parts.username:
        findings.append(finding("links", 20, f"Link hides its real host behind '@': {link}"))
    if "xn--" in host:
        findings.append(finding("links", 15, f"Link uses a punycode (look-alike characters) domain: {link}"))
    brand = impersonated_brand(host)
    if brand:
        findings.append(finding("links", 25, f"Link domain {host} imitates {brand}"))
    if domain in URL_SHORTENERS:
        findings.append(finding("links", 10, f"Link uses a URL shortener that hides the destination: {link}"))
    if domain in FREE_HOSTING or ".ipfs." in host or parts.path.startswith("/ipfs/"):
        findings.append(finding("links", 15, f"Link points to free web hosting often used for phishing pages: {link}"))
    if domain.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        findings.append(finding("links", 10, f"Link uses an uncommon top-level domain: {link}"))
    try:
        if parts.port and parts.port not in (HTTP, HTTPS):
            findings.append(finding("links", 10, f"Link uses a non-standard port: {link}"))
    except ValueError:
        findings.append(finding("links", 10, f"Link has an invalid port: {link}"))
    # the part after "#" never reaches the server: phishing kits put the victim's address there to pre-fill a fake login
    fragment = unquote(parts.fragment)
    address = EMAIL_RE.search(fragment) or EMAIL_RE.search(decode_base64(fragment.strip("/#?=&!")))
    if address:
        findings.append(finding("links", 25, f"Link carries an email address ({address.group()}) to pre-fill a fake login page: {link}"))
    return findings

def check_links(body):
    findings =[]
    seen = set()
    for link in sorted({link.rstrip(".,;:!?)]") for link in URL_RE.findall(body)}):
        host = hostname(link)
        for f in malicious_link_test(link):
            # report each problem once per host: newsletters repeat the same host dozens of times
            key = (f["detail"].split(": ")[0], host)
            if key not in seen:
                seen.add(key)
                findings.append(f)
    for href,text in ANCHOR_RE.findall(body):
        shown = html.unescape(TAG_RE.sub("", text)).strip()
        if shown.lower().startswith("www."):
            shown = "http://" + shown
        if not shown.lower().startswith(("http://", "https://")):
            continue
        shown_host, real_host = hostname(shown), destination(html.unescape(href))
        # unescaping ensures the script inspects the actual,
        # clean destination URL rather than getting tripped up by HTML formatting symbols.
        if not shown_host or not real_host or trusted(real_host):
            continue
        key = (registered_domain(shown_host), registered_domain(real_host))
        if key[0] != key[1] and key not in seen:
            seen.add(key)
            # showing a trusted brand's address is the classic trick; other mismatches are often newsletter click tracking
            weight = 30 if trusted(shown_host) else 10
            findings.append(finding("links", weight, f"Link text shows {shown_host} but actually opens {real_host}"))
    return findings

def check_sender(msg):
    if msg.get("From") is None:
        return []  # pasted text without headers: nothing to check
    name, address = parse_address(msg.get("From"))
    if "@" not in address:
        return [finding("sender", 10, f"Missing or malformed From address: {msg.get('From')!r}")]

    findings = []
    domain = address.rsplit("@", 1)[1].lower()
    subject = decode_header_value(msg.get("Subject", ""))
    mailing_list = any(msg.get(header) for header in LIST_HEADERS)
    if domain in BLOCKLIST or registered_domain(domain) in BLOCKLIST:
        findings.append(finding("sender", 40, f"Sender domain is blocklisted: {domain}"))
    brand = impersonated_brand(domain)
    if brand:
        findings.append(finding("sender", 30, f"Sender domain {domain} imitates {brand}"))
    if domain.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        findings.append(finding("sender", 10, f"Sender uses an uncommon top-level domain: {domain}"))

    shown_address = EMAIL_RE.search(name)
    name_tokens = set(re.split(r"[^a-z0-9]+", name.lower()))
    claimed = next((legit for legit in sorted(ALLOWLIST) if legit.split(".")[0] in name_tokens), None)
    same_brand = claimed and trusted(domain) and registered_domain(domain).split(".")[0] == claimed.split(".")[0]
    if shown_address and shown_address.group().lower() != address.lower():
        findings.append(finding("sender", 25, f"Display name shows {shown_address.group()} but the real address is {address}"))
    elif claimed and not same_brand:
        findings.append(finding("sender", 20, f"Display name '{name}' claims to be {claimed} but mail comes from {domain}"))

    lookalikes = lookalike_words(name + " " + subject)
    if lookalikes:
        findings.append(finding("sender", 20, f"Name or subject uses look-alike letters from another alphabet: {', '.join(lookalikes[:3])}"))

    other = parse_address(msg.get("Reply-To", ""))[1]
    if not mailing_list and "@" in other and registered_domain(other.rsplit("@", 1)[1]) != registered_domain(domain):
        findings.append(finding("sender", 20, f"Reply-To ({other}) differs from the sender domain ({domain})"))

    auth = str(msg.get("Authentication-Results", "")).lower()
    failed = [mech.upper() for mech in ("spf", "dkim", "dmarc") if re.search(rf"\b{mech}=(?:fail|softfail)", auth)]
    if "SPF" not in failed and re.match(r"\s*(?:fail|softfail)\b", str(msg.get("Received-SPF", "")), re.IGNORECASE):
        failed.insert(0, "SPF")
    if failed:
        findings.append(finding("sender", 15 * len(failed), f"Sender authentication failed: {', '.join(failed)}"))

    if not mailing_list and re.match(r"\s*(re|fwd?)\s*:", subject, re.IGNORECASE) and not (msg.get("In-Reply-To") or msg.get("References")):
        findings.append(finding("sender", 10, "Subject pretends to be a reply/forward, but the message is not part of any thread"))
    return findings

def check_recipient(msg):
    # mass phishing poses as the recipient's own organization (its IT or mail admin) and uses the address instead of a name
    to = next((a.lower() for _, a in getaddresses([decode_header_value(msg.get("To", ""))]) if "@" in a), "")
    name, address = parse_address(msg.get("From", ""))
    if "@" not in to:
        return []
    findings = []
    own = registered_domain(to.rsplit("@", 1)[1])
    org = own.split(".")[0]
    if "@" in address and registered_domain(address.rsplit("@", 1)[1]) != own:
        if own in name.lower() or (len(org) >= 4 and re.search(rf"\b{re.escape(org)}\b", name.lower())):
            findings.append(finding("sender", 25, f"Display name '{name}' poses as your own organization ({own}) "
                                                  f"but mail comes from {address.rsplit('@', 1)[1].lower()}"))
    if to in decode_header_value(msg.get("Subject", "")).lower():
        findings.append(finding("wording", 15, f"Subject contains your email address ({to})"))
    return findings


def check_wording(text):
    text = " ".join(text.lower().split())
    findings = []
    for category, (weight, patterns) in SUSPICIOUS_PHRASES.items():
        hits = [match.group() for match in (re.search(rf"\b{p}\b", text) for p in patterns) if match]
        if hits:
            findings.append(finding("wording", weight, f"{category.capitalize()} language: " + ", ".join(f'"{h}"' for h in hits)))
    return findings

def check_attachments(msg):
    findings = []
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        filename = decode_header_value(filename)
        suffixes = [s.lower() for s in Path(filename).suffixes]
        ext = suffixes[-1] if suffixes else ""
        # checking if the file has any suspicious extension
        if ext in DANGEROUS_EXTENSIONS:
            findings.append(finding("attachments", 40, f"Executable/script attachment: {filename}"))
        elif ext in MACRO_EXTENSIONS:
            findings.append(finding("attachments", 30, f"Macro-enabled Office attachment: {filename}"))
        elif ext in HTML_EXTENSIONS:
            findings.append(finding("attachments", 25, f"HTML/SVG attachment (often a fake login page): {filename}"))
        elif ext in CONTAINER_EXTENSIONS:
            findings.append(finding("attachments", 15, f"Archive/disk-image attachment can hide malware: {filename}"))
        if len(suffixes) >= 2 and suffixes[-2] in DOCUMENT_EXTENSIONS and ext not in DOCUMENT_EXTENSIONS:
            findings.append(finding("attachments", 25, f"Double file extension disguises the real type: {filename}"))
    return findings

def check_history(sender, past_verdicts):
    flagged = sum(1 for verdict in past_verdicts if verdict == "phishing")
    if flagged:
        return [finding("history", min(15 * flagged, 30), f"{sender} was flagged as phishing in {flagged} earlier scan(s)")]
    return []

def risk_score(findings):
    per_category = {}
    for f in findings:
        per_category[f["category"]] = per_category.get(f["category"], 0) + f["weight"]
    return min(100, sum(min(total, CATEGORY_CAPS[category]) for category, total in per_category.items()))

def verdict_for(score):
    if score >= PHISHING_THRESHOLD:
        return "phishing"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "safe"


def analyze_message(msg, history=None):
    body = get_body(msg)
    sender = parse_address(msg.get("From", ""))[1].lower()
    subject = decode_header_value(msg.get("Subject", ""))
    text = html.unescape(TAG_RE.sub(" ", HIDDEN_RE.sub(" ", body)))
    past = history(sender) if history and sender else []
    findings = (
                    check_links(body) +
                    check_sender(msg) +
                    check_recipient(msg) +
                    check_wording(subject + "\n" + text) +
                    check_attachments(msg) +
                    check_history(sender, past)
                )
    score = risk_score(findings)
    return {
        "sender": sender,
        "subject": subject,
        "score": score,
        "verdict": verdict_for(score),
        "findings": sorted(findings, key=lambda f: -f["weight"]),
    }

def analyze_text(raw, history=None):
    return analyze_message(message_from_string(raw), history)

def analyze(filename, history=None):
    return analyze_message(load_email(filename), history)

def past_verdicts(history_file, sender):
    try:
        with open(history_file, encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []
    return [r["verdict"] for r in records if r.get("sender") == sender]

def record_scan(history_file, filename, report):
    Path(history_file).parent.mkdir(parents=True, exist_ok=True)
    record = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "file": str(filename),
              **{key: report[key] for key in ("sender", "subject", "score", "verdict")}}
    with open(history_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

def print_report(filename, report):
    print(f"File:    {filename}")
    print(f"From:    {report['sender'] or '(unknown)'}")
    print(f"Subject: {report['subject'] or '(none)'}")
    print(f"Verdict: {VERDICT_LABELS[report['verdict']]} (risk score {report['score']}/100)")
    if report["findings"]:
        print("Indicators:")
        for f in report["findings"]:
            print(f"  +{f['weight']:<3} [{f['category']}] {f['detail']}")
    else:
        print("No phishing indicators found.")

def main(argv=None):
    parser = argparse.ArgumentParser(description="Scan email files for phishing indicators.")
    parser.add_argument("files", nargs="+", help="email file(s): raw .eml or plain text")
    parser.add_argument("--json", action="store_true", help="print the full reports as JSON")
    parser.add_argument("--history", default=str(DATA_DIR / "history.jsonl"),
                        help="JSON-lines file where every scan is recorded (default: %(default)s)")
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(errors="replace")
    # encoding safety, making python not crash via UnicodeEncodeError when printing reports to the terminal.
    reports = {}
    for filename in args.files:
        report = analyze(filename, history=lambda sender: past_verdicts(args.history, sender))
        record_scan(args.history, filename, report)
        reports[filename] = report
        if not args.json:
            print_report(filename, report)
            print()
    if args.json:
        print(json.dumps(reports, indent=2))


if __name__ == "__main__":
    main()
