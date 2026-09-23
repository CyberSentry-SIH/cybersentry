import email
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
import hashlib
import ipaddress
import re
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup

def get_safe_part_text(part) -> str:
    """B08: Robust text extractor that safely handles invalid/unknown character sets."""
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            raw_val = part.get_payload()
            return str(raw_val) if raw_val else ""

        charset = part.get_content_charset()
        if charset:
            try:
                return payload.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError, ValueError):
                pass

        # Fallback to UTF-8 replace
        try:
            return payload.decode("utf-8", errors="replace")
        except Exception:
            return payload.decode("latin-1", errors="replace")
    except Exception:
        try:
            return str(part.get_payload() or "")
        except Exception:
            return ""

def parse_eml_bytes(file_bytes: bytes) -> Dict[str, Any]:
    """
    B07 & B08: Evidentiary RFC 5322 parser.
    Fails safely on malformed emails, unknown charsets, and extracts initial magic bytes for attachments.
    """
    if not file_bytes:
        return {
            "parser_status": "FAILED",
            "error": "Empty file bytes",
            "headers": {},
            "body_text": "",
            "body_html": "",
            "urls": [],
            "attachments": [],
            "hops": [],
            "auth_results": {}
        }

    try:
        msg = email.message_from_bytes(file_bytes, policy=policy.default)
    except Exception as e:
        return {
            "parser_status": "FAILED",
            "error": str(e),
            "headers": {},
            "body_text": "",
            "body_html": "",
            "urls": [],
            "attachments": [],
            "hops": [],
            "auth_results": {}
        }

    # 1. Headers & Sender info
    from_raw = str(msg.get("From", ""))
    from_name, from_address = parseaddr(from_raw)
    from_domain = from_address.split("@")[-1].lower() if "@" in from_address else ""

    reply_to_raw = str(msg.get("Reply-To", ""))
    _, reply_to_addr = parseaddr(reply_to_raw)

    return_path_raw = str(msg.get("Return-Path", ""))
    _, return_path_addr = parseaddr(return_path_raw)

    subject = str(msg.get("Subject", ""))
    message_id = str(msg.get("Message-ID", ""))

    sent_at = None
    if msg.get("Date"):
        try:
            sent_at = parsedate_to_datetime(str(msg.get("Date")))
        except Exception:
            sent_at = None

    # 2. Recipients
    recipients = []
    for to_hdr in msg.get_all("To", []):
        for name, addr in email.utils.getaddresses([str(to_hdr)]):
            if addr:
                recipients.append({"address": addr, "recipient_type": "TO"})
    for cc_hdr in msg.get_all("Cc", []):
        for name, addr in email.utils.getaddresses([str(cc_hdr)]):
            if addr:
                recipients.append({"address": addr, "recipient_type": "CC"})

    # 3. Authentication-Results
    auth_header = str(msg.get("Authentication-Results", ""))
    auth_results = parse_auth_header(auth_header)

    # 4. Received Hops
    received_headers = msg.get_all("Received", [])
    hops = []
    for idx, raw_hop in enumerate(received_headers):
        hops.append({
            "hop_order": idx + 1,
            "raw_value": str(raw_hop).strip(),
            "hostname": extract_hop_hostname(str(raw_hop)),
            "ip_address": extract_hop_ip(str(raw_hop))
        })

    # 5. Extract Body & Attachments safely
    body_text_parts = []
    body_html_parts = []
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            # Attachment handling
            if "attachment" in disposition.lower() or part.get_filename() or content_type == "message/rfc822":
                att_name = part.get_filename() or ("attached_message.eml" if content_type == "message/rfc822" else "unnamed_attachment")
                try:
                    payload = part.get_payload(decode=True) or b""
                except Exception:
                    payload = b""

                att_sha256 = hashlib.sha256(payload).hexdigest()
                ext = ""
                if "." in att_name:
                    ext = f".{att_name.split('.')[-1].lower()}"

                head_bytes = payload[:16]

                attachments.append({
                    "filename": att_name,
                    "content_type": content_type,
                    "size_bytes": len(payload),
                    "sha256": att_sha256,
                    "extension": ext,
                    "head": head_bytes,
                    "metadata_json": {"disposition": disposition}
                })
            else:
                if content_type == "text/plain":
                    body_text_parts.append(get_safe_part_text(part))
                elif content_type == "text/html":
                    body_html_parts.append(get_safe_part_text(part))
    else:
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            body_text_parts.append(get_safe_part_text(msg))
        elif content_type == "text/html":
            body_html_parts.append(get_safe_part_text(msg))

    body_text = "\n".join(p for p in body_text_parts if p)
    body_html = "\n".join(p for p in body_html_parts if p)

    # 6. Extract URLs without executing
    urls = extract_urls_from_content(body_text, body_html)

    return {
        "parser_status": "SUCCESS",
        "message_id": message_id,
        "subject": subject,
        "from_name": from_name,
        "from_address": from_address,
        "from_domain": from_domain,
        "reply_to": reply_to_addr,
        "return_path": return_path_addr,
        "sent_at": sent_at,
        "recipients": recipients,
        "hops": hops,
        "auth_results": auth_results,
        "body_text": body_text,
        "body_html": body_html,
        "urls": urls,
        "attachments": attachments
    }

def parse_auth_header(auth_header: str) -> Dict[str, Any]:
    res = {
        "raw_header": auth_header,
        "spf_result": "NONE",
        "dkim_result": "NONE",
        "dmarc_result": "NONE"
    }
    if not auth_header:
        return res

    clean_header = auth_header.lower()

    # SPF
    spf_match = re.search(r'spf=(\w+)', clean_header)
    if spf_match:
        res["spf_result"] = spf_match.group(1).upper()

    # DKIM
    dkim_match = re.search(r'dkim=(\w+)', clean_header)
    if dkim_match:
        res["dkim_result"] = dkim_match.group(1).upper()

    # DMARC
    dmarc_match = re.search(r'dmarc=(\w+)', clean_header)
    if dmarc_match:
        res["dmarc_result"] = dmarc_match.group(1).upper()

    return res

def extract_urls_from_content(text: str, html: str) -> List[str]:
    urls = set()

    url_pattern = re.compile(r'https?://[^\s<>"\')]+', re.IGNORECASE)
    for u in url_pattern.findall(text or ""):
        urls.add(u.rstrip('.,;)'))

    if html:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all(["a", "form"], href=True):
                href = a.get("href", "").strip()
                if href.startswith("http://") or href.startswith("https://"):
                    urls.add(href)
            for form in soup.find_all("form", action=True):
                act = form.get("action", "").strip()
                if act.startswith("http://") or act.startswith("https://"):
                    urls.add(act)
        except Exception:
            for u in url_pattern.findall(html):
                urls.add(u.rstrip('.,;)'))

    return list(urls)

def extract_hop_hostname(raw_hop: str) -> Optional[str]:
    match = re.search(r'from\s+([a-zA-Z0-9\.\-]+)', raw_hop, re.IGNORECASE)
    return match.group(1) if match else None

def extract_hop_ip(raw_hop: str) -> Optional[str]:
    """Extract IPv4 or IPv6 connecting peer address from Received header."""
    match = re.search(r'\[(?:IPv6:)?([0-9a-fA-F:.]+)\]', raw_hop)
    if match:
        ip_str = match.group(1)
        try:
            parsed = ipaddress.ip_address(ip_str)
            return str(parsed)
        except ValueError:
            pass

    match_v4 = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', raw_hop)
    if match_v4:
        try:
            parsed = ipaddress.ip_address(match_v4.group(1))
            return str(parsed)
        except ValueError:
            pass
    return None
