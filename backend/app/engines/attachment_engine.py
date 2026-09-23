import os
import re
from typing import List, Dict, Any, Optional

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".msc", ".hta", ".cpl", ".jar",
    ".sh", ".bin", ".elf", ".iso", ".img", ".vhd", ".dll", ".sys"
}

MACRO_OFFICE_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".xlam", ".ppam"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".ace", ".iso"
}

# Known magic byte signatures
MAGIC_SIGNATURES = {
    b"MZ": "DOS/Windows Executable (PE/EXE/DLL)",
    b"\x7fELF": "Linux ELF Executable",
    b"PK\x03\x04": "ZIP/Office Archive",
    b"Rar!\x1a\x07": "RAR Archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip Archive",
    b"%PDF": "PDF Document"
}

def analyze_attachments(attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    B07: Forensic attachment risk engine.
    Analyzes attachments for executables, double extensions, magic byte anomalies,
    macro scripts, and archive obfuscation.
    """
    findings = []
    signals = {
        "has_attachments": bool(attachments),
        "attachment_count": len(attachments),
        "has_executable_attachment": False,
        "has_double_extension": False,
        "has_macro_attachment": False,
        "has_magic_mismatch": False
    }

    if not attachments:
        return {"findings": findings, "signals": signals, "attachments_analyzed": 0}

    for att in attachments:
        fname = (att.get("filename") or "").strip()
        ext = (att.get("extension") or "").lower().strip()
        if not ext and "." in fname:
            ext = f".{fname.split('.')[-1].lower()}"

        head = att.get("head") or b""
        if isinstance(head, str):
            head = head.encode("latin-1")
        head_bytes = head[:16]

        size_bytes = att.get("size_bytes", 0)
        sha256 = att.get("sha256", "")
        content_type = (att.get("content_type") or "").lower()

        # 1. Executable / Script Extension (+35)
        if ext in EXECUTABLE_EXTENSIONS or content_type in ("application/x-msdownload", "application/x-executable"):
            signals["has_executable_attachment"] = True
            findings.append({
                "category": "ATTACHMENT",
                "code": "EXECUTABLE_ATTACHMENT",
                "title": f"Dangerous Executable/Script Attachment ({fname})",
                "description": f"Attachment '{fname}' has high-risk executable or script extension '{ext}'.",
                "severity": "CRITICAL",
                "risk_contribution": 35.0,
                "evidence": {"filename": fname, "extension": ext, "sha256": sha256, "size_bytes": size_bytes}
            })

        # 2. Double Extension Detection (e.g. Invoice.pdf.exe) (+25)
        # Matches patterns like filename.ext1.ext2 where ext1 is document/image and ext2 is executable
        fname_lower = fname.lower()
        parts = fname_lower.split(".")
        if len(parts) >= 3:
            penultimate = f".{parts[-2]}"
            if penultimate in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt", ".mp4"):
                signals["has_double_extension"] = True
                findings.append({
                    "category": "ATTACHMENT",
                    "code": "DOUBLE_EXTENSION_ATTACHMENT",
                    "title": f"Deceptive Double-Extension Attachment ({fname})",
                    "description": f"Attachment disguises its true file type using double extension '{penultimate}{ext}'.",
                    "severity": "CRITICAL",
                    "risk_contribution": 25.0,
                    "evidence": {"filename": fname, "disguised_as": penultimate, "real_extension": ext}
                })

        # 3. Magic-Byte vs Extension Mismatch (+40)
        # E.g. PE header MZ or ELF inside a .pdf / .jpg / .txt
        if head_bytes.startswith(b"MZ") and ext not in EXECUTABLE_EXTENSIONS:
            signals["has_magic_mismatch"] = True
            findings.append({
                "category": "ATTACHMENT",
                "code": "MAGIC_BYTE_MISMATCH",
                "title": f"Malicious File Masquerading via Extension Mismatch ({fname})",
                "description": f"Attachment '{fname}' has non-executable extension '{ext}' but starts with Windows PE magic bytes 'MZ'.",
                "severity": "CRITICAL",
                "risk_contribution": 40.0,
                "evidence": {"filename": fname, "extension": ext, "magic": "MZ (PE/COFF)", "head_hex": head_bytes.hex()}
            })
        elif head_bytes.startswith(b"\x7fELF") and ext not in EXECUTABLE_EXTENSIONS:
            signals["has_magic_mismatch"] = True
            findings.append({
                "category": "ATTACHMENT",
                "code": "MAGIC_BYTE_MISMATCH",
                "title": f"Malicious Linux Binary Masquerading via Extension ({fname})",
                "description": f"Attachment '{fname}' has non-executable extension '{ext}' but starts with Linux ELF magic bytes.",
                "severity": "CRITICAL",
                "risk_contribution": 40.0,
                "evidence": {"filename": fname, "extension": ext, "magic": "ELF", "head_hex": head_bytes.hex()}
            })

        # 4. Macro-Enabled Office Documents (+20)
        if ext in MACRO_OFFICE_EXTENSIONS:
            signals["has_macro_attachment"] = True
            findings.append({
                "category": "ATTACHMENT",
                "code": "MACRO_ENABLED_OFFICE_ATTACHMENT",
                "title": f"Macro-Enabled Office Document Attachment ({fname})",
                "description": f"Attachment '{fname}' is a macro-enabled document ({ext}) capable of executing automated VBA code.",
                "severity": "HIGH",
                "risk_contribution": 20.0,
                "evidence": {"filename": fname, "extension": ext, "sha256": sha256}
            })

        # 5. Archive / Compressed Container (+12)
        elif ext in ARCHIVE_EXTENSIONS:
            findings.append({
                "category": "ATTACHMENT",
                "code": "ARCHIVE_ATTACHMENT",
                "title": f"Compressed Archive Attachment ({fname})",
                "description": f"Attachment '{fname}' is an archive ({ext}) commonly used to deliver evasive payloads.",
                "severity": "MEDIUM",
                "risk_contribution": 12.0,
                "evidence": {"filename": fname, "extension": ext, "sha256": sha256}
            })

        # 6. Embedded RFC 822 Email Message (+15)
        if ext in (".eml", ".msg") or content_type == "message/rfc822":
            findings.append({
                "category": "ATTACHMENT",
                "code": "EMBEDDED_EMAIL_ATTACHMENT",
                "title": f"Nested RFC 822 Email Attachment ({fname})",
                "description": f"Email contains a nested email attachment ({fname}) which may contain forwarded phishing lures.",
                "severity": "MEDIUM",
                "risk_contribution": 15.0,
                "evidence": {"filename": fname, "extension": ext}
            })

    return {
        "findings": findings,
        "signals": signals,
        "attachments_analyzed": len(attachments)
    }
