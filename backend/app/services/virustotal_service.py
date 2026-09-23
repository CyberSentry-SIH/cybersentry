"""
virustotal_service.py — B20: Hardened VirusTotal API v3 Integration

Key hardening (B20):
- Rate limiting via token bucket (4 req/min free tier default)
- Lookup-only default (VT_SUBMIT_URLS=False prevents URL submission)
- TTL-based in-process cache with configurable expiry
- Timeout hardening with per-request budget
- Graceful degradation on 429/5xx
"""

import time
import base64
import threading
import requests
from typing import Dict, Any, Optional, List
from backend.app.core.config import settings

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# B20: Thread-safe token bucket rate limiter
class _RateLimiter:
    """Token bucket rate limiter for VT free tier (4 requests/minute)."""
    def __init__(self, max_tokens: int = 4, refill_interval: float = 60.0):
        self._max_tokens = max_tokens
        self._tokens = float(max_tokens)
        self._refill_interval = refill_interval
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self._max_tokens, self._tokens + (elapsed / self._refill_interval) * self._max_tokens)
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            time.sleep(0.5)
        return False

_rate_limiter = _RateLimiter()

# B20: TTL-based cache
class _TTLCache:
    """Simple TTL cache for VT results."""
    def __init__(self, ttl_seconds: int = 3600):
        self._store: Dict[str, tuple] = {}  # key -> (result, expiry_time)
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._store.get(key)
            if entry and entry[1] > time.monotonic():
                return entry[0]
            elif entry:
                del self._store[key]
        return None

    def set(self, key: str, value: Dict[str, Any]) -> None:
        with self._lock:
            self._store[key] = (value, time.monotonic() + self._ttl)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

_url_cache = _TTLCache(ttl_seconds=3600)
_hash_cache = _TTLCache(ttl_seconds=3600)


def _vt_headers() -> Dict[str, str]:
    return {
        "x-apikey": settings.VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }


def scan_url_virustotal(url: str) -> Dict[str, Any]:
    """
    B20: Hardened URL lookup against VirusTotal.
    - Rate-limited via token bucket
    - Lookup-only by default (no submission unless VT_SUBMIT_URLS=True)
    - TTL-cached results
    """
    if not url or not settings.VIRUSTOTAL_API_KEY or not settings.ENABLE_EXTERNAL_INTEL:
        return _empty_url_result(url)

    cached = _url_cache.get(url)
    if cached:
        return cached

    if not _rate_limiter.acquire(timeout=10.0):
        res = _empty_url_result(url)
        res["error"] = "RATE_LIMITED"
        res["verdict"] = "RATE_LIMITED"
        return res

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        resp = requests.get(
            f"{VT_BASE_URL}/urls/{url_id}",
            headers=_vt_headers(),
            timeout=8
        )

        if resp.status_code == 404:
            if settings.VT_SUBMIT_URLS:
                sub = requests.post(
                    f"{VT_BASE_URL}/urls",
                    headers=_vt_headers(),
                    data={"url": url},
                    timeout=8
                )
                if sub.status_code not in (200, 202):
                    return _empty_url_result(url)
                time.sleep(2)
                resp = requests.get(
                    f"{VT_BASE_URL}/urls/{url_id}",
                    headers=_vt_headers(),
                    timeout=8
                )
            else:
                res = _empty_url_result(url)
                res["verdict"] = "NOT_FOUND"
                _url_cache.set(url, res)
                return res

        if resp.status_code == 429:
            res = _empty_url_result(url)
            res["error"] = "RATE_LIMITED_BY_VT"
            res["verdict"] = "RATE_LIMITED"
            return res

        if resp.status_code != 200:
            return _empty_url_result(url)

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        result = _build_url_result(url, stats, data)
        _url_cache.set(url, result)
        return result

    except Exception as e:
        res = _empty_url_result(url)
        res["error"] = str(e)
        return res


def scan_hash_virustotal(sha256: str) -> Dict[str, Any]:
    """B20: Hardened file hash lookup against VirusTotal."""
    if not sha256 or not settings.VIRUSTOTAL_API_KEY or not settings.ENABLE_EXTERNAL_INTEL:
        return _empty_hash_result(sha256)

    cached = _hash_cache.get(sha256)
    if cached:
        return cached

    if not _rate_limiter.acquire(timeout=10.0):
        res = _empty_hash_result(sha256)
        res["error"] = "RATE_LIMITED"
        return res

    try:
        resp = requests.get(
            f"{VT_BASE_URL}/files/{sha256}",
            headers=_vt_headers(),
            timeout=8
        )

        if resp.status_code == 404:
            result = _empty_hash_result(sha256)
            result["verdict"] = "NOT_FOUND"
            _hash_cache.set(sha256, result)
            return result

        if resp.status_code == 429:
            res = _empty_hash_result(sha256)
            res["error"] = "RATE_LIMITED_BY_VT"
            return res

        if resp.status_code != 200:
            return _empty_hash_result(sha256)

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        result = _build_hash_result(sha256, stats, data)
        _hash_cache.set(sha256, result)
        return result

    except Exception as e:
        res = _empty_hash_result(sha256)
        res["error"] = str(e)
        return res


def scan_urls_batch(urls: List[str]) -> Dict[str, Dict[str, Any]]:
    """Scan multiple URLs with rate limiting. Limits to 10 URLs max."""
    results = {}
    for url in urls[:10]:
        results[url] = scan_url_virustotal(url)
    return results


# --- helpers ---

def _build_url_result(url: str, stats: dict, raw: dict) -> Dict[str, Any]:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    total = malicious + suspicious + harmless + stats.get("undetected", 0)

    if malicious >= 3:
        verdict = "MALICIOUS"
    elif malicious >= 1 or suspicious >= 3:
        verdict = "SUSPICIOUS"
    elif total > 0:
        verdict = "CLEAN"
    else:
        verdict = "UNKNOWN"

    return {
        "url": url,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "total_engines": total,
        "verdict": verdict,
        "detection_ratio": f"{malicious}/{total}" if total > 0 else "0/0",
        "last_analysis_date": raw.get("data", {}).get("attributes", {}).get("last_analysis_date"),
        "source": "VIRUSTOTAL_V3",
        "enriched": True
    }


def _build_hash_result(sha256: str, stats: dict, raw: dict) -> Dict[str, Any]:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    total = malicious + suspicious + harmless + stats.get("undetected", 0)

    if malicious >= 3:
        verdict = "MALICIOUS"
    elif malicious >= 1 or suspicious >= 2:
        verdict = "SUSPICIOUS"
    elif total > 0:
        verdict = "CLEAN"
    else:
        verdict = "UNKNOWN"

    attrs = raw.get("data", {}).get("attributes", {})
    return {
        "sha256": sha256,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "total_engines": total,
        "verdict": verdict,
        "detection_ratio": f"{malicious}/{total}" if total > 0 else "0/0",
        "file_name": attrs.get("meaningful_name", ""),
        "file_type": attrs.get("type_description", ""),
        "file_size": attrs.get("size"),
        "source": "VIRUSTOTAL_V3",
        "enriched": True
    }


def _empty_url_result(url: str) -> Dict[str, Any]:
    return {
        "url": url,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "total_engines": 0,
        "verdict": "PENDING",
        "detection_ratio": "0/0",
        "last_analysis_date": None,
        "source": "UNAVAILABLE",
        "enriched": False
    }


def _empty_hash_result(sha256: str) -> Dict[str, Any]:
    return {
        "sha256": sha256,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "total_engines": 0,
        "verdict": "PENDING",
        "detection_ratio": "0/0",
        "file_name": "",
        "file_type": "",
        "file_size": None,
        "source": "UNAVAILABLE",
        "enriched": False
    }
