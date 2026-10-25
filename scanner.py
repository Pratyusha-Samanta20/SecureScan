"""
scanner.py — SecureScan security-checking logic.

Performs only ordinary HTTP GET requests against the supplied URL.
No exploitation, brute-forcing, port scanning, or credential handling.
"""

import ipaddress
import re
import socket
from urllib.parse import urlparse

import requests

# ── constants ────────────────────────────────────────────────────────────────

TIMEOUT = 10          # seconds
MAX_REDIRECTS = 5

# RFC-1918 / loopback / link-local / cloud-metadata ranges to block
_BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal"}
_BLOCKED_IP_PREFIXES = (
    "169.254.",   # link-local / AWS metadata
)

# Security headers and their check IDs
HEADERS_TO_CHECK = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


# ── URL validation ────────────────────────────────────────────────────────────

def validate_url(url: str) -> tuple[bool, str]:
    """
    Return (True, normalised_url) or (False, error_message).

    Rules
    -----
    - Scheme must be http or https.
    - Hostname must not resolve to a private/loopback/link-local address.
    - Blocked hostnames (localhost, metadata endpoints) are rejected.
    """
    url = url.strip()

    # Only prepend https:// when there is no scheme at all (no "://" present).
    # If the user typed an unsupported scheme like ftp://, reject it explicitly.
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, f"URL scheme '{parsed.scheme}' is not supported. Use http or https."

    hostname = parsed.hostname
    if not hostname:
        return False, "Could not parse a hostname from the URL."

    if hostname.lower() in _BLOCKED_HOSTNAMES:
        return False, f"Scanning '{hostname}' is not permitted."

    # Resolve the hostname and check for private/reserved ranges
    try:
        ip_str = socket.gethostbyname(hostname)
    except socket.gaierror:
        # Let the request attempt handle the DNS error with a friendlier message
        return True, url   # URL shape is fine; actual error surfaced during fetch

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, url

    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return False, (
            f"Scanning private, loopback, or reserved addresses ({ip_str}) "
            "is not permitted."
        )

    for prefix in _BLOCKED_IP_PREFIXES:
        if ip_str.startswith(prefix):
            return False, f"Scanning the address {ip_str} is not permitted."

    return True, url


# ── individual checks ─────────────────────────────────────────────────────────

def _check_https(final_url: str) -> dict:
    uses_https = final_url.startswith("https://")
    return {
        "check": "HTTPS",
        "status": "PASS" if uses_https else "WARNING",
        "value": final_url,
        "explanation": (
            "The final connection uses HTTPS (encrypted)."
            if uses_https
            else "The final connection does not use HTTPS. Data is transmitted in plain text."
        ),
        "recommendation": (
            ""
            if uses_https
            else (
                "Configure the web server to redirect all HTTP traffic to HTTPS "
                "and obtain a valid TLS certificate (e.g. via Let's Encrypt)."
            )
        ),
    }


def _check_header_present(headers: dict, header_name: str) -> dict:
    """Generic presence-only check for a security header."""
    value = headers.get(header_name, "")
    present = bool(value)
    return {
        "check": header_name,
        "status": "PASS" if present else "WARNING",
        "value": value if present else "Not present",
        "explanation": (
            f"Header '{header_name}' is present."
            if present
            else f"Header '{header_name}' was not found in the server response."
        ),
        "recommendation": (
            ""
            if present
            else (
                f"Review whether the '{header_name}' header should be set for this site. "
                "Its absence may represent a missing security configuration. "
                "Consult the OWASP Secure Headers Project for guidance."
            )
        ),
    }


def _check_x_content_type_options(headers: dict) -> dict:
    value = headers.get("X-Content-Type-Options", "")
    if not value:
        return {
            "check": "X-Content-Type-Options",
            "status": "WARNING",
            "value": "Not present",
            "explanation": "Header 'X-Content-Type-Options' was not found in the server response.",
            "recommendation": (
                "Consider setting 'X-Content-Type-Options: nosniff' to prevent browsers "
                "from MIME-sniffing responses away from the declared content type."
            ),
        }
    is_nosniff = value.strip().lower() == "nosniff"
    return {
        "check": "X-Content-Type-Options",
        "status": "PASS" if is_nosniff else "WARNING",
        "value": value,
        "explanation": (
            "Header is present and set to 'nosniff'."
            if is_nosniff
            else f"Header is present but value is '{value}' instead of 'nosniff'."
        ),
        "recommendation": (
            ""
            if is_nosniff
            else "Set the value to 'nosniff': X-Content-Type-Options: nosniff"
        ),
    }


def _check_status(status_code: int) -> dict:
    return {
        "check": "HTTP Response Status",
        "status": "INFO",
        "value": str(status_code),
        "explanation": f"The server returned HTTP status {status_code}.",
        "recommendation": "",
    }


def _check_redirect(original_url: str, final_url: str) -> dict:
    redirected = original_url.rstrip("/") != final_url.rstrip("/")
    return {
        "check": "Redirect",
        "status": "INFO",
        "value": final_url,
        "explanation": (
            f"The request was redirected from {original_url} to {final_url}."
            if redirected
            else "No redirect occurred; the server responded at the original URL."
        ),
        "recommendation": "",
    }


# ── main scan function ────────────────────────────────────────────────────────

def scan_website(url: str) -> dict:
    """
    Perform security checks against *url*.

    Returns a dict with keys:
        success (bool), error (str), original_url, final_url,
        status_code (int), response_headers (dict), checks (list[dict])

    Each item in *checks* is:
        { check, status, value, explanation, recommendation }
    """
    valid, url = validate_url(url)
    if not valid:
        return {"success": False, "error": url}

    original_url = url

    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            #max_redirects=MAX_REDIRECTS,  # requests uses allow_redirects + max_redirects
            allow_redirects=True,
            headers={"User-Agent": "SecureScan/1.0 (educational security header checker)"},
            verify=True,
        )
    except requests.exceptions.SSLError as exc:
        return {
            "success": False,
            "error": (
                f"SSL certificate error: {exc}. "
                "The site may have an invalid or self-signed certificate."
            ),
        }
    except requests.exceptions.ConnectionError as exc:
        return {
            "success": False,
            "error": (
                f"Connection failed: {exc}. "
                "Check the URL and ensure the site is reachable."
            ),
        }
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": f"Request timed out after {TIMEOUT} seconds.",
        }
    except requests.exceptions.TooManyRedirects:
        return {
            "success": False,
            "error": f"Too many redirects (limit: {MAX_REDIRECTS}).",
        }
    except requests.exceptions.RequestException as exc:
        return {"success": False, "error": f"Request error: {exc}"}

    final_url = response.url
    status_code = response.status_code
    resp_headers = dict(response.headers)

    checks: list[dict] = []

    # 1. HTTPS
    checks.append(_check_https(final_url))

    # 2. Redirect / final URL
    checks.append(_check_redirect(original_url, final_url))

    # 3. HTTP response status
    checks.append(_check_status(status_code))

    # 4. Strict-Transport-Security
    checks.append(_check_header_present(resp_headers, "Strict-Transport-Security"))

    # 5. Content-Security-Policy
    checks.append(_check_header_present(resp_headers, "Content-Security-Policy"))

    # 6. X-Content-Type-Options (special: also checks value)
    checks.append(_check_x_content_type_options(resp_headers))

    # 7. X-Frame-Options
    checks.append(_check_header_present(resp_headers, "X-Frame-Options"))

    # 8. Referrer-Policy
    checks.append(_check_header_present(resp_headers, "Referrer-Policy"))

    # 9. Permissions-Policy
    checks.append(_check_header_present(resp_headers, "Permissions-Policy"))

    return {
        "success": True,
        "error": "",
        "original_url": original_url,
        "final_url": final_url,
        "status_code": status_code,
        "response_headers": resp_headers,
        "checks": checks,
    }
