"""Technology fingerprinting placeholder."""
"""
ATLAS Technology Fingerprinting Engine.

Identifies web technologies using HTTP responses and headers.
Only scan systems you own or are authorized to assess.
"""

import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


USER_AGENT = "ATLAS-Security-Scanner/1.0"


def normalize_url(target):
    """Normalize a target into an HTTP or HTTPS URL."""

    target = target.strip().rstrip("/")

    if not target:
        raise ValueError("Target cannot be empty.")

    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    return target


def detect_server(headers):
    """Identify web server software from HTTP headers."""

    server = headers.get("Server", "")

    if not server:
        return {
            "name": "Unknown",
            "version": None,
            "evidence": None,
        }

    match = re.search(
        r"(Apache|nginx|Microsoft-IIS|LiteSpeed)(?:/([\w.\-]+))?",
        server,
        re.IGNORECASE,
    )

    if match:
        return {
            "name": match.group(1),
            "version": match.group(2),
            "evidence": server,
        }

    return {
        "name": server.split("/")[0],
        "version": None,
        "evidence": server,
    }


def detect_technologies(headers, body):
    """Identify technologies from HTTP headers and page content."""

    technologies = []

    header_checks = {
        "PHP": ["X-Powered-By"],
        "ASP.NET": ["X-Powered-By", "X-AspNet-Version"],
        "Express.js": ["X-Powered-By"],
    }

    for technology, header_names in header_checks.items():
        for header_name in header_names:
            value = headers.get(header_name, "")

            if technology.lower() in value.lower():
                technologies.append({
                    "name": technology,
                    "evidence": f"{header_name}: {value}",
                })
                break

    body_checks = {
        "WordPress": [
            r"wp-content/",
            r"wp-includes/",
        ],
        "Drupal": [
            r"Drupal\.settings",
            r"/sites/default/files/",
        ],
        "Joomla": [
            r"/media/system/js/",
            r"com_content",
        ],
    }

    for technology, patterns in body_checks.items():
        if any(
            re.search(pattern, body, re.IGNORECASE)
            for pattern in patterns
        ):
            technologies.append({
                "name": technology,
                "evidence": "Recognized page fingerprint",
            })

    return technologies


def analyze_security_headers(headers):
    """Check for important HTTP security headers."""

    required_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
    ]

    results = {}

    for header in required_headers:
        value = headers.get(header)

        results[header] = {
            "present": bool(value),
            "value": value,
        }

    return results


def fingerprint_technology(target, timeout=8):
    """Perform HTTP technology fingerprinting."""

    url = normalize_url(target)

    request = Request(
        url,
        headers={"User-Agent": USER_AGENT},
    )

    try:
        with urlopen(
            request,
            timeout=timeout,
            context=ssl.create_default_context(),
        ) as response:

            headers = response.headers
            body = response.read(500_000).decode(
                "utf-8",
                errors="replace",
            )

            return {
                "target": url,
                "status": response.status,
                "final_url": response.url,
                "server": detect_server(headers),
                "technologies": detect_technologies(
                    headers,
                    body,
                ),
                "security_headers": analyze_security_headers(
                    headers,
                ),
                "error": None,
            }

    except HTTPError as error:
        return {
            "target": url,
            "status": error.code,
            "server": detect_server(error.headers),
            "technologies": [],
            "security_headers": analyze_security_headers(
                error.headers,
            ),
            "error": f"HTTP error: {error.code}",
        }

    except (URLError, TimeoutError, OSError, ValueError) as error:
        return {
            "target": url,
            "status": None,
            "server": None,
            "technologies": [],
            "security_headers": {},
            "error": str(error),
        }