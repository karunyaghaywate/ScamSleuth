
from urllib.parse import urlparse
import ipaddress

BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd"
}

SUSPICIOUS_WORDS = {
    "login", "verify", "password", "urgent",
    "account", "free", "bank", "update"
}


def analyze_url(url):
    url = url.strip()

    if not url:
        return None, ["Please enter a URL."], 0

    if any(char.isspace() for char in url):
        return None, ["The URL contains spaces."], 0

    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)
        host = parsed.hostname

        if parsed.scheme not in ("http", "https") or not host:
            return None, ["Invalid or unsupported URL."], 0

        # Reject malformed hostnames and invalid IP addresses.
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if (
                not host.isascii()
                or len(host) > 253
                or any(not part or len(part) > 63 for part in host.split("."))
                or any(
                    not all(c.isalnum() or c == "-" for c in part)
                    or part.startswith("-")
                    or part.endswith("-")
                    for part in host.split(".")
                )
            ):
                return None, ["The hostname looks invalid."], 0

    except ValueError:
        return None, ["Could not parse this URL."], 0

    host = host.lower().rstrip(".")
    findings = []
    score = 0

    if parsed.scheme == "http":
        findings.append("Uses HTTP instead of HTTPS.")
        score += 15

    try:
        ipaddress.ip_address(host)
        findings.append("Uses an IP address instead of a domain name.")
        score += 25
    except ValueError:
        pass

    if host in SHORTENERS:
        findings.append("Uses a URL-shortening service.")
        score += 15

    if "@" in url:
        findings.append("Contains an @ symbol that can mislead readers.")
        score += 20

    for brand, official_domain in BRANDS.items():
        # Brand appears in hostname, but the hostname is not
        # the official domain or one of its subdomains.
        if brand in host and not (
            host == official_domain
            or host.endswith("." + official_domain)
        ):
            findings.append(
                f"Possible {brand} impersonation in the hostname."
            )
            score += 35
            break

    words_in_url = set(
        parsed.path.lower().replace("-", "/").split("/")
    )
    words_in_url.update(parsed.query.lower().replace("-", "/").split("/"))

    matches = words_in_url & SUSPICIOUS_WORDS
    if matches:
        findings.append(
            "Contains sensitive-action keywords: "
            + ", ".join(sorted(matches)) + "."
        )
        score += 10

    score = min(score, 100)

    if not findings:
        findings.append("No configured warning signs were detected.")

    return host, findings, score


def main():
    print("\n=== ScamSleuth: URL Safety Checker ===")
    print("This tool analyzes URL patterns; it does not prove a site is safe.\n")

    url = input("Paste a URL (do not open it): ")

    host, findings, score = analyze_url(url)

    if host is None:
        print("\nInput error:", findings[0])
        return

    print("\nDomain:", host)
    print("Risk indicator score:", score, "/ 100")
    print("\nFindings:")

    for finding in findings:
        print("-", finding)

    if score >= 35:
        print("\nResult: HIGHER RISK INDICATORS")
    elif score >= 15:
        print("\nResult: SOME WARNING SIGNS")
    else:
        print("\nResult: FEW WARNING SIGNS DETECTED")

    print("\nNote: This is a basic heuristic, not a security guarantee.")


if __name__ == "__main__":
    main()
