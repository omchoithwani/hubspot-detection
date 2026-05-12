#!/usr/bin/env python3
"""
HubSpot Detection Tool

Checks if companies are using HubSpot by analyzing their website domain
through multiple detection methods: DNS records, HTTP headers, HTML/JS
markers, and known HubSpot infrastructure patterns.

Usage:
    python hubspot_detector.py input.csv -o results.csv
"""

import argparse
import csv
import concurrent.futures
import dns.resolver
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# Request configuration
REQUEST_TIMEOUT = 15
MAX_WORKERS = 10
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# HubSpot detection signatures
HUBSPOT_DNS_CNAMES = [
    "hubspot.net",
    "hubspot.com",
    "hs-sites.com",
    "hubspotpagebuilder.com",
    "hscoscdn",
]

HUBSPOT_HEADER_INDICATORS = [
    "x-hs-hub-id",
    "x-hs-content-id",
    "x-hubspot",
    "x-hs-cache",
    "x-hs-cf-ray",
]

HUBSPOT_HTML_PATTERNS = [
    r"js\.hs-scripts\.com",
    r"js\.hsforms\.net",
    r"js\.hscollectedforms\.net",
    r"js\.hs-analytics\.net",
    r"js\.hs-banner\.com",
    r"js\.hsadspixel\.net",
    r"js\.usemessages\.com",
    r"track\.hubspot\.com",
    r"forms\.hubspot\.com",
    r"api\.hubspot\.com",
    r"hbspt\.forms\.create",
    r"hbspt\.cta\.load",
    r"hs-script-loader",
    r"hubspot-messages-iframe-container",
    r"hs-cta-wrapper",
    r"hbs-content-id",
    r"data-hsjs-portal",
    r"data-hs-cos",
    r"_hsp\.push",
    r"_hsq\.push",
    r"HubSpot",
]

HUBSPOT_META_INDICATORS = [
    "hubspot",
    "hs-cos",
    "hubs-content-id",
]

# DNS record types to check for MX-based detection
HUBSPOT_MX_DOMAINS = [
    "hubspot.com",
]


@dataclass
class DetectionResult:
    """Stores detection findings for a single domain."""
    company: str
    domain: str
    uses_hubspot: bool = False
    confidence: str = "none"  # none, low, medium, high
    signals: list = field(default_factory=list)
    hubspot_portal_id: str = ""
    error: str = ""

    def confidence_score(self) -> int:
        """Numeric score based on number and strength of signals."""
        score = 0
        for signal in self.signals:
            if "tracking code" in signal.lower() or "portal id" in signal.lower():
                score += 3
            elif "dns" in signal.lower() or "header" in signal.lower():
                score += 2
            else:
                score += 1
        return score

    def compute_confidence(self):
        """Set confidence level based on accumulated signals."""
        score = self.confidence_score()
        if score == 0:
            self.confidence = "none"
            self.uses_hubspot = False
        elif score <= 1:
            self.confidence = "low"
            self.uses_hubspot = True
        elif score <= 3:
            self.confidence = "medium"
            self.uses_hubspot = True
        else:
            self.confidence = "high"
            self.uses_hubspot = True


def normalize_domain(domain: str) -> str:
    """Normalize a domain string for consistent checking."""
    domain = domain.strip().lower()
    # Remove protocol if present
    if "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.netloc or parsed.path
    # Remove trailing slashes and paths
    domain = domain.split("/")[0]
    # Remove port
    domain = domain.split(":")[0]
    # Remove www prefix for DNS checks but keep for HTTP
    return domain


def check_dns(domain: str, result: DetectionResult):
    """Check DNS records for HubSpot indicators."""
    bare_domain = domain.lstrip("www.")

    # Check CNAME records for the domain and www subdomain
    for subdomain in [bare_domain, f"www.{bare_domain}"]:
        try:
            answers = dns.resolver.resolve(subdomain, "CNAME")
            for rdata in answers:
                target = str(rdata.target).lower()
                for indicator in HUBSPOT_DNS_CNAMES:
                    if indicator in target:
                        result.signals.append(
                            f"DNS CNAME: {subdomain} -> {target}"
                        )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.resolver.Timeout,
                Exception):
            pass

    # Check MX records for HubSpot email hosting
    try:
        answers = dns.resolver.resolve(bare_domain, "MX")
        for rdata in answers:
            exchange = str(rdata.exchange).lower()
            for mx_domain in HUBSPOT_MX_DOMAINS:
                if mx_domain in exchange:
                    result.signals.append(f"DNS MX: {exchange}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.Timeout,
            Exception):
        pass

    # Check TXT records for HubSpot verification
    try:
        answers = dns.resolver.resolve(bare_domain, "TXT")
        for rdata in answers:
            txt = str(rdata).lower()
            if "hubspot" in txt:
                result.signals.append(f"DNS TXT: HubSpot verification record found")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.Timeout,
            Exception):
        pass


def check_http(domain: str, result: DetectionResult):
    """Fetch the website and check HTTP headers and HTML content."""
    urls_to_try = [f"https://{domain}", f"https://www.{domain}"]
    headers = {"User-Agent": USER_AGENT}

    for url in urls_to_try:
        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            resp.raise_for_status()
            _check_headers(resp, result)
            _check_html(resp.text, result)
            _extract_portal_id(resp.text, result)
            return  # Success, no need to try next URL
        except requests.exceptions.SSLError:
            # Try HTTP as fallback
            try:
                http_url = url.replace("https://", "http://")
                resp = requests.get(
                    http_url,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
                _check_headers(resp, result)
                _check_html(resp.text, result)
                _extract_portal_id(resp.text, result)
                return
            except Exception:
                continue
        except requests.exceptions.RequestException:
            continue

    # If we get here, none of the URLs worked — not necessarily an error
    # The DNS checks may still have found something


def _check_headers(resp: requests.Response, result: DetectionResult):
    """Check HTTP response headers for HubSpot indicators."""
    resp_headers = {k.lower(): v for k, v in resp.headers.items()}

    for indicator in HUBSPOT_HEADER_INDICATORS:
        if indicator in resp_headers:
            result.signals.append(
                f"HTTP Header: {indicator}={resp_headers[indicator]}"
            )

    # Check Server header
    server = resp_headers.get("server", "").lower()
    if "hubspot" in server:
        result.signals.append(f"HTTP Header: server={server}")

    # Check for HubSpot cookies in Set-Cookie
    cookies = resp_headers.get("set-cookie", "").lower()
    if "__hs" in cookies or "hubspot" in cookies:
        result.signals.append("HTTP Header: HubSpot cookie detected")


def _check_html(html: str, result: DetectionResult):
    """Check HTML content for HubSpot markers."""
    # Regex-based pattern matching on raw HTML
    for pattern in HUBSPOT_HTML_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            match_label = pattern.replace(r"\.", ".").replace("\\", "")
            result.signals.append(f"HTML pattern: {match_label}")

    # Parse HTML with BeautifulSoup for structured checks
    soup = BeautifulSoup(html, "html.parser")

    # Check meta tags (only match name/property attributes, not free-text content)
    for meta in soup.find_all("meta"):
        name = (meta.get("name") or meta.get("property") or "").lower()
        content = (meta.get("content") or "").lower()
        for indicator in HUBSPOT_META_INDICATORS:
            if indicator in name:
                result.signals.append(f"Meta tag: {name}={content}")
            elif name == "generator" and indicator in content:
                result.signals.append(f"Meta tag: generator={content}")

    # Check for HubSpot script tags specifically
    for script in soup.find_all("script", src=True):
        src = script["src"].lower()
        if "hubspot" in src or "hs-scripts" in src or "hsforms" in src:
            result.signals.append(f"Script src: {src}")

    # Check for HubSpot tracking code pattern in inline scripts
    for script in soup.find_all("script", src=False):
        text = script.string or ""
        if "hs-script-loader" in text or "hbspt" in text:
            result.signals.append("Inline script: HubSpot tracking code")

    # Deduplicate signals
    result.signals = list(dict.fromkeys(result.signals))


def _extract_portal_id(html: str, result: DetectionResult):
    """Try to extract the HubSpot portal/hub ID from page source."""
    patterns = [
        r"js\.hs-scripts\.com/(\d+)\.js",
        r"js\.hsforms\.net/forms/v2\.js.*?portalId[\"':\s]+(\d+)",
        r"data-hsjs-portal=\"(\d+)\"",
        r"hbspt\.forms\.create\([^)]*portalId[\"':\s]+[\"']?(\d+)",
        r"hbspt\.cta\.load\((\d+)",
        r"HubSpot[- ]?Portal[- ]?ID[\"':\s]+(\d+)",
        r"hs-hub-id[\"':\s]+(\d+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            portal_id = match.group(1)
            result.hubspot_portal_id = portal_id
            result.signals.append(f"Portal ID: {portal_id}")
            return


def detect_hubspot(company: str, domain: str) -> DetectionResult:
    """Run all detection methods for a single domain."""
    result = DetectionResult(company=company, domain=domain)
    normalized = normalize_domain(domain)

    if not normalized:
        result.error = "Empty or invalid domain"
        return result

    try:
        check_dns(normalized, result)
        check_http(normalized, result)
    except Exception as e:
        result.error = str(e)
        logger.error("Error checking %s: %s", domain, e)

    result.compute_confidence()
    return result


def read_input_csv(path: str) -> list[dict]:
    """Read input CSV and return list of {company, domain} dicts."""
    rows = []
    filepath = Path(path)
    if not filepath.exists():
        logger.error("Input file not found: %s", path)
        sys.exit(1)

    with open(filepath, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fieldnames = [fn.lower().strip() for fn in (reader.fieldnames or [])]

        # Auto-detect column names
        company_col = None
        domain_col = None

        for fn in reader.fieldnames or []:
            lower = fn.lower().strip()
            if lower in ("company", "company name", "company_name", "name"):
                company_col = fn
            elif lower in ("domain", "website", "url", "site", "web"):
                domain_col = fn

        if domain_col is None:
            logger.error(
                "Could not find a domain column. Expected one of: "
                "domain, website, url, site, web. "
                "Found columns: %s",
                reader.fieldnames,
            )
            sys.exit(1)

        for row in reader:
            domain = (row.get(domain_col) or "").strip()
            company = (row.get(company_col) or domain).strip() if company_col else domain
            if domain:
                rows.append({"company": company, "domain": domain})

    logger.info("Loaded %d entries from %s", len(rows), path)
    return rows


def write_output_csv(results: list[DetectionResult], path: str):
    """Write detection results to a CSV file."""
    fieldnames = [
        "company",
        "domain",
        "uses_hubspot",
        "confidence",
        "hubspot_portal_id",
        "signals",
        "error",
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "company": r.company,
                "domain": r.domain,
                "uses_hubspot": r.uses_hubspot,
                "confidence": r.confidence,
                "hubspot_portal_id": r.hubspot_portal_id,
                "signals": " | ".join(r.signals),
                "error": r.error,
            })

    logger.info("Results written to %s", path)


def print_summary(results: list[DetectionResult]):
    """Print a summary table to stdout."""
    total = len(results)
    using = sum(1 for r in results if r.uses_hubspot)
    errors = sum(1 for r in results if r.error)

    print("\n" + "=" * 70)
    print(f"{'HUBSPOT DETECTION RESULTS':^70}")
    print("=" * 70)
    print(f"  Total domains checked : {total}")
    print(f"  Using HubSpot         : {using}")
    print(f"  Not using HubSpot     : {total - using - errors}")
    print(f"  Errors                : {errors}")
    print("-" * 70)
    print(f"  {'Company':<25} {'Domain':<25} {'HubSpot?':<10} {'Confidence'}")
    print("-" * 70)

    for r in sorted(results, key=lambda x: x.uses_hubspot, reverse=True):
        hubspot_str = "Yes" if r.uses_hubspot else ("Error" if r.error else "No")
        print(f"  {r.company[:24]:<25} {r.domain[:24]:<25} {hubspot_str:<10} {r.confidence}")

    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Detect HubSpot usage for a list of company domains.",
    )
    parser.add_argument(
        "input_csv",
        help="Path to input CSV file with 'company' and 'domain' columns",
    )
    parser.add_argument(
        "-o", "--output",
        default="hubspot_results.csv",
        help="Path to output CSV file (default: hubspot_results.csv)",
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=MAX_WORKERS,
        help=f"Number of concurrent workers (default: {MAX_WORKERS})",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    entries = read_input_csv(args.input_csv)
    if not entries:
        logger.error("No valid entries found in input CSV")
        sys.exit(1)

    results: list[DetectionResult] = []
    workers = min(args.workers, len(entries))

    logger.info("Checking %d domains with %d workers...", len(entries), workers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_entry = {
            executor.submit(detect_hubspot, e["company"], e["domain"]): e
            for e in entries
        }

        for i, future in enumerate(
            concurrent.futures.as_completed(future_to_entry), 1
        ):
            entry = future_to_entry[future]
            try:
                result = future.result()
                results.append(result)
                status = "HubSpot" if result.uses_hubspot else "No HubSpot"
                logger.info(
                    "[%d/%d] %s (%s) - %s [%s]",
                    i, len(entries), entry["company"], entry["domain"],
                    status, result.confidence,
                )
            except Exception as e:
                err_result = DetectionResult(
                    company=entry["company"],
                    domain=entry["domain"],
                    error=str(e),
                )
                results.append(err_result)
                logger.error(
                    "[%d/%d] %s - Error: %s",
                    i, len(entries), entry["domain"], e,
                )

    # Sort results: HubSpot users first, then by confidence
    confidence_order = {"high": 0, "medium": 1, "low": 2, "none": 3}
    results.sort(
        key=lambda r: (not r.uses_hubspot, confidence_order.get(r.confidence, 4))
    )

    write_output_csv(results, args.output)
    print_summary(results)


if __name__ == "__main__":
    main()
