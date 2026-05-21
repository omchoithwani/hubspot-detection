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
import ipaddress
import logging
import re
import sys
import threading
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
    "hubspotemail.net",
    "hubspotlinks.com",
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

# Module-level cache for HubSpot IP ranges
_HUBSPOT_IP_RANGES: list | None = None
_HUBSPOT_IP_LOCK = threading.Lock()


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
    hubspot_tier: str = "unknown"
    detected_products: list = field(default_factory=list)
    form_ids: list = field(default_factory=list, repr=False)
    cdn_masking: str = field(default="", repr=False)  # set by _check_headers, used by check_content_hub

    def confidence_score(self) -> int:
        """Numeric score based on number and strength of signals."""
        score = 0
        product_keywords = ("Content Hub", "Marketing Hub", "Service Hub", "Sales Hub", "Breeze")
        for signal in self.signals:
            if "tracking code" in signal.lower() or "portal id" in signal.lower():
                score += 3
            elif "dns" in signal.lower() or "header" in signal.lower():
                score += 2
            elif any(kw in signal for kw in product_keywords):
                score += 3
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

    def compute_tier(self):
        """Set hubspot_tier based on detected_products."""
        if not self.uses_hubspot:
            self.hubspot_tier = "unknown"
            return
        if any("Enterprise" in p for p in self.detected_products):
            self.hubspot_tier = "enterprise"
        elif any(any(k in p for k in ("Pro", "Breeze")) for p in self.detected_products):
            self.hubspot_tier = "pro"
        elif any("Starter" in p for p in self.detected_products):
            self.hubspot_tier = "starter"
        elif self.detected_products:
            self.hubspot_tier = "starter"
        else:
            self.hubspot_tier = "free"


def normalize_domain(domain: str) -> str:
    """Normalize a domain string for consistent checking."""
    domain = domain.strip().lower()
    if "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.netloc or parsed.path
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    return domain


def get_hubspot_ip_ranges() -> list:
    """Fetch HubSpot IP ranges from ARIN API, cached at module level."""
    global _HUBSPOT_IP_RANGES
    with _HUBSPOT_IP_LOCK:
        if _HUBSPOT_IP_RANGES is not None:
            return _HUBSPOT_IP_RANGES
        ranges = []
        try:
            headers = {"Accept": "application/json"}
            resp = requests.get(
                "https://whois.arin.net/rest/org/HUBSP-8/nets",
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            net_refs = data.get("nets", {}).get("netRef", [])
            if isinstance(net_refs, dict):
                net_refs = [net_refs]
            for ref in net_refs:
                handle = ref.get("@handle", "")
                if not handle:
                    continue
                try:
                    net_resp = requests.get(
                        f"https://whois.arin.net/rest/net/{handle}",
                        headers=headers,
                        timeout=REQUEST_TIMEOUT,
                    )
                    net_resp.raise_for_status()
                    net_data = net_resp.json()
                    net_blocks = net_data.get("net", {}).get("netBlocks", {}).get("netBlock", [])
                    if isinstance(net_blocks, dict):
                        net_blocks = [net_blocks]
                    for block in net_blocks:
                        cidr = block.get("cidrLength", "")
                        start = block.get("startAddress", "")
                        if start and cidr:
                            try:
                                ranges.append(ipaddress.ip_network(f"{start}/{cidr}", strict=False))
                            except ValueError:
                                pass
                except Exception:
                    pass
        except Exception as e:
            logger.warning("Failed to fetch HubSpot IP ranges from ARIN: %s", e)
        _HUBSPOT_IP_RANGES = ranges
        return ranges


def _ip_in_hubspot_ranges(ip_str: str, ranges: list) -> bool:
    """Check if an IP address is within any of the given HubSpot ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in ranges)
    except ValueError:
        return False


def _resolve_a_records(host: str) -> list:
    """Resolve A records for a hostname, returning list of IP strings."""
    try:
        answers = dns.resolver.resolve(host, "A")
        return [str(r.address) for r in answers]
    except Exception:
        return []


def check_dns(domain: str, result: DetectionResult):
    """Check DNS records for HubSpot indicators."""
    bare_domain = domain.lstrip("www.")

    for subdomain in [bare_domain, f"www.{bare_domain}"]:
        try:
            answers = dns.resolver.resolve(subdomain, "CNAME")
            for rdata in answers:
                target = str(rdata.target).lower()
                for indicator in HUBSPOT_DNS_CNAMES:
                    if indicator in target:
                        note = ""
                        if "hubspotpagebuilder.com" in target:
                            note = " (free tier subdomain)"
                        result.signals.append(
                            f"DNS CNAME: {subdomain} -> {target}{note}"
                        )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.resolver.Timeout,
                Exception):
            pass

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

    try:
        answers = dns.resolver.resolve(bare_domain, "TXT")
        for rdata in answers:
            txt = str(rdata).lower()
            if "hubspotemail" in txt:
                result.signals.append("DNS TXT: HubSpot email marketing (paid)")
            elif "hubspot" in txt:
                result.signals.append("DNS TXT: HubSpot verification record found")
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
            check_breeze(result.hubspot_portal_id, resp.text, result)
            return
        except requests.exceptions.SSLError:
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
                check_breeze(result.hubspot_portal_id, resp.text, result)
                return
            except Exception:
                continue
        except requests.exceptions.RequestException:
            continue


def _check_headers(resp: requests.Response, result: DetectionResult):
    """Check HTTP response headers for HubSpot indicators."""
    resp_headers = {k.lower(): v for k, v in resp.headers.items()}

    for indicator in HUBSPOT_HEADER_INDICATORS:
        if indicator in resp_headers:
            result.signals.append(
                f"HTTP Header: {indicator}={resp_headers[indicator]}"
            )

    server = resp_headers.get("server", "").lower()
    if "hubspot" in server:
        result.signals.append(f"HTTP Header: server={server}")

    cookies = resp_headers.get("set-cookie", "").lower()
    if "__hs" in cookies or "hubspot" in cookies:
        result.signals.append("HTTP Header: HubSpot cookie detected")

    # CDN detection — used later by check_content_hub to flag inconclusive IP checks
    server = resp_headers.get("server", "")
    via = resp_headers.get("via", "")
    if "cf-ray" in resp_headers or "cf-cache-status" in resp_headers or "cloudflare" in server:
        result.cdn_masking = "Cloudflare"
    elif "x-fastly-request-id" in resp_headers or "fastly" in server or "fastly" in via:
        result.cdn_masking = "Fastly"
    elif "x-akamai-edgescape" in resp_headers or "akamai" in server or "akamai" in via:
        result.cdn_masking = "Akamai"
    elif "x-sucuri-id" in resp_headers or "sucuri" in server:
        result.cdn_masking = "Sucuri"
    elif "x-iinfo" in resp_headers or "imperva" in server or "incapsula" in server:
        result.cdn_masking = "Imperva"


def _check_html(html: str, result: DetectionResult):
    """Check HTML content for HubSpot markers."""
    for pattern in HUBSPOT_HTML_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            match_label = pattern.replace(r"\.", ".").replace("\\", "")
            result.signals.append(f"HTML pattern: {match_label}")

    soup = BeautifulSoup(html, "html.parser")

    for meta in soup.find_all("meta"):
        name = (meta.get("name") or meta.get("property") or "").lower()
        content = (meta.get("content") or "").lower()
        for indicator in HUBSPOT_META_INDICATORS:
            if indicator in name:
                result.signals.append(f"Meta tag: {name}={content}")
            elif name == "generator" and indicator in content:
                result.signals.append(f"Meta tag: generator={content}")

    for script in soup.find_all("script", src=True):
        src = script["src"].lower()
        if "hubspot" in src or "hs-scripts" in src or "hsforms" in src:
            result.signals.append(f"Script src: {src}")

    for script in soup.find_all("script", src=False):
        text = script.string or ""
        if "hs-script-loader" in text or "hbspt" in text:
            result.signals.append("Inline script: HubSpot tracking code")

    # Signal #7: Sales Hub Starter+ via meetings widget
    if re.search(r"meetings[\w\-]*\.hubspot\.com", html, re.IGNORECASE):
        result.signals.append("Sales Hub Starter+: meetings widget detected")
        if "Sales Hub Starter+" not in result.detected_products:
            result.detected_products.append("Sales Hub Starter+")

    # Signal #10 (HTML part): Breeze Customer Agent chat widget
    if "hubspot-conversations-iframe" in html:
        result.signals.append("HubSpot Conversations chat widget")

    # Extract form IDs for Signal #4
    form_id_pattern = r'(?:formId|form_id)["\s:=]+["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
    for m in re.finditer(form_id_pattern, html, re.IGNORECASE):
        fid = m.group(1)
        if fid not in result.form_ids:
            result.form_ids.append(fid)

    # Deduplicate signals
    result.signals = list(dict.fromkeys(result.signals))


def _extract_portal_id(html: str, result: DetectionResult):
    """Try to extract the HubSpot portal/hub ID from page source."""
    patterns = [
        r"js\.hs-scripts\.com/(\d+)\.js",
        r"js[\w\-]*\.hs-scripts\.com/(\d+)\.js",
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


def check_form_api(portal_id: str, form_ids: list, result: DetectionResult):
    """Signal #4: Check form configs via HubSpot Forms API."""
    if not portal_id or not form_ids:
        return
    headers = {"User-Agent": USER_AGENT}
    for fid in form_ids[:5]:
        try:
            url = f"https://forms.hsforms.com/embed/v3/form/{portal_id}/{fid}/json"
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                continue
            data = resp.json()
            fields = data.get("fields", []) or data.get("formFieldGroups", [])
            # Flatten groups if needed
            flat_fields = []
            for f in fields:
                if isinstance(f, dict) and "fields" in f:
                    flat_fields.extend(f.get("fields", []))
                else:
                    flat_fields.append(f)
            for ff in flat_fields:
                if ff.get("isSmartField") or ff.get("isSmartGroup"):
                    if "Marketing Hub Pro" not in result.detected_products:
                        result.detected_products.append("Marketing Hub Pro")
                    result.signals.append("Marketing Hub Pro: smart field detected in form")
                if ff.get("dependentFieldFilters"):
                    if "Marketing Hub Pro" not in result.detected_products:
                        result.detected_products.append("Marketing Hub Pro")
                    result.signals.append("Marketing Hub Pro: dependent field filters in form")
            scopes = data.get("scopes", []) or []
            if "noBranding" in scopes:
                if "Marketing Hub Starter+" not in result.detected_products:
                    result.detected_products.append("Marketing Hub Starter+")
                result.signals.append("Marketing Hub Starter+: noBranding scope in form")
            if data.get("sfdcCampaignId"):
                if "Sales Hub Enterprise" not in result.detected_products:
                    result.detected_products.append("Sales Hub Enterprise")
                result.signals.append("Sales Hub Enterprise: Salesforce campaign ID in form")
        except Exception:
            pass


def check_popup_api(portal_id: str, result: DetectionResult):
    """Signal #5: Check popup audience configs for Marketing Hub Pro."""
    if not portal_id:
        return
    try:
        url = f"https://api.hubspot.com/web-interactives/v1/public/audiences/{portal_id}"
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return
        data = resp.json()
        configs = data.get("sortedAudienceConfigs", []) or []
        for cfg in configs:
            if cfg.get("campaignGuid") is not None:
                if "Marketing Hub Pro" not in result.detected_products:
                    result.detected_products.append("Marketing Hub Pro")
                result.signals.append("Marketing Hub Pro: popup audience config with campaignGuid")
                break
    except Exception:
        pass


def check_tracking_script(portal_id: str, result: DetectionResult):
    """Signal #8: Check analytics script for Marketing Hub Enterprise indicators."""
    if not portal_id:
        return
    headers = {"User-Agent": USER_AGENT}
    for region in ("na1", "eu1"):
        try:
            url = f"https://js-{region}.hs-analytics.net/analytics/0/{portal_id}.js"
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                continue
            text = resp.text
            has_tracking_config = bool(re.search(r'"trackingConfigId"\s*:\s*\d+', text))
            has_pe_event = bool(re.search(rf'"pe{portal_id}_\w+"', text))
            if has_tracking_config and has_pe_event:
                if "Marketing Hub Enterprise" not in result.detected_products:
                    result.detected_products.append("Marketing Hub Enterprise")
                result.signals.append("Marketing Hub Enterprise: custom event tracking in analytics script")
            break
        except Exception:
            pass


def check_content_hub(domain: str, result: DetectionResult, hubspot_ranges: list):
    """Signal #1: Check if domain hosts resolve to HubSpot IP ranges (Content Hub Pro+)."""
    bare_domain = domain.lstrip("www.")
    hosts_to_check = [bare_domain, f"www.{bare_domain}", f"blog.{bare_domain}"]
    req_headers = {"User-Agent": USER_AGENT}

    for host in hosts_to_check:
        ips = _resolve_a_records(host)
        for ip in ips:
            if _ip_in_hubspot_ranges(ip, hubspot_ranges):
                result.signals.append(f"Content Hub Pro: {host} ({ip}) -> HubSpot infrastructure")
                if "Content Hub Pro" not in result.detected_products:
                    result.detected_products.append("Content Hub Pro")
                # Try to get portal ID from diagnostics endpoint
                if not result.hubspot_portal_id:
                    try:
                        diag_url = f"https://{host}/_hcms/diagnostics"
                        diag_resp = requests.get(
                            diag_url,
                            headers=req_headers,
                            timeout=REQUEST_TIMEOUT,
                            allow_redirects=True,
                        )
                        pid = diag_resp.headers.get("X-Hs-Portal-Id", "")
                        if pid:
                            result.hubspot_portal_id = pid
                            result.signals.append(f"Portal ID: {pid}")
                    except Exception:
                        pass
                return

    # No HubSpot IPs found — flag if a CDN is masking the origin
    if result.cdn_masking:
        result.signals.append(
            f"Content Hub: {result.cdn_masking} CDN detected — IP check inconclusive, may be hosted on HubSpot"
        )


def check_service_hub(domain: str, result: DetectionResult, hubspot_ranges: list):
    """Signal #6: Check support subdomains against HubSpot IP ranges (Service Hub Pro)."""
    bare_domain = domain.lstrip("www.")
    subdomains = ["support", "help", "docs", "kb", "knowledge"]

    for sub in subdomains:
        host = f"{sub}.{bare_domain}"
        ips = _resolve_a_records(host)
        for ip in ips:
            if _ip_in_hubspot_ranges(ip, hubspot_ranges):
                result.signals.append(f"Service Hub Pro: {host} ({ip}) -> HubSpot infrastructure")
                if "Service Hub Pro" not in result.detected_products:
                    result.detected_products.append("Service Hub Pro")
                break


def check_breeze(portal_id: str, html: str, result: DetectionResult):
    """Signal #10: Check for Breeze Customer Agent indicators."""
    if "hubspot-conversations-iframe" not in html:
        return
    if not portal_id:
        return
    req_headers = {"User-Agent": USER_AGENT}
    for region in ("na1", "eu1"):
        try:
            url = (
                f"https://api-{region}.hubspot.com/livechat-public/v1/message/public"
                f"?portalId={portal_id}"
            )
            resp = requests.get(url, headers=req_headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                continue
            data = resp.json()
            is_breeze = False
            if data.get("routingRuleDefinitionAI") is True:
                is_breeze = True
            if data.get("recommendedQuestionsForAgent"):
                is_breeze = True
            send_from = data.get("sendFrom", []) or []
            if any(entry.get("isResponderAI") is True for entry in send_from):
                is_breeze = True
            if is_breeze:
                if "Breeze Customer Agent" not in result.detected_products:
                    result.detected_products.append("Breeze Customer Agent")
                result.signals.append("Breeze Customer Agent: AI routing/responder detected")
            break
        except Exception:
            pass


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

        if result.hubspot_portal_id:
            check_form_api(result.hubspot_portal_id, result.form_ids, result)
            check_popup_api(result.hubspot_portal_id, result)
            check_tracking_script(result.hubspot_portal_id, result)

        hubspot_ranges = get_hubspot_ip_ranges()
        if hubspot_ranges:
            check_content_hub(normalized, result, hubspot_ranges)
            check_service_hub(normalized, result, hubspot_ranges)

    except Exception as e:
        result.error = str(e)
        logger.error("Error checking %s: %s", domain, e)

    result.compute_confidence()
    result.compute_tier()
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
        "hubspot_tier",
        "detected_products",
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
                "hubspot_tier": r.hubspot_tier,
                "detected_products": " | ".join(r.detected_products),
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

    print("\n" + "=" * 90)
    print(f"{'HUBSPOT DETECTION RESULTS':^90}")
    print("=" * 90)
    print(f"  Total domains checked : {total}")
    print(f"  Using HubSpot         : {using}")
    print(f"  Not using HubSpot     : {total - using - errors}")
    print(f"  Errors                : {errors}")
    print("-" * 90)
    print(f"  {'Company':<25} {'Domain':<25} {'HubSpot?':<10} {'Confidence':<12} {'Tier':<12} {'Products'}")
    print("-" * 90)

    for r in sorted(results, key=lambda x: x.uses_hubspot, reverse=True):
        hubspot_str = "Yes" if r.uses_hubspot else ("Error" if r.error else "No")
        products_str = " | ".join(r.detected_products) or "—"
        print(
            f"  {r.company[:24]:<25} {r.domain[:24]:<25} {hubspot_str:<10} "
            f"{r.confidence:<12} {r.hubspot_tier:<12} {products_str}"
        )

    print("=" * 90 + "\n")


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

    logger.info("Pre-fetching HubSpot IP ranges from ARIN...")
    get_hubspot_ip_ranges()

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
                    "[%d/%d] %s (%s) - %s [%s] tier=%s",
                    i, len(entries), entry["company"], entry["domain"],
                    status, result.confidence, result.hubspot_tier,
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

    confidence_order = {"high": 0, "medium": 1, "low": 2, "none": 3}
    results.sort(
        key=lambda r: (not r.uses_hubspot, confidence_order.get(r.confidence, 4))
    )

    write_output_csv(results, args.output)
    print_summary(results)


if __name__ == "__main__":
    main()
