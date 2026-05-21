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
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15
MAX_WORKERS = 10
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

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

HUBSPOT_MX_DOMAINS = [
    "hubspot.com",
]

# Keywords used to find high-value secondary pages (contact, demo, pricing)
SECONDARY_PAGE_KEYWORDS = (
    "contact", "demo", "pricing", "get-started", "trial",
    "book", "request", "schedule", "talk-to-sales", "resources",
)

_HUBSPOT_IP_RANGES: list | None = None
_HUBSPOT_IP_LOCK = threading.Lock()


@dataclass
class DetectionResult:
    """Stores detection findings for a single domain."""
    company: str
    domain: str
    uses_hubspot: bool = False
    confidence: str = "none"
    signals: list = field(default_factory=list)
    hubspot_portal_id: str = ""
    error: str = ""
    hubspot_tier: str = "unknown"
    detected_products: list = field(default_factory=list)
    # Internal fields — not exported to CSV
    form_ids: list = field(default_factory=list, repr=False)
    gtm_ids: list = field(default_factory=list, repr=False)
    cdn_masking: str = field(default="", repr=False)

    def confidence_score(self) -> int:
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
    domain = domain.strip().lower()
    if "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.netloc or parsed.path
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    return domain


def get_hubspot_ip_ranges() -> list:
    """Fetch HubSpot IP ranges from ARIN (org HUBSP-8), cached for the process lifetime."""
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
            net_refs = resp.json().get("nets", {}).get("netRef", [])
            if isinstance(net_refs, dict):
                net_refs = [net_refs]
            for ref in net_refs:
                handle = ref.get("@handle", "")
                if not handle:
                    continue
                try:
                    nd = requests.get(
                        f"https://whois.arin.net/rest/net/{handle}",
                        headers=headers,
                        timeout=REQUEST_TIMEOUT,
                    ).json()
                    blocks = nd.get("net", {}).get("netBlocks", {}).get("netBlock", [])
                    if isinstance(blocks, dict):
                        blocks = [blocks]
                    for b in blocks:
                        start = b.get("startAddress", "")
                        cidr = b.get("cidrLength", "")
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
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in ranges)
    except ValueError:
        return False


def _resolve_a_records(host: str) -> list:
    try:
        return [str(r.address) for r in dns.resolver.resolve(host, "A")]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# DNS checks
# ---------------------------------------------------------------------------

def check_dns(domain: str, result: DetectionResult):
    bare = domain.lstrip("www.")

    # CNAME checks (main domain + www)
    for subdomain in [bare, f"www.{bare}"]:
        try:
            for rdata in dns.resolver.resolve(subdomain, "CNAME"):
                target = str(rdata.target).lower()
                for indicator in HUBSPOT_DNS_CNAMES:
                    if indicator in target:
                        note = " (free tier subdomain)" if "hubspotpagebuilder.com" in target else ""
                        result.signals.append(f"DNS CNAME: {subdomain} -> {target}{note}")
        except Exception:
            pass

    # MX records
    try:
        for rdata in dns.resolver.resolve(bare, "MX"):
            exchange = str(rdata.exchange).lower()
            if any(mx in exchange for mx in HUBSPOT_MX_DOMAINS):
                result.signals.append(f"DNS MX: {exchange}")
    except Exception:
        pass

    # TXT / SPF records
    try:
        for rdata in dns.resolver.resolve(bare, "TXT"):
            txt = str(rdata).lower()
            if "hubspotemail" in txt:
                result.signals.append("DNS TXT SPF: _spf.hubspotemail.net → HubSpot email marketing (paid)")
                if "Marketing Hub (email sending)" not in result.detected_products:
                    result.detected_products.append("Marketing Hub (email sending)")
            elif "hubspot" in txt:
                result.signals.append("DNS TXT: HubSpot verification record found")
    except Exception:
        pass

    # DKIM: hs1/hs2._domainkey.<domain> — set up during HubSpot email connection
    for prefix in ("hs1._domainkey", "hs2._domainkey"):
        try:
            for rdata in dns.resolver.resolve(f"{prefix}.{bare}", "CNAME"):
                target = str(rdata.target).lower()
                if "hubspot" in target:
                    result.signals.append(f"DNS CNAME (DKIM): {prefix}.{bare} → {target}")
                    if "Marketing Hub (email sending)" not in result.detected_products:
                        result.detected_products.append("Marketing Hub (email sending)")
        except Exception:
            pass

    # em<n>.<domain> CNAME → hubspotemail.net (portal-specific DKIM sending domain)
    for prefix in ("em1", "em2", "em3", "em4", "email"):
        try:
            for rdata in dns.resolver.resolve(f"{prefix}.{bare}", "CNAME"):
                target = str(rdata.target).lower()
                if "hubspotemail" in target:
                    result.signals.append(f"DNS CNAME (DKIM): {prefix}.{bare} → {target}")
                    if "Marketing Hub (email sending)" not in result.detected_products:
                        result.detected_products.append("Marketing Hub (email sending)")
                    break
        except Exception:
            pass


# ---------------------------------------------------------------------------
# HTTP checks
# ---------------------------------------------------------------------------

def check_http(domain: str, result: DetectionResult):
    headers = {"User-Agent": USER_AGENT}
    for url in [f"https://{domain}", f"https://www.{domain}"]:
        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            resp.raise_for_status()
            _process_response(resp, url, result)
            return
        except requests.exceptions.SSLError:
            try:
                resp = requests.get(
                    url.replace("https://", "http://"),
                    headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                )
                _process_response(resp, url.replace("https://", "http://"), result)
                return
            except Exception:
                continue
        except requests.exceptions.RequestException:
            continue


def _process_response(resp: requests.Response, url: str, result: DetectionResult):
    """Run all per-page checks, then trigger multi-page and GTM fallbacks."""
    _check_headers(resp, result)
    _check_html(resp.text, result)
    _extract_portal_id(resp.text, result)
    check_breeze(result.hubspot_portal_id, resp.text, result)
    if not result.hubspot_portal_id:
        check_multi_page(url, resp.text, result)
    if not result.hubspot_portal_id and result.gtm_ids:
        check_gtm_containers(result.gtm_ids, result)


def _check_headers(resp: requests.Response, result: DetectionResult):
    h = {k.lower(): v for k, v in resp.headers.items()}

    for indicator in HUBSPOT_HEADER_INDICATORS:
        if indicator in h:
            result.signals.append(f"HTTP Header: {indicator}={h[indicator]}")

    server = h.get("server", "").lower()
    if "hubspot" in server:
        result.signals.append(f"HTTP Header: server={server}")

    if "__hs" in h.get("set-cookie", "").lower() or "hubspot" in h.get("set-cookie", "").lower():
        result.signals.append("HTTP Header: HubSpot cookie detected")

    # CDN detection — used by check_content_hub to flag inconclusive IP results
    via = h.get("via", "").lower()
    srv = h.get("server", "").lower()
    if "cf-ray" in h or "cf-cache-status" in h or "cloudflare" in srv:
        result.cdn_masking = "Cloudflare"
    elif "x-fastly-request-id" in h or "fastly" in srv or "fastly" in via:
        result.cdn_masking = "Fastly"
    elif "x-akamai-edgescape" in h or "akamai" in srv or "akamai" in via:
        result.cdn_masking = "Akamai"
    elif "x-sucuri-id" in h or "sucuri" in srv:
        result.cdn_masking = "Sucuri"
    elif "x-iinfo" in h or "imperva" in srv or "incapsula" in srv:
        result.cdn_masking = "Imperva"


def _check_html(html: str, result: DetectionResult):
    for pattern in HUBSPOT_HTML_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            result.signals.append(f"HTML pattern: {pattern.replace(r'.', '.').replace(chr(92), '')}")

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

    if re.search(r"meetings[\w\-]*\.hubspot\.com", html, re.IGNORECASE):
        result.signals.append("Sales Hub Starter+: meetings widget detected")
        if "Sales Hub Starter+" not in result.detected_products:
            result.detected_products.append("Sales Hub Starter+")

    if "hubspot-conversations-iframe" in html:
        result.signals.append("HubSpot Conversations chat widget")

    # Collect form IDs for the Forms API check
    for m in re.finditer(
        r'(?:formId|form_id)["\s:=]+["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
        html, re.IGNORECASE,
    ):
        fid = m.group(1)
        if fid not in result.form_ids:
            result.form_ids.append(fid)

    # Collect GTM container IDs for GTM parsing fallback
    for gtm_id in re.findall(r'GTM-[A-Z0-9]{4,8}', html):
        if gtm_id not in result.gtm_ids:
            result.gtm_ids.append(gtm_id)

    result.signals = list(dict.fromkeys(result.signals))


def _extract_portal_id(html: str, result: DetectionResult):
    if result.hubspot_portal_id:
        return
    for pattern in [
        r"js[\w\-]*\.hs-scripts\.com/(\d+)\.js",
        r"js\.hsforms\.net/forms/v2\.js.*?portalId[\"':\s]+(\d+)",
        r"data-hsjs-portal=\"(\d+)\"",
        r"hbspt\.forms\.create\([^)]*portalId[\"':\s]+[\"']?(\d+)",
        r"hbspt\.cta\.load\((\d+)",
        r"HubSpot[- ]?Portal[- ]?ID[\"':\s]+(\d+)",
        r"hs-hub-id[\"':\s]+(\d+)",
    ]:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            result.hubspot_portal_id = m.group(1)
            result.signals.append(f"Portal ID: {m.group(1)}")
            return


# ---------------------------------------------------------------------------
# Multi-page scraping
# ---------------------------------------------------------------------------

def check_multi_page(base_url: str, homepage_html: str, result: DetectionResult):
    """
    Follow up to 3 links to contact/demo/pricing pages.
    Most HubSpot forms and CTAs live on these pages, not the homepage.
    Stops early once a portal ID is found.
    """
    base_host = urlparse(base_url).netloc
    soup = BeautifulSoup(homepage_html, "html.parser")
    candidates: list[str] = []

    for a in soup.find_all("a", href=True):
        href = a["href"]
        text = (a.get_text() or "").lower()
        if any(kw in href.lower() or kw in text for kw in SECONDARY_PAGE_KEYWORDS):
            full = urljoin(base_url, href)
            p = urlparse(full)
            if p.netloc == base_host and p.scheme in ("http", "https") and full not in candidates:
                candidates.append(full)

    for url in candidates[:3]:
        if result.hubspot_portal_id:
            break
        try:
            resp = requests.get(
                url, headers={"User-Agent": USER_AGENT}, timeout=10, allow_redirects=True,
            )
            if resp.status_code != 200:
                continue
            _check_html(resp.text, result)
            _extract_portal_id(resp.text, result)
        except Exception:
            continue


# ---------------------------------------------------------------------------
# GTM container parsing
# ---------------------------------------------------------------------------

def check_gtm_containers(gtm_ids: list, result: DetectionResult):
    """
    Fetch public GTM container bundles and search for HubSpot portal IDs.
    Recovers portal IDs for sites that load HubSpot via tag manager rather
    than a direct script tag — a common pattern that defeats static HTML checks.
    """
    for gtm_id in gtm_ids[:3]:
        if result.hubspot_portal_id:
            return
        try:
            resp = requests.get(
                f"https://www.googletagmanager.com/gtm.js?id={gtm_id}",
                headers={"User-Agent": USER_AGENT},
                timeout=10,
            )
            if resp.status_code != 200:
                continue
            js = resp.text
            _extract_portal_id(js, result)
            if result.hubspot_portal_id:
                result.signals.append(f"Portal ID recovered from GTM container ({gtm_id})")
                return
            if re.search(r"hs-scripts\.com", js, re.IGNORECASE):
                result.signals.append(f"GTM ({gtm_id}): HubSpot tracking tag in container")
        except Exception:
            continue


# ---------------------------------------------------------------------------
# Auxiliary URL checks (robots.txt, sitemap)
# ---------------------------------------------------------------------------

def check_auxiliary_urls(domain: str, result: DetectionResult):
    """
    Check robots.txt and sitemap.xml for portal IDs.
    HubSpot sitemaps and robots files often embed portal-specific paths.
    """
    if result.hubspot_portal_id:
        return
    bare = domain.lstrip("www.")
    for path in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml"):
        try:
            resp = requests.get(
                f"https://{bare}{path}",
                headers={"User-Agent": USER_AGENT},
                timeout=8,
                allow_redirects=True,
            )
            if resp.status_code != 200:
                continue
            _extract_portal_id(resp.text, result)
            if result.hubspot_portal_id:
                result.signals.append(f"Portal ID found in {path}")
                return
        except Exception:
            continue


# ---------------------------------------------------------------------------
# Proactive /_hcms/diagnostics (confirms Content Hub through CDNs)
# ---------------------------------------------------------------------------

def check_hcms_diagnostics_proactive(domain: str, result: DetectionResult):
    """
    Probe /_hcms/diagnostics on the bare domain and www subdomain.
    HubSpot CMS sites return X-Hs-Portal-Id from this endpoint even when a
    CDN sits in front, because CDNs pass /_hcms/* paths through to origin.
    """
    if "Content Hub Pro" in result.detected_products:
        return
    bare = domain.lstrip("www.")
    for host in (bare, f"www.{bare}"):
        try:
            resp = requests.get(
                f"https://{host}/_hcms/diagnostics",
                headers={"User-Agent": USER_AGENT},
                timeout=10,
                allow_redirects=True,
            )
            pid = (
                resp.headers.get("X-Hs-Portal-Id")
                or resp.headers.get("x-hs-portal-id")
                or resp.headers.get("x-hs-hub-id")
            )
            if pid:
                if not result.hubspot_portal_id:
                    result.hubspot_portal_id = pid
                    result.signals.append(f"Portal ID (/_hcms/diagnostics): {pid}")
                result.signals.append(f"Content Hub Pro: /_hcms/diagnostics confirmed ({host})")
                if "Content Hub Pro" not in result.detected_products:
                    result.detected_products.append("Content Hub Pro")
                return
        except Exception:
            continue


# ---------------------------------------------------------------------------
# Tier-specific API checks
# ---------------------------------------------------------------------------

def check_form_api(portal_id: str, form_ids: list, result: DetectionResult):
    """
    Query the public HubSpot Forms embed API for tier signals.
    Smart fields and conditional logic require Marketing Hub Pro+.
    sfdcCampaignId indicates Salesforce integration (Sales Hub Enterprise).
    noBranding is noted as a paying-customer signal but not used for tier.
    """
    if not portal_id or not form_ids:
        return
    for fid in form_ids[:5]:
        try:
            resp = requests.get(
                f"https://forms.hsforms.com/embed/v3/form/{portal_id}/{fid}/json",
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code != 200:
                continue
            data = resp.json()
            form = data.get("form", data)

            flat_fields: list = []
            for g in form.get("formFieldGroups", []):
                flat_fields.extend(g.get("fields", []) if isinstance(g, dict) else [])
            flat_fields.extend(form.get("fields", []))

            for ff in flat_fields:
                if ff.get("isSmartField") or ff.get("isSmartGroup"):
                    result.signals.append("Marketing Hub Pro: smart field in form")
                    if "Marketing Hub Pro" not in result.detected_products:
                        result.detected_products.append("Marketing Hub Pro")
                if ff.get("dependentFieldFilters"):
                    result.signals.append("Marketing Hub Pro: conditional field logic in form")
                    if "Marketing Hub Pro" not in result.detected_products:
                        result.detected_products.append("Marketing Hub Pro")

            if "noBranding" in (form.get("scopes") or []):
                # noBranding just means paying customer — don't use it for tier classification
                result.signals.append("Form: noBranding (paying customer confirmed)")

            if form.get("sfdcCampaignId"):
                result.signals.append("Sales Hub Enterprise: Salesforce campaign ID in form")
                if "Sales Hub Enterprise" not in result.detected_products:
                    result.detected_products.append("Sales Hub Enterprise")
        except Exception:
            continue


def check_popup_api(portal_id: str, result: DetectionResult):
    """campaignGuid in sortedAudienceConfigs → Marketing Hub Pro+ (low recall, zero false positives)."""
    if not portal_id:
        return
    try:
        resp = requests.get(
            f"https://api.hubspot.com/web-interactives/v1/public/audiences/{portal_id}",
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return
        for cfg in resp.json().get("sortedAudienceConfigs", []) or []:
            if cfg.get("campaignGuid"):
                result.signals.append("Marketing Hub Pro: popup campaignGuid found")
                if "Marketing Hub Pro" not in result.detected_products:
                    result.detected_products.append("Marketing Hub Pro")
                break
    except Exception:
        pass


def check_tracking_script(portal_id: str, result: DetectionResult):
    """trackingConfigId + pe<portalId>_ event names in analytics script → Marketing Hub Enterprise."""
    if not portal_id:
        return
    for region in ("na1", "eu1"):
        try:
            resp = requests.get(
                f"https://js-{region}.hs-analytics.net/analytics/0/{portal_id}.js",
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code != 200:
                continue
            js = resp.text
            if re.search(r'"trackingConfigId"\s*:\s*\d+', js) and re.search(rf'"pe{portal_id}_\w+"', js):
                result.signals.append("Marketing Hub Enterprise: custom event tracking in analytics script")
                if "Marketing Hub Enterprise" not in result.detected_products:
                    result.detected_products.append("Marketing Hub Enterprise")
            return
        except Exception:
            continue


# ---------------------------------------------------------------------------
# Infrastructure checks
# ---------------------------------------------------------------------------

def check_content_hub(domain: str, result: DetectionResult, hubspot_ranges: list):
    """A records for domain/www/blog against HubSpot IP ranges → Content Hub Pro."""
    bare = domain.lstrip("www.")
    for host in (bare, f"www.{bare}", f"blog.{bare}"):
        for ip in _resolve_a_records(host):
            if _ip_in_hubspot_ranges(ip, hubspot_ranges):
                result.signals.append(f"Content Hub Pro: {host} ({ip}) → HubSpot infrastructure")
                if "Content Hub Pro" not in result.detected_products:
                    result.detected_products.append("Content Hub Pro")
                if not result.hubspot_portal_id:
                    try:
                        r = requests.get(
                            f"https://{host}/_hcms/diagnostics",
                            headers={"User-Agent": USER_AGENT},
                            timeout=REQUEST_TIMEOUT,
                            allow_redirects=True,
                        )
                        pid = r.headers.get("X-Hs-Portal-Id", "")
                        if pid:
                            result.hubspot_portal_id = pid
                            result.signals.append(f"Portal ID: {pid}")
                    except Exception:
                        pass
                return
    if result.cdn_masking:
        result.signals.append(
            f"Content Hub: {result.cdn_masking} CDN detected — IP check inconclusive, may be on HubSpot"
        )


def check_service_hub(domain: str, result: DetectionResult, hubspot_ranges: list):
    """support/help/docs/kb/knowledge subdomains on HubSpot IPs → Service Hub Pro."""
    bare = domain.lstrip("www.")
    for sub in ("support", "help", "docs", "kb", "knowledge"):
        host = f"{sub}.{bare}"
        for ip in _resolve_a_records(host):
            if _ip_in_hubspot_ranges(ip, hubspot_ranges):
                result.signals.append(f"Service Hub Pro: {host} ({ip}) → HubSpot infrastructure")
                if "Service Hub Pro" not in result.detected_products:
                    result.detected_products.append("Service Hub Pro")
                break


def check_breeze(portal_id: str, html: str, result: DetectionResult):
    """Breeze Customer Agent: AI routing/responder fields in livechat config API."""
    if "hubspot-conversations-iframe" not in html or not portal_id:
        return
    for region in ("na1", "eu1"):
        try:
            resp = requests.get(
                f"https://api-{region}.hubspot.com/livechat-public/v1/message/public",
                params={"portalId": portal_id},
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code != 200:
                continue
            data = resp.json()
            if (
                data.get("routingRuleDefinitionAI") is True
                or data.get("recommendedQuestionsForAgent")
                or any(e.get("isResponderAI") for e in data.get("sendFrom", []) or [])
            ):
                result.signals.append("Breeze Customer Agent: AI routing/responder detected")
                if "Breeze Customer Agent" not in result.detected_products:
                    result.detected_products.append("Breeze Customer Agent")
            break
        except Exception:
            continue


# ---------------------------------------------------------------------------
# Main detection entry point
# ---------------------------------------------------------------------------

def detect_hubspot(company: str, domain: str) -> DetectionResult:
    """Run all detection methods for a single domain."""
    result = DetectionResult(company=company, domain=domain)
    normalized = normalize_domain(domain)

    if not normalized:
        result.error = "Empty or invalid domain"
        return result

    try:
        check_dns(normalized, result)
        check_http(normalized, result)           # includes multi-page + GTM fallback
        check_auxiliary_urls(normalized, result)  # robots.txt / sitemap portal ID

        # Proactive Content Hub confirmation — works through CDNs
        if result.signals:
            check_hcms_diagnostics_proactive(normalized, result)

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


# ---------------------------------------------------------------------------
# CSV I/O and CLI
# ---------------------------------------------------------------------------

def read_input_csv(path: str) -> list[dict]:
    rows = []
    filepath = Path(path)
    if not filepath.exists():
        logger.error("Input file not found: %s", path)
        sys.exit(1)
    with open(filepath, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        company_col = domain_col = None
        for fn in reader.fieldnames or []:
            lower = fn.lower().strip()
            if lower in ("company", "company name", "company_name", "name"):
                company_col = fn
            elif lower in ("domain", "website", "url", "site", "web"):
                domain_col = fn
        if domain_col is None:
            logger.error(
                "Could not find a domain column. Expected: domain, website, url, site, web. "
                "Found: %s", reader.fieldnames,
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
    fieldnames = [
        "company", "domain", "uses_hubspot", "confidence",
        "hubspot_tier", "detected_products", "hubspot_portal_id", "signals", "error",
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
    total = len(results)
    using = sum(1 for r in results if r.uses_hubspot)
    errors = sum(1 for r in results if r.error)
    print("\n" + "=" * 90)
    print(f"{'HUBSPOT DETECTION RESULTS':^90}")
    print("=" * 90)
    print(f"  Total checked  : {total}")
    print(f"  Using HubSpot  : {using}")
    print(f"  Not using      : {total - using - errors}")
    print(f"  Errors         : {errors}")
    print("-" * 90)
    print(f"  {'Company':<25} {'Domain':<25} {'HubSpot?':<10} {'Confidence':<12} {'Tier':<12} {'Products'}")
    print("-" * 90)
    for r in sorted(results, key=lambda x: x.uses_hubspot, reverse=True):
        status = "Yes" if r.uses_hubspot else ("Error" if r.error else "No")
        products = " | ".join(r.detected_products) or "—"
        print(f"  {r.company[:24]:<25} {r.domain[:24]:<25} {status:<10} {r.confidence:<12} {r.hubspot_tier:<12} {products}")
    print("=" * 90 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Detect HubSpot usage for a list of company domains.")
    parser.add_argument("input_csv")
    parser.add_argument("-o", "--output", default="hubspot_results.csv")
    parser.add_argument("-w", "--workers", type=int, default=MAX_WORKERS)
    parser.add_argument("-v", "--verbose", action="store_true")
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
        for i, future in enumerate(concurrent.futures.as_completed(future_to_entry), 1):
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
                results.append(DetectionResult(company=entry["company"], domain=entry["domain"], error=str(e)))
                logger.error("[%d/%d] %s - Error: %s", i, len(entries), entry["domain"], e)

    results.sort(key=lambda r: (not r.uses_hubspot, {"high": 0, "medium": 1, "low": 2, "none": 3}.get(r.confidence, 4)))
    write_output_csv(results, args.output)
    print_summary(results)


if __name__ == "__main__":
    main()
