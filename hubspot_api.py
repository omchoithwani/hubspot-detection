"""
HubSpot CRM API helpers — fetch companies and update properties.

Uses the HubSpot CRM v3 REST API with a Private App access token.
"""

import requests

API_BASE = "https://api.hubapi.com"


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def test_connection(token: str) -> bool:
    """Return True if the token is valid and has CRM access."""
    resp = requests.get(
        f"{API_BASE}/crm/v3/objects/companies",
        headers=_headers(token),
        params={"limit": 1},
        timeout=10,
    )
    return resp.status_code == 200


def fetch_companies_missing_property(
    token: str,
    property_name: str,
    batch_size: int = 100,
) -> list[dict]:
    """Fetch all companies where *property_name* is empty/unset.

    Returns a list of dicts: {id, name, domain}.
    """
    companies: list[dict] = []
    after = None

    while True:
        params: dict = {
            "limit": batch_size,
            "properties": f"name,domain,{property_name}",
        }
        if after:
            params["after"] = after

        resp = requests.get(
            f"{API_BASE}/crm/v3/objects/companies",
            headers=_headers(token),
            params=params,
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()

        for company in data.get("results", []):
            props = company.get("properties", {})
            domain = (props.get("domain") or "").strip()
            prop_val = (props.get(property_name) or "").strip()

            # Only include companies with a domain but missing the property
            if domain and not prop_val:
                companies.append({
                    "id": company["id"],
                    "name": props.get("name") or domain,
                    "domain": domain,
                })

        paging = data.get("paging", {})
        next_page = paging.get("next", {})
        after = next_page.get("after")
        if not after:
            break

    return companies


def update_company_property(
    token: str,
    company_id: str,
    property_name: str,
    value: str,
) -> bool:
    """Update a single property on a company. Returns True on success."""
    resp = requests.patch(
        f"{API_BASE}/crm/v3/objects/companies/{company_id}",
        headers=_headers(token),
        json={"properties": {property_name: value}},
        timeout=10,
    )
    return resp.status_code == 200
