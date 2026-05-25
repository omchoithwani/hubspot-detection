"""
Google Sheets integration — upserts HubSpot detection results keyed by domain.
Requires a Google Service Account with the sheet shared to its email.
"""

import re
from datetime import datetime

import gspread
from google.oauth2.service_account import Credentials

from hubspot_detector import DetectionResult

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive.file",
]

HEADERS = [
    "Company", "Domain", "Uses HubSpot", "Confidence",
    "Tier", "Detected Products", "Portal ID", "Signals", "Error", "Last Checked",
]

_DOMAIN_COL_IDX = 1  # 0-indexed; Domain is column B


def get_client(service_account_info: dict) -> gspread.Client:
    info = dict(service_account_info)
    if "private_key" in info:
        key = str(info["private_key"])
        key = key.replace("\\n", "\n")   # literal \n → real newlines
        key = key.replace("\r\n", "\n")  # normalise CRLF
        key = key.strip()
        info["private_key"] = key
    creds = Credentials.from_service_account_info(info, scopes=SCOPES)
    return gspread.authorize(creds)


def get_worksheet(client: gspread.Client, sheet_id: str, worksheet_name: str = "Results") -> gspread.Worksheet:
    """Open the sheet and return (or create) the named worksheet with headers."""
    sh = client.open_by_key(sheet_id)
    try:
        ws = sh.worksheet(worksheet_name)
    except gspread.WorksheetNotFound:
        ws = sh.add_worksheet(title=worksheet_name, rows=1000, cols=len(HEADERS))
    # Ensure headers are correct
    first_row = ws.row_values(1) if ws.row_count > 0 else []
    if first_row != HEADERS:
        if first_row:
            ws.insert_row(HEADERS, index=1)
        else:
            ws.append_row(HEADERS)
    return ws


def extract_sheet_id(url_or_id: str) -> str:
    """Accept a full Google Sheets URL or a bare sheet ID."""
    m = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", url_or_id)
    return m.group(1) if m else url_or_id.strip()


def _result_to_row(r: DetectionResult, now: str) -> list:
    return [
        r.company,
        r.domain,
        "Yes" if r.uses_hubspot else ("Error" if r.error else "No"),
        r.confidence.capitalize(),
        r.hubspot_tier.capitalize(),
        " | ".join(r.detected_products),
        r.hubspot_portal_id,
        " | ".join(r.signals),
        r.error,
        now,
    ]


def upsert_results(ws: gspread.Worksheet, results: list[DetectionResult]) -> tuple[int, int]:
    """
    Update existing rows matched by domain (case-insensitive), append new ones.
    Returns (updated_count, appended_count).
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    all_rows = ws.get_all_values()

    # domain -> 1-indexed row number (skip header row 1)
    domain_to_row: dict[str, int] = {}
    for i, row in enumerate(all_rows[1:], start=2):
        if len(row) > _DOMAIN_COL_IDX:
            domain_to_row[row[_DOMAIN_COL_IDX].lower().strip()] = i

    batch_updates = []
    to_append = []
    col_end = chr(ord("A") + len(HEADERS) - 1)  # "J"

    for r in results:
        row_data = _result_to_row(r, now)
        key = r.domain.lower().strip()
        if key in domain_to_row:
            row_idx = domain_to_row[key]
            if row_idx == -1:
                continue  # duplicate in this batch, already queued for append
            batch_updates.append({
                "range": f"A{row_idx}:{col_end}{row_idx}",
                "values": [row_data],
            })
        else:
            to_append.append(row_data)
            domain_to_row[key] = -1  # prevent duplicates within same batch

    if batch_updates:
        ws.batch_update(batch_updates, value_input_option="USER_ENTERED")
    if to_append:
        ws.append_rows(to_append, value_input_option="USER_ENTERED")

    return len(batch_updates), len(to_append)
