#!/usr/bin/env python3
"""
HubSpot Detection Tool — Web Interface

A simple Streamlit app where you can upload a CSV of company domains
and check which ones are using HubSpot. No command line needed!

Run with:
    streamlit run app.py
"""

import concurrent.futures
import io
import time

import pandas as pd
import streamlit as st

from hubspot_detector import detect_hubspot, DetectionResult, MAX_WORKERS
from hubspot_api import (
    test_connection,
    fetch_companies_missing_property,
    update_company_property,
)

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="HubSpot Detector",
    page_icon="🔍",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #666;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: #f8f9fa;
        border-radius: 10px;
        padding: 1.2rem;
        text-align: center;
        border: 1px solid #e9ecef;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #666;
        margin-top: 0.3rem;
    }
    .confidence-high { color: #28a745; font-weight: 600; }
    .confidence-medium { color: #fd7e14; font-weight: 600; }
    .confidence-low { color: #ffc107; font-weight: 600; }
    .confidence-none { color: #6c757d; }
    .status-yes { color: #28a745; font-weight: 700; }
    .status-no { color: #dc3545; font-weight: 600; }
    .status-error { color: #6c757d; font-style: italic; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown('<div class="main-header">HubSpot Detection Tool</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">'
    "Check if companies use HubSpot — one domain at a time or in bulk via CSV."
    "</div>",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar — instructions & settings
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("How to use")
    st.markdown(
        """
        1. Prepare a CSV file with at least a **domain** column
        2. Optionally include a **company** column
        3. Upload the file below
        4. Click **Run Detection**
        5. View results and download the report
        """
    )

    st.divider()
    st.subheader("Settings")
    workers = st.slider(
        "Concurrent workers",
        min_value=1,
        max_value=30,
        value=MAX_WORKERS,
        help="Number of domains to check simultaneously. Higher = faster but uses more resources.",
    )

    st.divider()
    st.subheader("CSV format example")
    st.code("company,domain\nAcme Corp,acme.com\nWidgets Inc,widgets.io", language="csv")

    st.divider()
    st.subheader("HubSpot Sync")
    st.markdown(
        """
        Use the **HubSpot Sync** tab to connect your
        HubSpot account and auto-fill a custom property
        on companies that don't have it set yet.

        You'll need a **Private App** token with
        company read/write scopes.
        """
    )

    st.divider()
    st.subheader("Detection methods")
    st.markdown(
        """
        - **DNS records** — CNAME, MX, TXT
        - **HTTP headers** — HubSpot-specific headers & cookies
        - **HTML/JS analysis** — tracking scripts, forms, CTAs
        - **Portal ID extraction** — identifies the HubSpot account
        """
    )

# ---------------------------------------------------------------------------
# Tabs — Single Domain vs Bulk CSV
# ---------------------------------------------------------------------------
tab_single, tab_bulk, tab_hubspot = st.tabs(["Single Domain", "Bulk CSV Upload", "HubSpot Sync"])

# ---------------------------------------------------------------------------
# Tab 1 — Single domain lookup
# ---------------------------------------------------------------------------
with tab_single:
    col_input1, col_input2 = st.columns([2, 1])
    with col_input1:
        single_domain = st.text_input(
            "Company Domain",
            placeholder="e.g. hubspot.com",
            help="Enter the domain you want to check for HubSpot usage.",
        )
    with col_input2:
        single_company = st.text_input(
            "Company Name (optional)",
            placeholder="e.g. HubSpot",
            help="Optional — just for labelling the result.",
        )

    if st.button("Check Domain", type="primary", use_container_width=True, key="single_check"):
        if not single_domain.strip():
            st.warning("Please enter a domain to check.")
        else:
            domain = single_domain.strip()
            company = single_company.strip() or domain

            with st.spinner(f"Checking **{domain}**..."):
                start_time = time.time()
                try:
                    result = detect_hubspot(company, domain)
                except Exception as e:
                    result = DetectionResult(company=company, domain=domain, error=str(e))
                elapsed = time.time() - start_time

            st.success(f"Done in {elapsed:.1f}s")

            # --- Result card ---
            if result.error:
                st.error(f"Error checking {domain}: {result.error}")
            else:
                col_r1, col_r2, col_r3 = st.columns(3)
                with col_r1:
                    if result.uses_hubspot:
                        st.metric("Uses HubSpot", "Yes")
                    else:
                        st.metric("Uses HubSpot", "No")
                with col_r2:
                    st.metric("Confidence", result.confidence.capitalize())
                with col_r3:
                    st.metric("Portal ID", result.hubspot_portal_id or "—")

                if result.signals:
                    st.subheader("Detection Signals")
                    for sig in result.signals:
                        st.markdown(f"- {sig}")
                else:
                    st.info("No HubSpot signals detected.")

# ---------------------------------------------------------------------------
# Tab 2 — Bulk CSV upload
# ---------------------------------------------------------------------------
with tab_bulk:
    uploaded_file = st.file_uploader(
        "Upload your CSV file",
        type=["csv"],
        help="CSV must have a 'domain' (or 'website' / 'url') column. A 'company' (or 'name') column is optional.",
    )

    if uploaded_file is not None:
        # Parse the uploaded CSV
        try:
            df_input = pd.read_csv(uploaded_file)
        except Exception as e:
            st.error(f"Could not read CSV file: {e}")
            st.stop()

        # Auto-detect columns
        col_lower_map = {c.lower().strip(): c for c in df_input.columns}
        domain_col = None
        company_col = None

        for alias in ("domain", "website", "url", "site", "web"):
            if alias in col_lower_map:
                domain_col = col_lower_map[alias]
                break

        for alias in ("company", "company name", "company_name", "name"):
            if alias in col_lower_map:
                company_col = col_lower_map[alias]
                break

        if domain_col is None:
            st.error(
                "Could not find a domain column in your CSV. "
                "Please include a column named **domain**, **website**, or **url**."
            )
            st.stop()

        # Build entries list
        entries = []
        for _, row in df_input.iterrows():
            domain = str(row.get(domain_col, "")).strip()
            company = str(row.get(company_col, domain)).strip() if company_col else domain
            if domain and domain.lower() != "nan":
                entries.append({"company": company, "domain": domain})

        if not entries:
            st.error("No valid domains found in the uploaded CSV.")
            st.stop()

        # Preview
        st.subheader(f"Preview — {len(entries)} domains loaded")
        preview_df = pd.DataFrame(entries)
        st.dataframe(preview_df, use_container_width=True, hide_index=True, height=min(200, 35 * len(entries) + 38))

        # -------------------------------------------------------------------
        # Run detection
        # -------------------------------------------------------------------
        if st.button("Run Detection", type="primary", use_container_width=True):

            results: list[DetectionResult] = []
            progress_bar = st.progress(0, text="Starting detection...")
            status_text = st.empty()
            start_time = time.time()

            actual_workers = min(workers, len(entries))

            with concurrent.futures.ThreadPoolExecutor(max_workers=actual_workers) as executor:
                future_to_entry = {
                    executor.submit(detect_hubspot, e["company"], e["domain"]): e
                    for e in entries
                }

                for i, future in enumerate(concurrent.futures.as_completed(future_to_entry), 1):
                    entry = future_to_entry[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        results.append(DetectionResult(
                            company=entry["company"],
                            domain=entry["domain"],
                            error=str(e),
                        ))

                    pct = i / len(entries)
                    progress_bar.progress(pct, text=f"Checking {i}/{len(entries)}: {entry['domain']}")

            elapsed = time.time() - start_time
            progress_bar.progress(1.0, text="Done!")
            status_text.success(f"Finished checking {len(entries)} domains in {elapsed:.1f}s")

            # Sort: HubSpot users first, then by confidence
            confidence_order = {"high": 0, "medium": 1, "low": 2, "none": 3}
            results.sort(
                key=lambda r: (not r.uses_hubspot, confidence_order.get(r.confidence, 4))
            )

            # ---------------------------------------------------------------
            # Summary metrics
            # ---------------------------------------------------------------
            total = len(results)
            using = sum(1 for r in results if r.uses_hubspot)
            not_using = sum(1 for r in results if not r.uses_hubspot and not r.error)
            errors = sum(1 for r in results if r.error)

            st.subheader("Summary")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Checked", total)
            with col2:
                st.metric("Using HubSpot", using)
            with col3:
                st.metric("Not Using HubSpot", not_using)
            with col4:
                st.metric("Errors", errors)

            # ---------------------------------------------------------------
            # Results table
            # ---------------------------------------------------------------
            st.subheader("Detailed Results")

            # Build results dataframe
            rows = []
            for r in results:
                rows.append({
                    "Company": r.company,
                    "Domain": r.domain,
                    "Uses HubSpot": "Yes" if r.uses_hubspot else ("Error" if r.error else "No"),
                    "Confidence": r.confidence.capitalize(),
                    "Portal ID": r.hubspot_portal_id or "—",
                    "Signals": " | ".join(r.signals) if r.signals else "—",
                    "Error": r.error or "",
                })

            df_results = pd.DataFrame(rows)

            # Color-coded display
            def style_hubspot(val):
                if val == "Yes":
                    return "color: #28a745; font-weight: 700"
                elif val == "No":
                    return "color: #dc3545; font-weight: 600"
                return "color: #6c757d; font-style: italic"

            def style_confidence(val):
                styles = {
                    "High": "color: #28a745; font-weight: 600",
                    "Medium": "color: #fd7e14; font-weight: 600",
                    "Low": "color: #ffc107; font-weight: 600",
                    "None": "color: #6c757d",
                }
                return styles.get(val, "")

            styled_df = df_results.style.map(
                style_hubspot, subset=["Uses HubSpot"]
            ).map(
                style_confidence, subset=["Confidence"]
            )

            st.dataframe(styled_df, use_container_width=True, hide_index=True, height=min(600, 35 * len(rows) + 38))

            # ---------------------------------------------------------------
            # Download button
            # ---------------------------------------------------------------
            st.subheader("Export Results")

            # CSV for download
            csv_rows = []
            for r in results:
                csv_rows.append({
                    "company": r.company,
                    "domain": r.domain,
                    "uses_hubspot": r.uses_hubspot,
                    "confidence": r.confidence,
                    "hubspot_portal_id": r.hubspot_portal_id,
                    "signals": " | ".join(r.signals),
                    "error": r.error,
                })

            df_export = pd.DataFrame(csv_rows)
            csv_buffer = df_export.to_csv(index=False)

            st.download_button(
                label="Download Results as CSV",
                data=csv_buffer,
                file_name="hubspot_results.csv",
                mime="text/csv",
                type="primary",
                use_container_width=True,
            )

    else:
        st.info("Upload a CSV file to check multiple domains at once.")

# ---------------------------------------------------------------------------
# Tab 3 — HubSpot Sync
# ---------------------------------------------------------------------------
with tab_hubspot:
    st.markdown(
        "Connect to your HubSpot account and auto-populate a custom property "
        "on every company that doesn't have it filled in yet."
    )

    # --- Token input ---
    # Try Streamlit secrets first, fall back to manual entry
    default_token = ""
    try:
        default_token = st.secrets.get("HUBSPOT_API_TOKEN", "")
    except Exception:
        pass

    hubspot_token = st.text_input(
        "HubSpot Private App Token",
        value=default_token,
        type="password",
        help=(
            "Create a Private App in HubSpot (Settings → Integrations → Private Apps) "
            "with **crm.objects.companies.read** and **crm.objects.companies.write** scopes. "
            "You can also store this in Streamlit Secrets as HUBSPOT_API_TOKEN."
        ),
    )

    property_name = st.text_input(
        "Custom Property Internal Name",
        value="hubspot_user",
        help=(
            "The internal name of the company property to populate "
            "(e.g. hubspot_user). Create this property in HubSpot first: "
            "Settings → Properties → Company → Create property. "
            "Supports both single-checkbox (boolean) and single-line text properties."
        ),
    )

    if hubspot_token:
        # Validate connection
        with st.spinner("Verifying HubSpot connection..."):
            connected = test_connection(hubspot_token)

        if not connected:
            st.error(
                "Could not connect to HubSpot. Check that your token is valid "
                "and has the required scopes (crm.objects.companies.read/write)."
            )
        else:
            st.success("Connected to HubSpot!")

            if st.button("Sync Now", type="primary", use_container_width=True, key="hubspot_sync"):
                # Step 1 — Fetch companies missing the property
                with st.spinner("Fetching companies missing the property..."):
                    try:
                        companies = fetch_companies_missing_property(
                            hubspot_token, property_name
                        )
                    except Exception as e:
                        st.error(f"Error fetching companies: {e}")
                        st.stop()

                if not companies:
                    st.info(
                        f"All companies already have **{property_name}** filled in. Nothing to do!"
                    )
                else:
                    st.write(f"Found **{len(companies)}** companies to check.")

                    # Step 2 — Run detection
                    results: list[tuple[dict, DetectionResult]] = []
                    progress = st.progress(0, text="Starting detection...")
                    start_time = time.time()

                    actual_workers = min(workers, len(companies))

                    with concurrent.futures.ThreadPoolExecutor(max_workers=actual_workers) as executor:
                        future_to_company = {
                            executor.submit(detect_hubspot, c["name"], c["domain"]): c
                            for c in companies
                        }

                        for i, future in enumerate(
                            concurrent.futures.as_completed(future_to_company), 1
                        ):
                            company = future_to_company[future]
                            try:
                                result = future.result()
                            except Exception as e:
                                result = DetectionResult(
                                    company=company["name"],
                                    domain=company["domain"],
                                    error=str(e),
                                )
                            results.append((company, result))
                            progress.progress(
                                i / len(companies),
                                text=f"Checking {i}/{len(companies)}: {company['domain']}",
                            )

                    elapsed = time.time() - start_time
                    progress.progress(1.0, text="Detection complete!")

                    # Step 3 — Write results back to HubSpot
                    updated = 0
                    failed = 0
                    write_progress = st.progress(0, text="Updating HubSpot...")

                    for i, (company, result) in enumerate(results, 1):
                        if result.error:
                            # Skip companies with errors so they get retried next sync
                            failed += 1
                        else:
                            # Checkbox properties accept "true" / "false"
                            value = "true" if result.uses_hubspot else "false"
                            try:
                                ok = update_company_property(
                                    hubspot_token, company["id"], property_name, value
                                )
                                if ok:
                                    updated += 1
                                else:
                                    failed += 1
                            except Exception:
                                failed += 1

                        write_progress.progress(
                            i / len(results),
                            text=f"Updating {i}/{len(results)}: {company['name']}",
                        )

                    write_progress.progress(1.0, text="Done!")

                    # Summary
                    st.subheader("Sync Complete")
                    col_s1, col_s2, col_s3, col_s4 = st.columns(4)
                    with col_s1:
                        st.metric("Companies Checked", len(results))
                    with col_s2:
                        st.metric("Using HubSpot", sum(1 for _, r in results if r.uses_hubspot))
                    with col_s3:
                        st.metric("Updated in HubSpot", updated)
                    with col_s4:
                        st.metric("Failed Updates", failed)

                    st.success(
                        f"Done! Checked {len(results)} companies and updated "
                        f"{updated} records in {elapsed:.1f}s."
                    )
    else:
        st.info("Enter your HubSpot Private App token above to get started.")
