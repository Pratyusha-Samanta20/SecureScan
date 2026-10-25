"""
app.py — SecureScan Streamlit user interface.

Run with:
    streamlit run app.py
"""

import streamlit as st

import report_generator
import scanner

# ── Page configuration ────────────────────────────────────────────────────────

st.set_page_config(
    page_title="SecureScan — Website Security Checker",
    page_icon="🔍",
    layout="centered",
)

# ── Header ────────────────────────────────────────────────────────────────────

st.title("🔍 SecureScan")
st.subheader("Automated Website Security Checker")
st.write(
    "SecureScan inspects publicly accessible websites for common security-header "
    "configurations. It performs only standard HTTP GET requests and does **not** "
    "test for vulnerabilities, exploit weaknesses, or collect any personal data."
)

# ── Responsible-use notice ────────────────────────────────────────────────────

with st.expander("⚠️ Responsible Use — please read before scanning"):
    st.warning(
        "**Only scan websites you own or have explicit written permission to test.** "
        "Scanning third-party websites without permission may violate laws and terms "
        "of service. This tool is intended for educational purposes and defensive "
        "security awareness only.\n\n"
        "SecureScan checks a limited set of observable HTTP security configurations. "
        "A passing result does **not** mean the website is fully secure, and a "
        "warning does **not** necessarily mean a vulnerability exists. This tool "
        "does **not** replace a professional security audit."
    )

st.divider()

# ── URL input ─────────────────────────────────────────────────────────────────

url_input = st.text_input(
    "Enter a website URL to scan",
    placeholder="https://example.com",
    help="Enter a public URL starting with https:// or http://",
)

scan_clicked = st.button("🔎 Scan Website", type="primary")

# ── Scan logic ────────────────────────────────────────────────────────────────

if scan_clicked:
    if not url_input.strip():
        st.error("Please enter a URL before scanning.")
        st.stop()

    with st.spinner("Scanning — this may take a few seconds …"):
        result = scanner.scan_website(url_input.strip())

    if not result["success"]:
        st.error(f"**Scan failed:** {result['error']}")
        st.stop()

    checks = result["checks"]
    pass_count = sum(1 for c in checks if c["status"] == "PASS")
    warn_count = sum(1 for c in checks if c["status"] == "WARNING")
    info_count = sum(1 for c in checks if c["status"] == "INFO")
    total = len(checks)

    # ── Summary metrics ───────────────────────────────────────────────────────

    st.divider()
    st.subheader("📊 Scan Results")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Checks", total)
    col2.metric("✅ Passed", pass_count)
    col3.metric("⚠️ Warnings", warn_count)
    col4.metric("ℹ️ Info", info_count)

    # Overall summary sentence
    if warn_count == 0:
        st.success(
            "All security-header checks passed. Remember: this covers only a "
            "limited set of configurations and does not guarantee full security."
        )
    elif warn_count <= 2:
        st.warning(
            f"{warn_count} configuration issue(s) found. Review the findings below "
            "and consider addressing any warnings."
        )
    else:
        st.error(
            f"{warn_count} configuration issues found. Several security headers "
            "appear to be missing or misconfigured. Review the findings below."
        )

    # ── Scan metadata ─────────────────────────────────────────────────────────

    with st.expander("🔗 Connection Details"):
        st.write(f"**Original URL:** {result['original_url']}")
        st.write(f"**Final URL:** {result['final_url']}")
        st.write(f"**HTTP Status Code:** {result['status_code']}")

    # ── Findings table ────────────────────────────────────────────────────────

    st.subheader("🔐 Security Findings")

    STATUS_ICON = {"PASS": "✅", "WARNING": "⚠️", "INFO": "ℹ️"}

    for check in checks:
        status = check["status"]
        icon = STATUS_ICON.get(status, "")
        label = f"{icon} **{check['check']}** — {status}"

        if status == "PASS":
            with st.expander(label):
                st.write(f"**Value:** `{check['value']}`")
                st.write(f"**Finding:** {check['explanation']}")
        elif status == "WARNING":
            with st.expander(label, expanded=True):
                st.write(f"**Value:** `{check['value']}`")
                st.write(f"**Finding:** {check['explanation']}")
                if check["recommendation"]:
                    st.info(f"**Recommendation:** {check['recommendation']}")
        else:  # INFO
            with st.expander(label):
                st.write(f"**Value:** `{check['value']}`")
                st.write(f"**Finding:** {check['explanation']}")

    # ── Recommendations summary ───────────────────────────────────────────────

    recommendations = [
        c for c in checks if c["status"] == "WARNING" and c["recommendation"]
    ]
    if recommendations:
        st.subheader("📋 Recommendations Summary")
        for i, rec in enumerate(recommendations, start=1):
            st.markdown(f"**{i}. {rec['check']}**")
            st.write(rec["recommendation"])

    # ── Report downloads ──────────────────────────────────────────────────────

    st.subheader("📥 Download Report")

    csv_data = report_generator.generate_csv(result)
    text_data = report_generator.generate_text(result)

    from urllib.parse import urlparse
    safe_hostname = urlparse(result["final_url"]).hostname or "report"
    safe_hostname = safe_hostname.replace(".", "_")

    dl_col1, dl_col2 = st.columns(2)
    with dl_col1:
        st.download_button(
            label="⬇️ Download CSV Report",
            data=csv_data,
            file_name=f"securescan_{safe_hostname}.csv",
            mime="text/csv",
        )
    with dl_col2:
        st.download_button(
            label="⬇️ Download Text Report",
            data=text_data,
            file_name=f"securescan_{safe_hostname}.txt",
            mime="text/plain",
        )

    # ── Disclaimer ────────────────────────────────────────────────────────────

    st.divider()
    st.caption(
        "⚠️ **Disclaimer:** SecureScan checks a limited set of visible HTTP security "
        "configurations. Results do not reflect the overall security posture of a "
        "website and do not replace a professional security audit. Use this tool "
        "only on websites you own or have explicit permission to test."
    )

# ── Footer ────────────────────────────────────────────────────────────────────

st.divider()
st.caption(
    "SecureScan — Built for IBM SkillsBuild National Cybersecurity Bootcamp | "
    "Educational use only"
)
