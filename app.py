import streamlit as st
from pathlib import Path
from repo_shield.cli import scan_text, redact_text

st.set_page_config(
    page_title="RepoShield | Secret Scanner",
    page_icon="🛡️",
    layout="centered",
)

st.title("🛡️ RepoShield")
st.subheader("Find exposed secrets before you push.")
st.write("Scan sample text for potential credentials.")
st.warning("Use sample data only. Never paste real API keys or passwords.")

text = st.text_area(
    "Text to scan",
    height=220,
    placeholder="Paste sample code or configuration here...",
)

if st.button("Scan text", type="primary", use_container_width=True):
    if not text.strip():
        st.info("Paste some text first.")
    else:
        try:
            findings = scan_text(Path("sample.txt"), text)

            if not findings:
                st.success("No potential secrets detected.")
            else:
                st.error(f"Found {len(findings)} potential secret(s).")
                for finding in findings:
                    st.write(
                        f"**Type:** {finding.kind}  |  "
                        f"**Line:** {finding.line}"
                    )
                st.caption(
                    "Matched secret values are intentionally hidden."
                )
        except Exception:
            st.error(
                "The scan could not be completed. "
                "Please check the scanner integration."
            )
