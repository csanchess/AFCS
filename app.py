# app.py

import streamlit as st
import pandas as pd
import requests
import difflib
from datetime import datetime

# ---------------------------
# CONFIG
# ---------------------------

UN_SANCTIONS_URL = "https://scsanctions.un.org/resources/xml/en/consolidated.xml"
OFAC_SDN_URL = "https://www.treasury.gov/ofac/downloads/sdn.csv"
FATF_URL = "https://www.fatf-gafi.org/en/topics/high-risk-and-other-monitored-jurisdictions.html"

MATCH_THRESHOLD = 85

# ---------------------------
# HELPERS
# ---------------------------

def similarity(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio() * 100

def fuzzy_match(name, candidates):
    matches = []
    for c in candidates:
        score = similarity(name.lower(), c.lower())
        if score >= MATCH_THRESHOLD:
            matches.append((c, score))
    return matches


def load_ofac():
    df = pd.read_csv(OFAC_SDN_URL)

    # Normalize column names
    df.columns = [c.lower().strip() for c in df.columns]

    # OFAC SDN usually uses 'name'
    if "name" not in df.columns:
        raise ValueError(f"OFAC columns not as expected: {df.columns}")

    return df["name"].dropna().unique().tolist()

def load_un():
    import xml.etree.ElementTree as ET
    r = requests.get(UN_SANCTIONS_URL)
    tree = ET.fromstring(r.content)

    names = []
    for individual in tree.findall(".//INDIVIDUAL"):
        name = " ".join(filter(None, [
            individual.findtext("FIRST_NAME"),
            individual.findtext("SECOND_NAME"),
            individual.findtext("THIRD_NAME")
        ]))
        if name.strip():
            names.append(name)

    for entity in tree.findall(".//ENTITY"):
        name = entity.findtext("NAME")
        if name:
            names.append(name)

    return list(set(names))


def check_domain(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "creation_date": w.creation_date,
            "registrar": w.registrar,
            "country": w.country
        }
    except Exception:
        return {"domain": domain, "error": "WHOIS lookup failed"}


# ---------------------------
# STREAMLIT UI
# ---------------------------

st.set_page_config(page_title="Integrity & Financial Crime Screening", layout="wide")
st.title("🔍 Public Integrity & Financial Crime Screening Tool")

st.caption("Uses UN, OFAC, FATF public sources – non-commercial, transparency-first")

name = st.text_input("Individual or Organisation Name")
country = st.text_input("Country (optional)")
domain = st.text_input("Website / Domain (optional)")
run = st.button("Run Screening")

# ---------------------------
# SCREENING LOGIC
# ---------------------------

if run and name:
    with st.spinner("Checking public watchlists…"):
        results = []

        # OFAC
        try:
            ofac_names = load_ofac()
            matches = fuzzy_match(name, ofac_names)
            if matches:
                results.append(("OFAC SDN", matches))
        except Exception as e:
            st.warning(f"OFAC check failed: {e}")

        # UN
        try:
            un_names = load_un()
            matches = fuzzy_match(name, un_names)
            if matches:
                results.append(("UN Sanctions", matches))
        except Exception as e:
            st.warning(f"UN check failed: {e}")

    st.subheader("📋 Screening Results")

    if results:
        for source, matches in results:
            st.error(f"⚠️ Potential Match on {source}")
            df = pd.DataFrame(matches, columns=["Matched Name", "Similarity Score"])
            st.dataframe(df)
    else:
        st.success("✅ No matches found in UN or OFAC public lists")

    # Domain / cyber signal
    if domain:
        st.subheader("🌐 Cyber / Domain Signals")
        domain_info = check_domain(domain)
        st.json(domain_info)

    # Audit footer
    st.caption(
        f"Screened on {datetime.utcnow().isoformat()} UTC | "
        "Public data only | Not legal advice"
    )
