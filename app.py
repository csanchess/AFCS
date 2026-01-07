# app.py

import streamlit as st
import pandas as pd
import requests
import difflib
import whois
from datetime import datetime
import xml.etree.ElementTree as ET

# ---------------------------
# CONFIG
# ---------------------------

UN_SANCTIONS_URL = "https://scsanctions.un.org/resources/xml/en/consolidated.xml"
OFAC_SDN_URL = "https://www.treasury.gov/ofac/downloads/sdn.csv"

MATCH_THRESHOLD = 85

# FATF-style country risk (public, simplified, transparent)
FATF_HIGH_RISK = {
    "iran", "north korea", "myanmar"
}

FATF_MONITORED = {
    "panama", "haiti", "south sudan", "syria"
}

# ---------------------------
# TEXT NORMALISATION & MATCHING
# ---------------------------

def normalize(text: str) -> str:
    return " ".join(sorted(text.lower().split()))

def similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio() * 100

def fuzzy_match(name, candidates):
    matches = []
    name_n = normalize(name)

    for c in candidates:
        score = similarity(name_n, normalize(c))
        if score >= MATCH_THRESHOLD:
            matches.append((c, round(score, 1)))

    return sorted(matches, key=lambda x: x[1], reverse=True)

# ---------------------------
# DATA LOADERS (CACHED)
# ---------------------------

@st.cache_data(ttl=86400)
def load_ofac():
    df = pd.read_csv(OFAC_SDN_URL)
    df.columns = [c.lower().strip() for c in df.columns]

    if "name" not in df.columns:
        raise ValueError("Unexpected OFAC SDN format")

    return df["name"].dropna().unique().tolist()

@st.cache_data(ttl=86400)
def load_un():
    r = requests.get(UN_SANCTIONS_URL, timeout=30)
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

# ---------------------------
# CYBER / DOMAIN SIGNALS
# ---------------------------

def check_domain(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "creation_date": str(w.creation_date),
            "registrar": w.registrar,
            "country": w.country
        }
    except Exception:
        return {
            "domain": domain,
            "error": "WHOIS lookup failed"
        }

# ---------------------------
# RISK SCORING (EXPLAINABLE)
# ---------------------------

def compute_risk(ofac_hit, un_hit, country):
    score = 0
    factors = []

    if ofac_hit:
        score += 60
        factors.append("OFAC sanctions exposure")

    if un_hit:
        score += 50
        factors.append("UN sanctions exposure")

    if country:
        c = country.lower()
        if c in FATF_HIGH_RISK:
            score += 20
            factors.append("High-risk FATF jurisdiction")
        elif c in FATF_MONITORED:
            score += 10
            factors.append("FATF monitored jurisdiction")

    return min(score, 100), factors

# ---------------------------
# STREAMLIT UI
# ---------------------------

st.set_page_config(
    page_title="Integrity & Financial Crime Screening",
    layout="wide"
)

st.title("🔍 Public Integrity & Financial Crime Screening Tool")

st.caption(
    "Uses UN Consolidated List and OFAC SDN List (public sources). "
    "Country risk is contextual (FATF-inspired). Not legal advice."
)

name = st.text_input("Individual or Organisation Name")
country = st.text_input("Country (optional)")
domain = st.text_input("Website / Domain (optional)")
run = st.button("Run Screening")

# ---------------------------
# SCREENING LOGIC
# ---------------------------

if run and name:

    with st.spinner("Running integrity screening…"):
        results = []
        ofac_hit = False
        un_hit = False

        # OFAC
        try:
            ofac_names = load_ofac()
            matches = fuzzy_match(name, ofac_names)
            if matches:
                ofac_hit = True
                results.append(("OFAC SDN List", matches))
        except Exception as e:
            st.warning(f"OFAC check failed: {e}")

        # UN
        try:
            un_names = load_un()
            matches = fuzzy_match(name, un_names)
            if matches:
                un_hit = True
                results.append(("UN Consolidated Sanctions List", matches))
        except Exception as e:
            st.warning(f"UN check failed: {e}")

    st.subheader("📋 Screening Results")

    if results:
        for source, matches in results:
            st.error(f"⚠️ Potential match on {source}")
            st.dataframe(
                pd.DataFrame(
                    matches,
                    columns=["Matched Name", "Similarity (%)"]
                )
            )
    else:
        st.success("✅ No matches found on UN or OFAC public lists")

    # Country risk
    if country:
        st.subheader("🌍 Country Risk Context")
        c = country.lower()
        if c in FATF_HIGH_RISK:
            st.warning("High-risk jurisdiction (FATF)")
        elif c in FATF_MONITORED:
            st.info("Monitored jurisdiction (FATF)")
        else:
            st.success("No elevated FATF country risk identified")

    # Cyber signals
    if domain:
        st.subheader("🌐 Cyber / Domain Signals")
        st.json(check_domain(domain))

    # Risk score
    risk_score, factors = compute_risk(ofac_hit, un_hit, country)

    st.subheader("📊 Overall Risk Assessment")
    st.metric("Indicative Risk Score", f"{risk_score} / 100")

    if factors:
        st.write("Risk drivers:")
        for f in factors:
            st.write(f"• {f}")
    else:
        st.write("No material public risk factors identified.")

    # Audit footer
    st.caption(
        f"Screened on {datetime.utcnow().isoformat()} UTC | "
        "Sources: OFAC SDN, UN Consolidated List | "
        "Public data only | Not legal advice"
    )

    st.caption(
        "Note: UN matching uses primary names only. "
        "Aliases and adverse media are not yet included."
    )
