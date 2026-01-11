# app.py

import streamlit as st
import pandas as pd
import requests
import whois
from datetime import datetime
import xml.etree.ElementTree as ET

from rapidfuzz import fuzz

# ---------------------------
# CONFIG
# ---------------------------

UN_SANCTIONS_URL = "https://scsanctions.un.org/resources/xml/en/consolidated.xml"
OFAC_SDN_URL = "https://www.treasury.gov/ofac/downloads/sdn.csv"

MATCH_THRESHOLD = 85

FATF_HIGH_RISK = {"iran", "north korea", "myanmar"}
FATF_MONITORED = {"panama", "haiti", "south sudan", "syria"}

# ---------------------------
# NORMALISATION & MATCHING
# ---------------------------

def normalize(text: str) -> str:
    return " ".join(text.lower().split())

def fuzzy_match(query, candidates):
    matches = []
    q = normalize(query)

    for c in candidates:
        score = fuzz.token_sort_ratio(q, normalize(c))
        if score >= MATCH_THRESHOLD:
            matches.append((c, score))

    return sorted(matches, key=lambda x: x[1], reverse=True)

# ---------------------------
# DATA LOADERS (CACHED)
# ---------------------------

@st.cache_data(ttl=86400)
def load_ofac():
    df = pd.read_csv(OFAC_SDN_URL)

    # OFAC uses SDN_NAME in most versions
    for col in df.columns:
        if col.lower() in {"sdn_name", "name"}:
            return df[col].dropna().unique().tolist()

    raise ValueError(f"OFAC SDN name column not found: {df.columns}")

@st.cache_data(ttl=86400)
def load_un():
    r = requests.get(UN_SANCTIONS_URL, timeout=30)
    tree = ET.fromstring(r.content)

    names = []

    for individual in tree.findall(".//INDIVIDUAL"):
        parts = [
            individual.findtext("FIRST_NAME"),
            individual.findtext("SECOND_NAME"),
            individual.findtext("THIRD_NAME"),
            individual.findtext("FOURTH_NAME"),
        ]
        full_name = " ".join(p for p in parts if p)
        if full_name:
            names.append(full_name)

        # aliases
        for alias in individual.findall(".//ALIAS_NAME"):
            if alias.text:
                names.append(alias.text)

    for entity in tree.findall(".//ENTITY"):
        name = entity.findtext("NAME")
        if name:
            names.append(name)

    return list(set(names))

# ---------------------------
# CYBER SIGNALS
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
        return {"domain": domain, "error": "WHOIS lookup failed"}

# ---------------------------
# RISK SCORING
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
