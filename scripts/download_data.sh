#!/usr/bin/env bash
# Idempotent download of AIT Alert Data Set into data/raw/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RAW="${ROOT}/data/raw"
mkdir -p "${RAW}"

CSV_MARKER="${RAW}/.csv_ok"
JSON_MARKER="${RAW}/.json_ok"
LABELS_MARKER="${RAW}/.labels_ok"
DECISIONS="${ROOT}/DECISIONS.md"

echo "=== Downloading AIT-ADS ==="

# 1) Pre-labeled CSVs (primary)
if [[ -f "${CSV_MARKER}" ]] && ls "${RAW}"/*_alerts.txt >/dev/null 2>&1; then
  echo "CSVs already present; skipping clone."
else
  TMP="$(mktemp -d)"
  echo "Cloning ait-aecid/alert-data-set into temp..."
  git clone --depth 1 https://github.com/ait-aecid/alert-data-set "${TMP}/alert-data-set"
  unzip -o "${TMP}/alert-data-set/alerts_csv/alerts_csv.zip" -d "${RAW}"
  # Flatten if zip created a subfolder
  if ls "${RAW}"/alerts_csv/*_alerts.txt >/dev/null 2>&1; then
    mv "${RAW}"/alerts_csv/*_alerts.txt "${RAW}/"
    rmdir "${RAW}/alerts_csv" 2>/dev/null || true
  fi
  rm -rf "${TMP}"
  touch "${CSV_MARKER}"
  echo "CSV alerts extracted to ${RAW}"
fi

# 2) Phase labels
if [[ -f "${LABELS_MARKER}" ]] && [[ -f "${RAW}/labels.csv" ]]; then
  echo "labels.csv already present."
else
  echo "Downloading labels.csv from Zenodo..."
  curl -L --fail --retry 3 -o "${RAW}/labels.csv" \
    "https://zenodo.org/records/8263181/files/labels.csv?download=1" \
    && touch "${LABELS_MARKER}" \
    || echo "WARN: labels.csv download failed; continuing with CSV time_label/event_label columns."
fi

# 3) Raw JSON (secondary)
if [[ -f "${JSON_MARKER}" ]]; then
  echo "Raw JSON already verified; skipping."
else
  echo "Downloading ait_ads.zip from Zenodo (optional, richer fields)..."
  ZIP="${RAW}/ait_ads.zip"
  if curl -L --fail --retry 3 -o "${ZIP}" \
    "https://zenodo.org/records/8263181/files/ait_ads.zip?download=1"; then
    ACTUAL_MD5="$(md5 -q "${ZIP}" 2>/dev/null || md5sum "${ZIP}" | awk '{print $1}')"
    EXPECTED="43db6b1f0996e0024befd617706c50e9"
    if [[ "${ACTUAL_MD5}" == "${EXPECTED}" ]]; then
      echo "MD5 ok (${ACTUAL_MD5}). Unzipping..."
      mkdir -p "${RAW}/json"
      unzip -o "${ZIP}" -d "${RAW}/json"
      touch "${JSON_MARKER}"
    else
      echo "WARN: MD5 mismatch (got ${ACTUAL_MD5}, expected ${EXPECTED}). Leaving zip; CSV path remains primary."
      echo "- Zenodo ait_ads.zip MD5 mismatch; continuing with CSVs only." >> "${DECISIONS}"
    fi
  else
    echo "WARN: Zenodo JSON download failed; continuing with CSVs only."
    if ! grep -q "Zenodo download failed" "${DECISIONS}" 2>/dev/null; then
      echo "- Zenodo JSON download failed; continuing with CSVs only (CSVs contain every alert)." >> "${DECISIONS}"
    fi
  fi
fi

echo "=== Data download done ==="
ls -la "${RAW}" | head -40
