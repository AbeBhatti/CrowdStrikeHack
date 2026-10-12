# On-Call Security Teammate

A local 24/7 security teammate for teams without a SOC. It triages endpoint and network alerts, forecasts the next attack stage, places predictive decoys, and phones the on-call engineer for irreversible actions. The dashboard is the audit trail. Everything runs on your Mac; only short plain-language summaries leave the machine when notification keys are configured.

See `DEMO.md` for the live demo script and `docs/SETUP_KEYS.md` for free Twilio / PagerDuty / Telegram setup.

## Quick start

```bash
make setup && make train && make library && make demo
```

## Data

AIT Alert Data Set (AIT-ADS), CC BY 4.0.

Landauer, M., Skopik, F., Wurzenberger, M. (2024). Introducing a New Alert Data Set for Multi-Step Attack Analysis. Proceedings of the 17th Cyber Security Experimentation and Test Workshop.

## Status

Build in progress. Architecture, results, limitations, and isolation guarantees will be filled in the final deliverable pass.
