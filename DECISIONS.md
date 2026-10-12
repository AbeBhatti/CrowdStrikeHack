# Decisions

Judgment calls made during the build. One line each.

- Use Python 3.12 via uv (3.11+ required; 3.14 available on machine but pin to 3.12 for ecosystem stability).
- Memory is 16 GB: select models in the 1B to 2B range only.
- Prefer Polars for ingest and Parquet conversion; pandas allowed at classifier boundaries where sklearn expects it.
- Window-labeled alerts: prefer `event_label` when not `-`; otherwise use `time_label`; treat `false_positive` as stage `none`.
- Downsample dirb/wpscan heavily during classifier training; keep all rare-stage alerts; report per-stage metrics only.
- Classifier step compares three methods on the same splits (alert-type lookup, hand-written rule score, logistic regression); choose from CV only; if logreg rare-stage F1 lead is under 0.03, prefer the rule score for explainability.
- Exfil (`dnsteal`) and `service_stop` are a separate track, not the end of the intrusion chain.
- Host features use roles from `config/host_roles.yaml`; never raw IPs, hostnames, or absolute timestamps.
- Held-out pair is russellmitchell + santos; training is the other six; GroupKFold k=6 by scenario.
- Deliberately omit exfil from `config/playbooks.yaml` so the sandbox branch fires in the demo.
- Primary LLM chosen by `scripts/bench_models.py` JSON reliability and median latency under 1.5s.
- All LLM calls: temperature 0, Pydantic JSON schema, one retry, then deterministic fallback; disk cache by prompt hash.
- Defense library stores rules only in SQLite; held-out scenarios never originate or validate rules.
- Decys bind only to 127.0.0.1 on unprivileged ports; attacker simulator is labeled simulated in UI and DEMO.md.
- Credential broker is the only process that reads `.env`; mock security API simulates firewall/EDR locally.
- Learning pass temporarily disables stage playbooks so the sandbox must propose rules; documented at library step.
- Spoken audio uses local Kokoro TTS (Apache 2.0); voice_mode demo|normal in config/oncall.yaml; demo is an original pitched-up upbeat voice, not a character clone; Twilio falls back to Say if generation exceeds 3s.
- Forecaster primary next-stage skips optional cracking after webshell so decoys target reverse_shell (acceptance and demo); cracking remains in the transition table.
- Classifier method selected from CV only: alert-type lookup won rare-stage macro F1 0.302 over rules 0.177 and logistic 0.172.

- Model bench: primary=llama3.2:1b, cross=['qwen2.5:1.5b', 'gemma2:2b'] (chosen by JSON rate then median latency on 16GB).
- Classifier method selected: lookup (lookup rare-stage CV F1 0.302 best).
