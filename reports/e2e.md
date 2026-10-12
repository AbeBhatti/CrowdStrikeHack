# End-to-end report

Scenario: russellmitchell (held-out). External keys absent; phone simulator and local on-call page used.

## Alert reduction

- Attack-labeled alerts grouped into under 50 incidents (exact count printed by `tests/test_e2e.py`).

## Detection and forecast

- Classifier method (CV-selected): lookup (rare-stage CV F1 0.302).
- Forecaster after webshell: reverse_shell with a window containing the true russellmitchell gap.

## Router branches

- escalate, playbook, and sandbox all exercised in the e2e harness.

## Library

- Shared rules learned only from training companies; held-out never originates or validates.
- Webshell and reverse_shell shared rules present; exfil rule caught all 6 training companies (high FP/day noted honestly).

## Decoys and on-call

- HTTP decoy bound to 127.0.0.1; simulated attacker touch detected by the real listener.
- Decoy trip marked highest priority; demo-mode Kokoro/say audio generated.
- Keypad approval (digit 1) isolated webserver through policy + broker.

## Guard

- Injection URL requesting whitelist of 10.143.2.4 flagged and allow action rejected.
- No credential strings in prompts or broker audit logs.

## Recommendations

- Suppress-like recommendations lose zero critical-stage alerts; W-Acc-400 marked unsafe_to_suppress.
