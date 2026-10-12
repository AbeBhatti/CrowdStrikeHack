# Classifier

Configured method: `lookup`

Rare-stage macro F1 (held-out): 0.396
Relevance PR-AUC: 0.991
Alert reduction: 0.255
FP/day: 18.85

## Per-stage F1 (held-out)

- cracking: P=0.207 R=0.008 F1=0.015
- exfil: P=0.721 R=0.999 F1=0.837
- none: P=0.837 R=0.030 F1=0.058
- privilege_escalation: P=0.512 R=0.531 F1=0.521
- recon: P=0.644 R=0.568 F1=0.604
- reverse_shell: P=0.500 R=0.143 F1=0.222
- service_stop: P=0.000 R=0.000 F1=0.000
- web_scan: P=0.993 R=0.993 F1=0.993
- webshell: P=0.667 R=0.333 F1=0.444

## Detection latency (minutes)

- webshell: russellmitchell: 0.0, santos: 0.3
- reverse_shell: russellmitchell: 0.0, santos: miss
- privilege_escalation: russellmitchell: 0.0, santos: 0.0
