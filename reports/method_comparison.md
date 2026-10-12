# Method comparison

Same splits: GroupKFold k=6 by scenario on training; final on russellmitchell and santos.

**Selected method:** `lookup`
**Reason:** lookup rare-stage CV F1 0.302 best

## CV rare-stage macro F1 (mean +/- std)

| method | rare_macro_f1 | relevance_pr_auc | alert_reduction |
| --- | ---: | ---: | ---: |
| lookup | 0.302 +/- 0.101 | 0.927 +/- 0.042 | 0.615 +/- 0.145 |
| rules | 0.177 +/- 0.089 | 0.895 +/- 0.095 | 0.993 +/- 0.004 |
| logistic | 0.172 +/- 0.102 | 0.975 +/- 0.029 | 0.359 +/- 0.141 |

## Held-out per-stage recall

| method | webshell | reverse_shell | privilege_escalation | pr_auc |
| --- | ---: | ---: | ---: | ---: |
| lookup | 0.333 | 0.143 | 0.531 | 0.991 |
| rules | 0.083 | 0.571 | 0.198 | 0.917 |
| logistic | 0.208 | 0.429 | 0.728 | 0.990 |

## Held-out detection latency (minutes)

### lookup
- webshell: russellmitchell: 0.0, santos: 0.3
- reverse_shell: russellmitchell: 0.0, santos: miss
- privilege_escalation: russellmitchell: 0.0, santos: 0.0

### rules
- webshell: russellmitchell: 0.3, santos: 1.1
- reverse_shell: russellmitchell: 0.0, santos: 0.0
- privilege_escalation: russellmitchell: 0.0, santos: 0.0

### logistic
- webshell: russellmitchell: 0.5, santos: 0.3
- reverse_shell: russellmitchell: miss, santos: 0.0
- privilege_escalation: russellmitchell: 0.0, santos: 0.0

## Chart: per-stage recall by method (held-out)

```
webshell
  lookup      0.33 |#############
  rules       0.08 |###
  logistic    0.21 |########
reverse_shell
  lookup      0.14 |######
  rules       0.57 |#######################
  logistic    0.43 |#################
privilege_escalation
  lookup      0.53 |#####################
  rules       0.20 |########
  logistic    0.73 |#############################
```

## Chart: relevance PR-AUC by method (held-out)

```
  lookup      0.99 |########################################
  rules       0.92 |#####################################
  logistic    0.99 |########################################
```

## Logistic top weights (critical stages)

### webshell
Positive: minutes_since_first (9.82), prior_recon (4.14), cnt_1m (2.17), cnt_30m (2.17), prior_webshell (1.53), distinct_detectors_30m (1.06), cnt_5m (0.90), prior_web_scan (0.69), rarity (0.56), is_suricata (0.30)
Negative: prior_cracking (-3.32), prior_priv_esc (-2.32), multi_detector_recent (-1.87), prior_reverse_shell (-1.81), noise_score (-0.77), prior_exfil (-0.48), is_wazuh (-0.29), is_aminer (-0.04), distinct_roles_30m (0.00), burst_vs_baseline (0.00)

### reverse_shell
Positive: cnt_30m (1.77), prior_reverse_shell (1.25), minutes_since_first (1.09), rarity (0.86), prior_webshell (0.77), multi_detector_recent (0.76), prior_web_scan (0.70), prior_recon (0.64), prior_cracking (0.42), prior_exfil (0.40)
Negative: distinct_detectors_30m (-1.87), prior_priv_esc (-1.81), cnt_1m (-0.56), is_wazuh (-0.22), distinct_roles_30m (0.00), burst_vs_baseline (0.00), cnt_5m (0.09), is_suricata (0.13), noise_score (0.14), is_aminer (0.32)

### privilege_escalation
Positive: prior_web_scan (1.43), prior_reverse_shell (1.28), cnt_30m (1.20), cnt_5m (1.11), prior_priv_esc (0.89), prior_recon (0.77), prior_webshell (0.75), noise_score (0.63), is_aminer (0.53), rarity (0.51)
Negative: cnt_1m (-2.73), minutes_since_first (-1.68), distinct_detectors_30m (-1.47), prior_exfil (-0.49), is_suricata (-0.10), is_wazuh (-0.04), distinct_roles_30m (0.00), burst_vs_baseline (0.00), multi_detector_recent (0.10), prior_cracking (0.50)
