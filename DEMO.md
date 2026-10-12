# 3-minute live demo

Start with `make demo`. Use **demo** voice mode for the call. Switch to **normal** if a judge asks a serious question.

Classifier comparison (CV only): alert-type lookup won rare-stage macro F1 0.302 over rules 0.177 and logistic 0.172. The pipeline uses lookup.

1. Start replay on russellmitchell. Tens of thousands of alerts collapse into a few incidents on the counters and kill-chain graph.
2. Webshell is caught. A defense library rule fires and names its origin company (learned at another training company, never from held-out data).
3. The webshell playbook blocks the source IP automatically through the guard-dog broker and mock firewall.
4. The forecast says reverse_shell is likely in about 30 to 45 minutes. A decoy is placed on the predicted host role (127.0.0.1 only).
5. Run the attacker simulator against the decoy. Say "simulated" out loud. The real decoy service detects the trip.
6. The phone rings (Twilio if keys exist, otherwise the phone simulator). Press 1. The host is isolated and the on-call incident moves to acknowledged (PagerDuty mirrors when configured).
7. Show the planted injection alert being quoted as data, flagged, and rejected at the policy engine.
8. Use what-if on the graph: place a block at webshell and show downstream stages as prevented. The UI states that this assumes blocking a stage stops later stages.
9. Open recommendations: noise reduction with zero critical attack alerts lost, plus an unsafe-to-suppress note for W-Acc-400.
