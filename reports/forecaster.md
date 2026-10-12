# Forecaster

Training scenarios: fox, harrison, shaw, wardbeck, wheeler, wilson

## Transitions

- recon -> web_scan=1.00
- web_scan -> webshell=1.00
- webshell -> cracking=0.83, reverse_shell=0.17
- cracking -> reverse_shell=1.00
- reverse_shell -> privilege_escalation=1.00

## Gaps (minutes)

- recon->web_scan: median=3.1 min=1.4 max=23.6
- web_scan->webshell: median=18.9 min=1.0 max=27.5
- webshell->cracking: median=0.3 min=0.3 max=1.4
- cracking->reverse_shell: median=39.4 min=27.2 max=40.5
- reverse_shell->privilege_escalation: median=0.6 min=0.2 max=0.7
- webshell->reverse_shell: median=40.3 min=27.5 max=594.5

After webshell, predicted next=reverse_shell p=1.00 window=(27.516666666666666, 594.45)
