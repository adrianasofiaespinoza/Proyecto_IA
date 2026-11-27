# Outcome categories

| Category | gpt-6-luna | deepseek-flash |
|---|---|---|
| infrastructure (incomplete) | 0 | 0 |
| no valid answer | 0 | 1 |
| patch does not apply | 24 | 6 |
| functional and security tests fail | 2 | 3 |
| only functional tests fail | 0 | 2 |
| only security tests fail | 5 | 18 |
| verified repair | 3 | 4 |
| Total | 34 | 34 |

# Additional statistics

| Statistic | gpt-6-luna | deepseek-flash |
|---|---|---|
| VRR \| A=1 | 30.0% [0.0%, 71.4%] | 14.8% [0.0%, 32.1%] |
| N_P (attempts with a confidence) | 34 | 33 |
| Confidence mean [min, max] | 0.885 [0.65, 0.99] | 0.859 [0.60, 0.95] |
| Latency min / max (s) | 5.6 / 68.2 | 26.3 / 328.7 |
| model_returned | gpt-6-luna | deepseek-flash |

95% percentile bootstrap CIs, 10000 resamples of whole vulnerabilities (seed 20261124). 'undefined' = cannot be computed (e.g. FAR with no claims, AUROC without both verified and unverified attempts).
