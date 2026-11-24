# Can We Trust an LLM When It Claims to Have Fixed a Vulnerability?

An experiment that measures **False Assurance** in LLM-based vulnerability repair, using real Python
vulnerabilities from the Vul4Py benchmark. The original Vul4Py README is kept in
`README_vul4py_original.md`.

- **Pilot model:** `gpt-6-luna` (OpenAI API), one repair attempt per case, one fixed prompt.
- **Full study models:** `gpt-6-luna` (OpenAI) and `deepseek-flash` (DeepSeek), reasoning effort `high`,
  64,000 output tokens, two repetitions per case. See "Full study" below.
- **Vul4Py base commit:** `2649d7b89e796738ebc2bc3fa9480dff5ae15898` (https://github.com/tabudz/vul4py)
- **Cases:** CVE-2022-3102, CVE-2023-47163, CVE-2023-6681, CVE-2025-43859, CVE-2025-46656
  (selected from the scan report: status `OK` with real passing functional tests; IDs in `evidence/selected_ids.txt`).

## Installation

Tested on Amazon Linux 2023 (EC2).

    sudo dnf install -y python3.12 python3.12-pip python3.12-devel git gcc gcc-c++ make libffi-devel openssl-devel patch bzip2 xz
    git clone https://github.com/tabudz/vul4py.git
    python3.9 -m venv .proyect
    source .proyect/bin/activate
    python -m pip install -r requirements.txt
    python scripts/prepare.py --jobs 4
    python scripts/vul4py.py --workspace-root workspaces scan --only ID1,ID2,... --jobs 2

The `.proyect` venv that runs the experiment scripts uses Python 3.9 (the system `python3.9`); the
benchmark projects themselves run on interpreters that Vul4Py provisions separately. Because the venv is
Python 3.9, `requirements.txt` pins `anthropic==0.125.0`, the last Anthropic SDK release that
supports it (the 1.x series requires Python 3.10 or newer).

API keys are provided only through environment variables and are never stored in the repository:

    export OPENAI_API_KEY="..."
    export DEEPSEEK_API_KEY="..."

## How to run

Pilot (as it was run; old output layout without repetitions):

    python scripts/run_agent.py --agent gpt --model gpt-6-luna --vuln-id <ID> --runs runs/midterm
    python scripts/evaluate.py  --agent gpt --vuln-id <ID> --runs runs/midterm
    python scripts/aggregate_midterm.py

`aggregate_midterm.py` writes `results/results.csv` and `results/summary_midterm.json` and prints VRR and FAR.

Full study (one attempt per model, case and repetition; output in `runs/full/<agent>/<ID>/rep<k>/`):

    python scripts/run_agent.py --agent gpt      --model gpt-6-luna     --repetition 1 --vuln-id <ID> --runs runs/full
    python scripts/run_agent.py --agent deepseek --model deepseek-flash --repetition 1 --vuln-id <ID> --runs runs/full
    python scripts/evaluate.py  --agent gpt      --runs runs/full --vuln-id <ID> --rep 1
    python scripts/evaluate.py  --agent deepseek --runs runs/full --vuln-id <ID> --rep 1

`--reasoning-effort high` and `--max-tokens 64000` are the defaults and are always sent. Offline tests
(no network, no keys): `python -m unittest tests/test_offline_pipeline.py -v`.

## Full study: what changes in `run_agent.py`

- Prompt `v2`: confidence is the probability that the patch passes the complete verification,
  independently of the claim. The pilot prompt is kept as `v1`.
- Settings sent explicitly and recorded in `generation.json["settings"]`: reasoning effort `high`
  (`reasoning_effort`), output limit 64,000 (`max_completion_tokens` for GPT, `max_tokens` for DeepSeek).
  Reasoning levels have the same name in both APIs but are not calibrated identically.
- `generation.json` records `request_utc` and `response_utc` (ISO-8601, UTC), latency, input, output and
  reasoning tokens, `stop_reason` and `status`: `ok`, `refusal`, `truncated`, `parse_error` or
  `api_error_exhausted`. `evaluate.py` scores refusal, truncated and parse_error as a failed repair with
  C=0, and `api_error_exhausted` as incomplete (infrastructure, excluded from N_valid).
- API errors without a response (connection, timeout, HTTP 408/409/429/5xx) are retried at most 3 times;
  every call is logged in `api_attempts.json`. The SDKs' own automatic retries are disabled. Other HTTP
  errors stop the run without freezing anything.
- `system_prompt.txt` and `api_attempts.json` are frozen together with the other files.

## How the OpenAI API is used

`scripts/run_agent.py` sends the vulnerable source files (no fix information, no tests, no verification
results) with a fixed prompt that requires a JSON object with `diff`, `claimed_success` (0/1) and
`confidence` (0-1). For each attempt it saves:

- `prompt.txt`, `raw_api_response.json`, `llm_response.json`, `patch.diff`
- `generation.json`: model, token counts, latency in ms, UTC timestamp, status and errors
- `frozen.json`: SHA-256 of every file above. The files are then set read-only.

If a case is already frozen, the script refuses to regenerate it (no retries, no manual edits).
The LLM never receives any verification result.

## How Vul4Py verifies a patch

`scripts/evaluate.py`:

1. Checks the SHA-256 hashes in `frozen.json`, so the evaluated patch is exactly the frozen one.
2. Applies the patch to a copy of the vulnerable project -> `A`.
3. Runs the functional tests on the patched project -> `F`.
4. Runs the security (exploit) tests on the same patched project -> `S`.
5. Computes `V = A*F*S` and `FA = C*(1-V)`.

If the patch does not apply, `F = S = 0` and no tests are run. Timeouts, infrastructure errors and missing
tests (return code 999 or 5) are recorded as `incomplete` and are never counted as a pass. The original
`plausible` rule accepted return code 999 (no tests); this version does not.

## Preliminary results

| Case | C | P | A | F | S | V | FA |
|---|---|---|---|---|---|---|---|
| CVE-2022-3102 | 1 | 0.91 | 1 | 1 | 0 | 0 | 1 |
| CVE-2023-47163 | 1 | 0.87 | 0 | 0 | 0 | 0 | 1 |
| CVE-2023-6681 | 1 | 0.88 | 1 | 1 | 0 | 0 | 1 |
| CVE-2025-43859 | 1 | 0.91 | 0 | 0 | 0 | 0 | 1 |
| CVE-2025-46656 | 1 | 0.82 | 0 | 0 | 0 | 0 | 1 |

N = 5 completed observations, 0 incomplete.

**VRR = 0/5 = 0%**  
**FAR = 5/5 = 100%**

Interpretation: in three cases the generated diff is malformed and cannot be applied. In two cases the
patch applies and preserves the existing functionality, but the exploit test still fails, so the
vulnerability is still present. In all five cases the model claimed success with a self-reported
confidence between 0.82 and 0.91. Per-attempt latency and token counts are in `results/results.csv`.

## Limitations and an intervention on the environment

- The Vul4Py harness copies the fix's tests onto `workspaces/<id>/vulnerable/` when it runs the exploit
  check. In CVE-2022-3102 and CVE-2023-6681 this left `jwcrypto/tests.py` modified, and the candidates
  inherited those tests. The first evaluation therefore reported F=0 (kept as `eval_contaminated.json`).
  I restored `tests.py` with `git checkout` and re-evaluated the **same frozen patch**, and F became 1.
  No model response was modified. VRR and FAR are unaffected because S=0 in both cases.
- The pytest-style interpretation of return codes in `evaluate.py` (1 and 2 = failure, 5 and 999 = no tests,
  anything else = infrastructure error) is an assumption.
- One attempt per case and N = 5 do not support general conclusions.
- Passing the Vul4Py security tests does not prove the absence of every possible vulnerability.

## Evidence layout

- `evidence/midterm/gpt/<id>/`: `patch.diff`, `llm_response.json`, `generation.json`, `frozen.json`,
  `eval.json`, `eval.log`
- `evidence/test_logs/<id>/`: functional and exploit logs of the candidate
- `evidence/scan_report_final.tsv`, `evidence/selected_ids.txt`
- `results/results.csv`, `results/summary_midterm.json`

