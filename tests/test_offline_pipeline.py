#!/usr/bin/env python3
"""
Offline tests for run_agent.py and the generation-status handling of evaluate.py.

No network access and no API keys: the real openai / anthropic SDKs are used, but
their HTTP client is replaced by an httpx.MockTransport that answers locally, so
request construction, SSE streaming, stop reasons and HTTP errors go through the
same code paths as a real call. Dummy keys are set only inside this process.

Run:  .proyect/bin/python -m unittest tests/test_offline_pipeline.py -v
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import evaluate as ev  # noqa: E402
import run_agent as ra  # noqa: E402

DUMMY_ENV = {"OPENAI_API_KEY": "dummy-openai", "ANTHROPIC_API_KEY": "dummy-anthropic",
             "DEEPSEEK_API_KEY": "dummy-deepseek"}
GOOD = json.dumps({"diff": "--- a/pkg/mod.py\n+++ b/pkg/mod.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n",
                   "claimed_success": 1, "confidence": 0.7})


# ---------- mock HTTP servers ----------

def sse(events):
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events)


def anthropic_stream_body(text: str, stop_reason: str):
    return sse([
        {"type": "message_start", "message": {
            "id": "msg_test", "type": "message", "role": "assistant",
            "model": "claude-opus-5-5", "content": [], "stop_reason": None,
            "stop_sequence": None, "usage": {"input_tokens": 11, "output_tokens": 1}}},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": stop_reason, "stop_sequence": None},
         "usage": {"output_tokens": 42}},
        {"type": "message_stop"},
    ])


def openai_body(text, finish="stop", refusal=None, model="m"):
    return {"id": "cmpl_test", "object": "chat.completion", "created": 0, "model": model,
            "choices": [{"index": 0, "finish_reason": finish,
                         "message": {"role": "assistant", "content": text, "refusal": refusal}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 42, "total_tokens": 53}}


class MockServer:
    """Records requests; answers with queued (status, kind, payload) responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status, kind, payload = self.responses.pop(0)
        if kind == "sse":
            return httpx.Response(status, text=payload,
                                  headers={"content-type": "text/event-stream"})
        return httpx.Response(status, json=payload)

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self.handler))


def patch_sdks(server: MockServer):
    """Make every OpenAI/Anthropic client created inside run_agent use the mock."""
    import anthropic
    import openai
    real_a, real_o = anthropic.Anthropic, openai.OpenAI

    def make_a(*a, **k):
        k["http_client"] = server.client()
        return real_a(*a, **k)

    def make_o(*a, **k):
        k["http_client"] = server.client()
        return real_o(*a, **k)

    return mock.patch.multiple(anthropic, Anthropic=make_a), mock.patch.multiple(openai, OpenAI=make_o)


def fake_case(root: Path) -> Path:
    case = root / "workspaces" / "CVE-TEST-1"
    (case / "vulnerable" / "pkg").mkdir(parents=True)
    (case / "vulnerable" / "pkg" / "mod.py").write_text("x = 1\n")
    (case / "meta.json").write_text(json.dumps({"new_code_files": ["pkg/mod.py"]}))
    return case


# ---------- tests ----------

class TestParsingAndStatus(unittest.TestCase):
    def test_status_mapping(self):
        parsed, _ = ra.parse_response(GOOD)
        self.assertEqual(ra.generation_status(parsed, {"refusal": False, "truncated": False}), "ok")
        self.assertEqual(ra.generation_status(parsed, {"refusal": True, "truncated": False}), "refusal")
        bad, err = ra.parse_response(GOOD[:40])
        self.assertIsNone(bad)
        self.assertEqual(ra.generation_status(bad, {"refusal": False, "truncated": True}), "truncated")
        self.assertEqual(ra.generation_status(bad, {"refusal": False, "truncated": False}), "parse_error")

    def test_prompts(self):
        self.assertIn("probability", ra.SYSTEM_PROMPT_V2)
        self.assertIn("independently", ra.SYSTEM_PROMPT_V2)
        self.assertIn("confidence in that claim", ra.SYSTEM_PROMPT_V1)  # pilot wording kept


class FakeErr(Exception):
    def __init__(self, status=None):
        super().__init__(f"fake status {status}")
        self.status_code = status


class TestRetries(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.log = self.tmp / "api_attempts.json"
        self.sleeps = []

    def run_calls(self, outcomes):
        seq = list(outcomes)

        def call():
            o = seq.pop(0)
            if isinstance(o, Exception):
                raise o
            return o
        return ra.call_with_retries(call, self.log, sleep=self.sleeps.append)

    def test_exhausted_after_three_retries(self):
        res, att = self.run_calls([FakeErr(503)] * 4)
        self.assertIsNone(res)
        self.assertEqual(len(att), 1 + ra.MAX_API_RETRIES)
        self.assertEqual(len(json.loads(self.log.read_text())), 4)
        self.assertEqual(self.sleeps, list(ra.RETRY_BACKOFF_S))

    def test_success_after_retries(self):
        res, att = self.run_calls([FakeErr(429), FakeErr(500), "RESULT"])
        self.assertEqual(res, "RESULT")
        self.assertEqual([a["outcome"] for a in att], ["error", "error", "response"])

    def test_config_error_not_retried(self):
        with self.assertRaises(ra.ConfigError):
            self.run_calls([FakeErr(401)])
        self.assertEqual(len(json.loads(self.log.read_text())), 1)

    def test_interrupted_calls_count(self):
        self.log.write_text(json.dumps([{"call": 1, "outcome": "started"},
                                        {"call": 2, "outcome": "started"}]))
        res, att = self.run_calls([FakeErr(503), FakeErr(503)])
        self.assertIsNone(res)
        self.assertEqual([a["outcome"] for a in att],
                         ["interrupted", "interrupted", "error", "error"])


class TestProvidersThroughSDK(unittest.TestCase):
    """Real SDK code, mocked HTTP: checks requests and response handling."""

    def setUp(self):
        self.env = mock.patch.dict(os.environ, DUMMY_ENV)
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def _run(self, responses, fn):
        server = MockServer(responses)
        pa, po = patch_sdks(server)
        with pa, po:
            out = fn()
        return out, server

    def test_claude_request_and_ok(self):
        (text, info, raw, sig), srv = self._run(
            [(200, "sse", anthropic_stream_body(GOOD, "end_turn"))],
            lambda: ra.call_anthropic("SYS", "USER", "claude-opus-5-5", "medium", 64000))
        self.assertEqual(len(srv.requests), 1)
        req = srv.requests[0]
        body = json.loads(req.content)
        self.assertEqual(req.url.host, "api.anthropic.com")
        self.assertEqual(req.headers["x-api-key"], "dummy-anthropic")
        self.assertEqual(body["model"], "claude-opus-5-5")
        self.assertEqual(body["system"], "SYS")
        self.assertEqual(body["max_tokens"], 64000)
        self.assertEqual(body["output_config"], {"effort": "medium"})
        self.assertTrue(body["stream"])
        for forbidden in ("temperature", "thinking", "fallbacks"):
            self.assertNotIn(forbidden, body)
        self.assertEqual(text, GOOD)
        self.assertEqual(info["stop_reason"], "end_turn")
        self.assertEqual((info["input_tokens"], info["output_tokens"]), (11, 42))
        self.assertGreaterEqual(info["latency_ms"], 0)
        self.assertEqual(sig, {"refusal": False, "truncated": False})
        self.assertEqual(raw["id"], "msg_test")

    def test_claude_refusal_and_truncation(self):
        (_, _, _, sig), _ = self._run(
            [(200, "sse", anthropic_stream_body("", "refusal"))],
            lambda: ra.call_anthropic("S", "U", "claude-opus-5-5", "medium", 64000))
        self.assertTrue(sig["refusal"])
        (_, _, _, sig), _ = self._run(
            [(200, "sse", anthropic_stream_body(GOOD[:30], "max_tokens"))],
            lambda: ra.call_anthropic("S", "U", "claude-opus-5-5", "medium", 64000))
        self.assertTrue(sig["truncated"])

    def test_deepseek_request(self):
        (text, info, _, sig), srv = self._run(
            [(200, "json", openai_body(GOOD, model="deepseek-test"))],
            lambda: ra.call_openai_compatible("deepseek", "SYS", "USER", "deepseek-test",
                                              None, 32000))
        req = srv.requests[0]
        body = json.loads(req.content)
        self.assertEqual(req.url.host, "api.deepseek.com")
        self.assertEqual(req.headers["authorization"], "Bearer dummy-deepseek")
        self.assertEqual(body["messages"][0], {"role": "system", "content": "SYS"})
        self.assertEqual(body["max_tokens"], 32000)
        self.assertNotIn("temperature", body)
        self.assertEqual(text, GOOD)
        self.assertEqual(sig, {"refusal": False, "truncated": False})

    def test_gpt_request_matches_pilot_shape(self):
        (_, _, _, sig), srv = self._run(
            [(200, "json", openai_body("", finish="stop", refusal="I can't help"))],
            lambda: ra.call_openai_compatible("gpt", "SYS", "USER", "gpt-6-luna", None, None))
        req = srv.requests[0]
        body = json.loads(req.content)
        self.assertEqual(req.url.host, "api.openai.com")
        self.assertNotIn("max_tokens", body)
        self.assertTrue(sig["refusal"])

    def test_sdk_auto_retries_disabled_and_errors_classified(self):
        for status, retryable in ((500, True), (429, True), (401, False), (404, False)):
            server = MockServer([(status, "json", {"error": {"message": "x"}})] * 5)
            pa, po = patch_sdks(server)
            with pa, po:
                with self.assertRaises(Exception) as cm:
                    ra.call_openai_compatible("deepseek", "S", "U", "m", None, None)
            self.assertEqual(len(server.requests), 1, f"SDK retried on {status}")
            self.assertEqual(ra.is_retryable(cm.exception), retryable, status)
            server = MockServer([(status, "json", {"type": "error",
                                                   "error": {"type": "x", "message": "x"}})] * 5)
            pa, po = patch_sdks(server)
            with pa, po:
                with self.assertRaises(Exception) as cm:
                    ra.call_anthropic("S", "U", "claude-opus-5-5", "medium", 64000)
            self.assertEqual(len(server.requests), 1, f"SDK retried on {status}")
            self.assertEqual(ra.is_retryable(cm.exception), retryable, status)


class TestRunBuiltinEndToEnd(unittest.TestCase):
    """run_builtin with the real SDK + mocked HTTP, then evaluate.evaluate_one."""

    def setUp(self):
        self.env = mock.patch.dict(os.environ, DUMMY_ENV)
        self.env.start()
        self.root = Path(tempfile.mkdtemp())
        self.case = fake_case(self.root)
        self.runs = self.root / "runs"

    def tearDown(self):
        self.env.stop()

    def attempt(self, agent, model, responses, rep=1, **kw):
        server = MockServer(responses)
        pa, po = patch_sdks(server)
        out = self.runs / agent / "CVE-TEST-1" / f"rep{rep}"
        with pa, po:
            rc = ra.run_builtin(agent, model, "CVE-TEST-1", rep, self.case, out, "v2",
                                None, kw.get("max_tokens", 64000 if agent == "claude" else None),
                                "medium" if agent == "claude" else None,
                                sleep=lambda s: None)
        return rc, out, server

    def evaluate(self, agent, rep=1):
        return ev.evaluate_one(self.root / "workspaces", self.runs, agent, "CVE-TEST-1",
                               rep=rep)

    def test_ok_is_frozen_and_prompt_v2(self):
        rc, out, _ = self.attempt("claude", "claude-opus-5-5",
                                  [(200, "sse", anthropic_stream_body(GOOD, "end_turn"))])
        self.assertEqual(rc, 0)
        gen = json.loads((out / "generation.json").read_text())
        self.assertEqual((gen["status"], gen["claimed_success"], gen["confidence"]), ("ok", 1, 0.7))
        self.assertEqual((gen["repetition"], gen["prompt_version"], gen["api_calls"]), (1, "v2", 1))
        self.assertEqual((out / "system_prompt.txt").read_text(), ra.SYSTEM_PROMPT_V2)
        frozen = json.loads((out / "frozen.json").read_text())["sha256"]
        for n in ("system_prompt.txt", "prompt.txt", "raw_api_response.json",
                  "llm_response.json", "patch.diff", "api_attempts.json", "generation.json"):
            self.assertIn(n, frozen)
            self.assertFalse(os.stat(out / n).st_mode & stat.S_IWUSR, n)
        self.assertNotIn("dummy", "".join(p.read_text() for p in out.iterdir() if p.is_file()))
        # Second run of the same (agent, case, rep) is refused without any API call.
        rc2, _, srv2 = self.attempt("claude", "claude-opus-5-5", [])
        self.assertEqual((rc2, len(srv2.requests)), (3, 0))

    def test_no_usable_answer_is_complete_failure_with_c0(self):
        cases = {
            "refusal": ("claude", [(200, "sse", anthropic_stream_body("", "refusal"))]),
            "truncated": ("deepseek", [(200, "json", openai_body(GOOD[:50], finish="length"))]),
            "parse_error": ("gpt", [(200, "json", openai_body("I think the fix is..."))]),
        }
        for status, (agent, resp) in cases.items():
            rc, out, _ = self.attempt(agent, "m", resp)
            self.assertEqual(rc, 4, status)
            gen = json.loads((out / "generation.json").read_text())
            self.assertEqual(gen["status"], status)
            self.assertFalse((out / "patch.diff").exists())
            v = self.evaluate(agent)
            self.assertEqual((v["status"], v["generation_status"]), ("complete", status))
            self.assertEqual((v["C"], v["A"], v["F"], v["S"], v["V"], v["FA"]),
                             (0, 0, 0, 0, 0, 0), status)
            self.assertIsNone(v["P"])

    def test_api_exhausted_is_frozen_and_incomplete(self):
        rc, out, srv = self.attempt("deepseek", "m", [(503, "json", {"error": {}})] * 4)
        self.assertEqual((rc, len(srv.requests)), (5, 4))
        gen = json.loads((out / "generation.json").read_text())
        self.assertEqual((gen["status"], gen["api_calls"]), ("api_error_exhausted", 4))
        self.assertTrue((out / "frozen.json").exists())
        v = self.evaluate("deepseek")
        self.assertEqual(v["status"], "incomplete")
        self.assertTrue(v["incomplete_reason"].startswith("infra_api_error"))
        self.assertIsNone(v["V"])

    def test_retry_then_success(self):
        rc, out, srv = self.attempt("gpt", "gpt-6-luna",
                                    [(500, "json", {"error": {}}), (200, "json", openai_body(GOOD))])
        self.assertEqual((rc, len(srv.requests)), (0, 2))
        att = json.loads((out / "api_attempts.json").read_text())
        self.assertEqual([a["outcome"] for a in att], ["error", "response"])

    def test_config_error_not_frozen_and_not_counted(self):
        rc, out, _ = self.attempt("claude", "bad-model",
                                  [(404, "json", {"type": "error",
                                                  "error": {"type": "not_found_error",
                                                            "message": "model"}})])
        self.assertEqual(rc, 2)
        self.assertFalse((out / "frozen.json").exists())
        self.assertFalse((out / "api_attempts.json").exists())
        self.assertEqual(len(list(out.glob("api_attempts_config_error_*.json"))), 1)
        # After fixing the configuration the attempt runs normally (budget intact).
        rc, out, srv = self.attempt("claude", "claude-opus-5-5",
                                    [(200, "sse", anthropic_stream_body(GOOD, "end_turn"))])
        self.assertEqual((rc, len(srv.requests)), (0, 1))

    def test_received_but_unfrozen_response_is_not_called_again(self):
        out = self.runs / "gpt" / "CVE-TEST-1" / "rep1"
        out.mkdir(parents=True)
        (out / "api_attempts.json").write_text(json.dumps([{"call": 1, "outcome": "response"}]))
        rc, _, srv = self.attempt("gpt", "gpt-6-luna", [])
        self.assertEqual((rc, len(srv.requests)), (6, 0))

    def test_repetitions_are_separate_and_tamper_detected(self):
        for rep in (1, 2):
            rc, _, _ = self.attempt("claude", "claude-opus-5-5",
                                    [(200, "sse", anthropic_stream_body("nope", "end_turn"))], rep=rep)
            self.assertEqual(rc, 4)
        self.assertTrue((self.runs / "claude/CVE-TEST-1/rep2/frozen.json").exists())
        p = self.runs / "claude/CVE-TEST-1/rep2/llm_response.json"
        os.chmod(p, 0o644)
        p.write_text("{}")
        v = self.evaluate("claude", rep=2)
        self.assertEqual(v["status"], "incomplete")
        self.assertIn("hash mismatch", v["incomplete_reason"])


class TestCLIGuards(unittest.TestCase):
    def cli(self, *args, env_extra=None):
        env = {k: v for k, v in os.environ.items() if not k.endswith("_API_KEY")}
        env.update(env_extra or {})
        return subprocess.run([sys.executable, str(ROOT / "scripts/run_agent.py"), *args],
                              capture_output=True, text=True, env=env, cwd=ROOT)

    def test_missing_key_makes_no_call(self):
        tmp = tempfile.mkdtemp()
        cp = self.cli("--agent", "claude", "--model", "claude-opus-5-5", "--repetition", "1",
                      "--vuln-id", "CVE-2023-6681", "--runs", tmp)
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("ANTHROPIC_API_KEY is not set", cp.stderr)
        self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_argument_guards(self):
        k = {"ANTHROPIC_API_KEY": "dummy"}
        cp = self.cli("--agent", "claude", "--model", "x", "--vuln-id", "X", env_extra=k)
        self.assertIn("--repetition", cp.stderr)
        cp = self.cli("--agent", "claude", "--model", "x", "--repetition", "1",
                      "--temperature", "0", "--vuln-id", "X", env_extra=k)
        self.assertIn("temperature", cp.stderr)


if __name__ == "__main__":
    unittest.main()
