"""Offline security-boundary regression tests for the AI SOC agent.

No Azure credentials, model calls, or network access are required. Each test
stubs the query executor and checks that hostile arguments never reach it.
These tests do not establish that an LLM is immune to prompt injection.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tools  # noqa: E402  - import the app's local module


class QueryArgumentSecurityTests(unittest.TestCase):
    def test_injection_attempts_are_rejected_before_kql_execution(self):
        cases = [
            ("get_user_activity", {"user": "x' or 1==1 //"}),
            ("get_ip_activity", {"ip": "1.1.1.1' | union AppEvents //"}),
            ("get_auth_events", {"user": "'; SecurityAlert | take 100 //"}),
            ("get_related_requests", {"path": "/api/auth/refresh' | union SecurityAlert //"}),
            ("get_incident", {"incident_number": "1 | union SecurityAlert"}),
            ("get_related_alerts", {"entity": "'; SecurityAlert | take 100 //"}),
            ("get_azure_activity", {"caller": "x' or 1==1 //"}),
            ("get_azure_activity", {"ip": "1.1.1.1' | union AppEvents //"}),
            ("get_azure_activity", {"resource": "vm' | union SecurityAlert //"}),
            ("get_user_activity", {
                "user": "analyst@example.org",
                "around": "2026-11-18T11:00:00Z' | union SecurityAlert",
            }),
        ]
        for name, arguments in cases:
            with self.subTest(tool=name, arguments=arguments):
                with patch.object(tools, "_run", return_value=[]) as query:
                    result = json.loads(tools.dispatch(name, json.dumps(arguments)))
                    self.assertIn("error", result)
                    query.assert_not_called()

    def test_valid_user_builds_fixed_query_without_remote_access(self):
        with patch.object(tools, "_run", return_value=[]) as query:
            result = json.loads(tools.dispatch(
                "get_user_activity",
                json.dumps({"user": "analyst@example.org", "hours": 24}),
            ))
        self.assertEqual(result["row_count"], 0)
        statement = query.call_args.args[0]
        self.assertIn("EventEmail =~ 'analyst@example.org'", statement)
        self.assertIn("| take 50", statement)

    def test_unknown_model_parameters_cannot_become_kql(self):
        malicious = "| union SecurityAlert | take 100"
        with patch.object(tools, "_run", return_value=[]) as query:
            result = json.loads(tools.dispatch(
                "get_related_requests",
                json.dumps({"path": "/api/auth/refresh", "kql": malicious}),
            ))
        self.assertEqual(result["row_count"], 0)
        self.assertNotIn(malicious, query.call_args.args[0])

    def test_bounded_lookback_and_normalized_timestamp(self):
        with patch.object(tools, "_run", return_value=[]) as query:
            tools.dispatch("get_ip_activity", json.dumps({
                "ip": "192.0.2.10",
                "hours": 99999,
                "around": "2026-11-18T11:00:00+00:00",
            }))
        statement = query.call_args.args[0]
        self.assertIn("datetime(2026-11-11T11:00:00Z)", statement)
        self.assertIn("datetime(2026-11-18T17:00:00Z)", statement)

    def test_unknown_tool_and_malformed_json_never_query(self):
        with patch.object(tools, "_run", return_value=[]) as query:
            for name, args in [
                ("run_arbitrary_kql", "{}"),
                ("get_ip_activity", "{not-json"),
            ]:
                with self.subTest(name=name):
                    result = json.loads(tools.dispatch(name, args))
                    self.assertIn("error", result)
            query.assert_not_called()


if __name__ == "__main__":
    unittest.main()
