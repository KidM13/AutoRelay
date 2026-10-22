import socket
import ssl
import subprocess
import sys
import types
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import MagicMock, patch
from uuid import UUID

from relay import (
    InvalidSessionTransitionError,
    RelayAssessmentConfig,
    RelayAssessmentConfigurationError,
    RelayConfig,
    RelayConfigurationError,
    RelayLifecycleError,
    RelayServer,
    RelayTimeoutError,
    SessionManager,
    SessionNotFoundError,
    SessionState,
    ServerState,
    assess_targets,
)


def finding(status="PASS"):
    return {
        "check_id": "test.simulation",
        "title": "Simulation check",
        "status": status,
        "severity": "INFO",
        "details": "A simulated lifecycle result.",
        "evidence": {"mode": "simulation"},
        "remediation": "None.",
    }


def assessment_finding(target="10.20.30.40", check_id="relay.test", port=None):
    evidence = {"mode": "active_assessment", "target": target}
    if port is not None:
        evidence["port"] = port
    return {
        "check_id": check_id,
        "title": "Assessment check",
        "status": "UNKNOWN",
        "severity": "INFO",
        "details": "Test assessment observation.",
        "evidence": evidence,
        "remediation": "Test remediation.",
    }


class RelaySessionTests(unittest.TestCase):
    def test_session_ids_timestamps_transitions_and_results(self):
        manager = SessionManager()
        first = manager.create_session(["lab-host"])
        second = manager.create_session(["lab-host"])

        self.assertNotEqual(first.session_id, second.session_id)
        self.assertTrue(first.created_at.endswith("+00:00"))
        self.assertIsNone(first.started_at)
        first.start()
        self.assertEqual(first.state, SessionState.RUNNING)
        first.complete([finding()])

        self.assertEqual(first.state, SessionState.COMPLETED)
        self.assertIsNotNone(first.started_at)
        self.assertIsNotNone(first.completed_at)
        self.assertEqual(first.results, [finding()])

        returned_results = first.results
        returned_results[0]["evidence"]["mode"] = "changed"
        self.assertEqual(first.results[0]["evidence"]["mode"], "simulation")

    def test_invalid_transitions_and_findings_fail_explicitly(self):
        session = SessionManager().create_session(["lab-host"])
        with self.assertRaises(InvalidSessionTransitionError):
            session.complete([finding()])

        session.start()
        with self.assertRaises(ValueError):
            session.complete([{"status": "PASS"}])
        self.assertEqual(session.state, SessionState.RUNNING)

        session.fail(RuntimeError("message is not retained"))
        self.assertEqual(session.state, SessionState.FAILED)
        self.assertEqual(session.error_type, "RuntimeError")

    def test_cleanup_removes_session_and_preserves_issued_id(self):
        manager = SessionManager()
        with patch(
            "relay.session.uuid4",
            side_effect=[UUID(int=1), UUID(int=1), UUID(int=2)],
        ):
            session = manager.create_session(["lab-host"])
            self.assertTrue(manager.cleanup_session(session.session_id))
            replacement = manager.create_session(["lab-host"])

        self.assertEqual(session.state, SessionState.CLEANED)
        self.assertIsNotNone(session.cleaned_at)
        self.assertFalse(manager.cleanup_session(session.session_id))
        self.assertNotEqual(session.session_id, replacement.session_id)
        with self.assertRaises(SessionNotFoundError):
            manager.get_session(session.session_id)

    def test_targets_must_be_explicit_and_unique(self):
        manager = SessionManager()
        for invalid in ("lab-host", [], ["", "lab-host"], ["lab-host", "lab-host"]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                manager.create_session(invalid)


class RelayConfigurationTests(unittest.TestCase):
    def test_valid_config_preserves_only_explicit_targets(self):
        config = RelayConfig(["host-a", "host-b"])
        self.assertEqual(config.relay_targets, ("host-a", "host-b"))
        config.validate()

    def test_invalid_targets_and_timeouts_are_rejected(self):
        for targets in ([], ["host with space"], ["host-a", "host-a"]):
            with self.subTest(targets=targets), self.assertRaises(RelayConfigurationError):
                RelayConfig(targets)
        for timeout in (0, -1, float("inf"), float("nan"), True):
            with self.subTest(timeout=timeout), self.assertRaises(RelayConfigurationError):
                RelayConfig(["host-a"], startup_timeout=timeout)


class RelayAssessmentTests(unittest.TestCase):
    def test_assessment_checks_only_explicit_targets_and_fixed_service_ports(self):
        connection = MagicMock()
        with patch(
            "relay.assessment.socket.create_connection",
            return_value=connection,
        ) as connect, patch(
            "relay.assessment._check_smb_signing",
            side_effect=lambda target, timeout: assessment_finding(
                target, "relay.smb.signing", 445
            ),
        ), patch(
            "relay.assessment._check_ldaps_tls",
            side_effect=lambda target, timeout, ca_file: assessment_finding(
                target, "relay.ldaps.tls", 636
            ),
        ):
            findings = assess_targets(
                RelayAssessmentConfig(
                    ["10.20.30.40"],
                    timeout=0.25,
                    authorized_lab=True,
                )
            )

        reachability = findings[:3]
        self.assertEqual(
            [finding["status"] for finding in reachability],
            ["FAIL", "FAIL", "FAIL"],
        )
        self.assertEqual(
            [finding["evidence"]["port"] for finding in reachability],
            [445, 389, 636],
        )
        self.assertTrue(
            all(finding["evidence"]["mode"] == "active_assessment" for finding in findings)
        )
        self.assertTrue(
            all(
                "does not establish relay susceptibility" in finding["details"]
                for finding in reachability
            )
        )
        self.assertTrue(
            all(
                set(finding)
                == {
                    "check_id",
                    "title",
                    "status",
                    "severity",
                    "details",
                    "evidence",
                    "remediation",
                }
                for finding in findings
            )
        )
        self.assertEqual(connect.call_count, 3)
        self.assertEqual(
            connect.call_args_list[0].args,
            (("10.20.30.40", 445),),
        )
        self.assertEqual(connect.call_args_list[0].kwargs, {"timeout": 0.25})
        self.assertEqual(connection.__exit__.call_count, 3)

    def test_refused_connections_timeouts_and_other_errors_are_distinguished(self):
        with patch(
            "relay.assessment.socket.create_connection",
            side_effect=[
                ConnectionRefusedError("refused"),
                socket.timeout("timed out"),
                OSError(113, "no route to host"),
            ],
        ), patch(
            "relay.assessment._check_smb_signing",
            side_effect=lambda target, timeout: assessment_finding(target),
        ), patch(
            "relay.assessment._check_ldaps_tls",
            side_effect=lambda target, timeout, ca_file: assessment_finding(target),
        ):
            findings = assess_targets(
                RelayAssessmentConfig(["127.0.0.1"], authorized_lab=True)
            )

        self.assertEqual(
            [finding["status"] for finding in findings[:3]],
            ["PASS", "UNKNOWN", "ERROR"],
        )
        self.assertEqual(
            [finding["evidence"]["observation"] for finding in findings[:3]],
            ["connection_refused", "timeout", "connection_error"],
        )
        self.assertIn("no route to host", findings[2]["details"])
        self.assertEqual(
            [finding["status"] for finding in findings[3:]],
            ["UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN"],
        )

    def test_smb_signing_required_optional_disabled_and_inconclusive(self):
        cases = (
            ((3, 1, 2), "PASS", True, True),
            ((1, 1, 2), "FAIL", True, False),
            ((0, 1, 2), "FAIL", False, False),
            ((None, 1, 2), "UNKNOWN", None, None),
            ((0x80, 1, 2), "UNKNOWN", None, None),
        )
        for response, expected_status, enabled, required in cases:
            with self.subTest(response=response), patch(
                "relay.assessment._query_smb_signing",
                return_value=response,
            ):
                result = __import__(
                    "relay.assessment", fromlist=["_check_smb_signing"]
                )._check_smb_signing("10.20.30.40", 0.5)

            self.assertEqual(result["status"], expected_status)
            self.assertEqual(
                set(result),
                {
                    "check_id",
                    "title",
                    "status",
                    "severity",
                    "details",
                    "evidence",
                    "remediation",
                },
            )
            self.assertEqual(result["evidence"].get("signing_enabled"), enabled)
            self.assertEqual(result["evidence"].get("signing_required"), required)
            if expected_status == "FAIL":
                self.assertTrue(result["remediation"])
            if response[0] is None or response[0] == 0x80:
                self.assertEqual(
                    result["evidence"]["observation"],
                    "inconclusive_protocol_response",
                )

    def test_smb_connection_timeout_and_protocol_errors_are_not_security_results(self):
        from relay.assessment import _SMBProtocolAssessmentError, _check_smb_signing

        cases = (
            (TimeoutError("timed out"), "UNKNOWN", "timeout"),
            (ConnectionRefusedError("refused"), "ERROR", "connection_error"),
            (_SMBProtocolAssessmentError("unsupported dialect"), "ERROR", "protocol_error"),
            (ImportError("missing smbprotocol"), "ERROR", "dependency_error"),
            (RuntimeError("unexpected transport failure"), "ERROR", "assessment_error"),
        )
        for error, expected_status, observation in cases:
            with self.subTest(error=type(error).__name__), patch(
                "relay.assessment._query_smb_signing",
                side_effect=error,
            ):
                result = _check_smb_signing("10.20.30.40", 0.5)
            self.assertEqual(result["status"], expected_status)
            self.assertEqual(result["evidence"]["observation"], observation)
            if isinstance(error, _SMBProtocolAssessmentError):
                self.assertIn("unsupported dialect", result["details"])
            elif isinstance(error, ImportError):
                self.assertIn("SMB protocol dependency is unavailable", result["details"])
            else:
                self.assertIn(type(error).__name__, result["details"])

    def test_smb_negotiate_connection_is_closed_and_timeout_is_bounded(self):
        from relay.assessment import _query_smb_signing

        instances = []

        class FakeConnection:
            def __init__(self, guid, server_name, port, require_signing):
                self.server_security_mode = 3
                self.transport = object()
                self.disconnect_calls = []
                instances.append(self)

            def connect(self, timeout):
                self.connect_timeout = timeout

            def disconnect(self, close, timeout):
                self.disconnect_calls.append((close, timeout))

        connection_module = types.ModuleType("smbprotocol.connection")
        connection_module.Connection = FakeConnection
        connection_module.SecurityMode = types.SimpleNamespace(
            SMB2_NEGOTIATE_SIGNING_ENABLED=1,
            SMB2_NEGOTIATE_SIGNING_REQUIRED=2,
        )
        exceptions_module = types.ModuleType("smbprotocol.exceptions")
        exceptions_module.SMBException = type("SMBException", (Exception,), {})
        package_module = types.ModuleType("smbprotocol")
        package_module.__path__ = []

        with patch.dict(
            sys.modules,
            {
                "smbprotocol": package_module,
                "smbprotocol.connection": connection_module,
                "smbprotocol.exceptions": exceptions_module,
            },
        ):
            response = _query_smb_signing("10.20.30.40", 0.75)

        self.assertEqual(response, (3, 1, 2))
        self.assertEqual(instances[0].connect_timeout, 0.75)
        self.assertEqual(instances[0].disconnect_calls, [(False, 0.75)])

    def test_smb_connection_is_closed_after_negotiation_failure(self):
        from relay.assessment import _query_smb_signing

        instances = []

        class FakeConnection:
            def __init__(self, guid, server_name, port, require_signing):
                self.transport = object()
                self.disconnect_calls = []
                instances.append(self)

            def connect(self, timeout):
                raise ConnectionRefusedError("refused")

            def disconnect(self, close, timeout):
                self.disconnect_calls.append((close, timeout))

        connection_module = types.ModuleType("smbprotocol.connection")
        connection_module.Connection = FakeConnection
        connection_module.SecurityMode = types.SimpleNamespace(
            SMB2_NEGOTIATE_SIGNING_ENABLED=1,
            SMB2_NEGOTIATE_SIGNING_REQUIRED=2,
        )
        exceptions_module = types.ModuleType("smbprotocol.exceptions")
        exceptions_module.SMBException = type("SMBException", (Exception,), {})
        package_module = types.ModuleType("smbprotocol")
        package_module.__path__ = []

        with patch.dict(
            sys.modules,
            {
                "smbprotocol": package_module,
                "smbprotocol.connection": connection_module,
                "smbprotocol.exceptions": exceptions_module,
            },
        ), self.assertRaises(ConnectionRefusedError):
            _query_smb_signing("10.20.30.40", 0.5)

        self.assertEqual(instances[0].disconnect_calls, [(False, 0.5)])

    def test_ldap_signing_and_channel_binding_require_local_evidence(self):
        from relay.assessment import _unknown_ldap_setting

        signing = _unknown_ldap_setting("10.20.30.40", "signing")
        channel_binding = _unknown_ldap_setting("10.20.30.40", "channel_binding")

        self.assertEqual(signing["status"], "UNKNOWN")
        self.assertEqual(signing["evidence"]["remote_setting_query"], "not_supported")
        self.assertIn("LDAPServerIntegrity", signing["evidence"]["required_evidence"])
        self.assertIn("administrator evidence", signing["remediation"])
        self.assertEqual(channel_binding["status"], "UNKNOWN")
        self.assertIn(
            "LdapEnforceChannelBinding",
            channel_binding["evidence"]["required_evidence"],
        )
        self.assertIn("local server policy", channel_binding["details"])

    def test_ldaps_valid_certificate_uses_explicit_verification_and_ca_file(self):
        from relay.assessment import _check_ldaps_tls

        connection = MagicMock()
        tls_socket = MagicMock()
        tls_socket.version.return_value = "TLSv1.3"
        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = tls_socket
        with patch(
            "relay.assessment.socket.create_connection",
            return_value=connection,
        ) as connect, patch(
            "relay.assessment.ssl.create_default_context",
            return_value=context,
        ):
            result = _check_ldaps_tls(
                "10.20.30.40", 0.5, "C:\\lab\\root-ca.pem"
            )

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["evidence"]["certificate_validation"], "passed")
        self.assertEqual(result["evidence"]["tls_version"], "TLSv1.3")
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        context.load_verify_locations.assert_called_once_with(
            cafile="C:\\lab\\root-ca.pem"
        )
        context.wrap_socket.assert_called_once_with(
            connection.__enter__.return_value,
            server_hostname="10.20.30.40",
        )
        connect.assert_called_once_with(("10.20.30.40", 636), timeout=0.5)

    def test_ldaps_invalid_certificate_connection_failure_and_timeout_are_distinct(self):
        from relay.assessment import _check_ldaps_tls

        context = MagicMock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            1, "certificate verify failed"
        )
        with patch(
            "relay.assessment.ssl.create_default_context",
            return_value=context,
        ), patch(
            "relay.assessment.socket.create_connection",
            return_value=MagicMock(),
        ):
            invalid_cert = _check_ldaps_tls("10.20.30.40", 0.5, None)

        self.assertEqual(invalid_cert["status"], "FAIL")
        self.assertEqual(
            invalid_cert["evidence"]["observation"],
            "certificate_invalid",
        )
        self.assertIn("CA", invalid_cert["remediation"])

        for error, expected_status, observation in (
            (ConnectionRefusedError("refused"), "ERROR", "connection_error"),
            (socket.timeout("timed out"), "UNKNOWN", "timeout"),
        ):
            with self.subTest(error=type(error).__name__), patch(
                "relay.assessment.ssl.create_default_context",
                return_value=MagicMock(),
            ), patch(
                "relay.assessment.socket.create_connection",
                side_effect=error,
            ):
                result = _check_ldaps_tls("10.20.30.40", 0.5, None)
            self.assertEqual(result["status"], expected_status)
            self.assertEqual(result["evidence"]["observation"], observation)

    def test_malformed_or_unsafe_assessment_configuration_is_rejected(self):
        for targets in (
            [],
            "10.20.30.40",
            [None],
            [[]],
            ["10.20.30.40", "10.20.30.40"],
            ["example.test"],
            ["https://10.20.30.40"],
            ["8.8.8.8"],
        ):
            with self.subTest(targets=targets), self.assertRaises(
                RelayAssessmentConfigurationError
            ):
                RelayAssessmentConfig(targets, authorized_lab=True)

        for timeout in (0, -1, 3.1, float("inf"), float("nan"), True, 10**1000):
            with self.subTest(timeout=timeout), self.assertRaises(
                RelayAssessmentConfigurationError
            ):
                RelayAssessmentConfig(
                    ["10.20.30.40"],
                    timeout=timeout,
                    authorized_lab=True,
                )

    def test_assessment_requires_valid_config_and_caps_target_count(self):
        with self.assertRaises(TypeError):
            assess_targets(["10.20.30.40"])
        with self.assertRaises(RelayAssessmentConfigurationError):
            RelayAssessmentConfig(["10.20.30.40"])
        with self.assertRaises(RelayAssessmentConfigurationError):
            RelayAssessmentConfig(
                [f"10.0.0.{index}" for index in range(1, 18)],
                authorized_lab=True,
            )


class RelayServerTests(unittest.TestCase):
    def test_start_status_simulation_and_graceful_cleanup(self):
        server = RelayServer(RelayConfig(["lab-host"]))
        with self.assertRaises(RelayLifecycleError):
            server.simulate_session()

        server.start()
        self.assertTrue(server.is_ready())
        self.assertEqual(server.status()["mode"], "simulation")
        session = server.simulate_session()
        self.assertEqual(session.state, SessionState.COMPLETED)
        self.assertEqual(session.results[0]["status"], "PASS")
        self.assertEqual(session.results[0]["evidence"]["mode"], "simulation")

        server.stop()
        self.assertEqual(server.state, ServerState.STOPPED)
        self.assertEqual(session.state, SessionState.CLEANED)
        self.assertFalse(server.is_ready())

    def test_invalid_configuration_does_not_start_service(self):
        server = RelayServer(RelayConfig(["host-a"]))
        with patch.object(RelayConfig, "validate", side_effect=RelayConfigurationError):
            with self.assertRaises(RelayConfigurationError):
                server.start()
        self.assertEqual(server.state, ServerState.STOPPED)

    def test_startup_timeout_is_reported_and_worker_cleaned_up(self):
        server = RelayServer(RelayConfig(["lab-host"], startup_timeout=0.02))
        with patch.object(server, "_serve"):
            with self.assertRaises(RelayTimeoutError):
                server.start()
        self.assertEqual(server.state, ServerState.FAILED)
        self.assertEqual(server.status()["active_session_count"], 0)

    def test_service_shutdown_cleans_up_all_sessions(self):
        server = RelayServer(RelayConfig(["lab-host"]))
        server.start()
        session = server.sessions.create_session(["lab-host"])
        server.stop()
        self.assertEqual(session.state, SessionState.CLEANED)
        self.assertEqual(len(server.sessions), 0)

    def test_shutdown_timeout_is_reported_and_sessions_are_cleaned(self):
        server = RelayServer(RelayConfig(["lab-host"], shutdown_timeout=0.02))
        release_worker = Event()

        def stalled_worker():
            with server._lock:
                server._state = ServerState.READY
                server._ready_event.set()
            release_worker.wait()

        with patch.object(server, "_serve", stalled_worker):
            server.start()
            session = server.sessions.create_session(["lab-host"])
            with self.assertRaises(RelayTimeoutError):
                server.stop()
            self.assertEqual(server.state, ServerState.FAILED)
            self.assertEqual(session.state, SessionState.CLEANED)
            release_worker.set()
            server._thread.join(1)
            self.assertFalse(server._thread.is_alive())

    def test_cli_help_remains_available(self):
        project_root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, "autorelay.py", "--help"],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("relay", result.stdout)

    def test_relay_cli_help_describes_both_modes(self):
        project_root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, "autorelay.py", "relay", "--help"],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("assessment", result.stdout)
        self.assertIn("--authorized-lab", result.stdout)
        self.assertIn("--tls-ca-file", result.stdout)


if __name__ == "__main__":
    unittest.main()
