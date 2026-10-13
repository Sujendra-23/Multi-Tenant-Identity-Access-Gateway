"""Regression checks for failure handling; real HTTP/replicas are checked in kind."""

import contextlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import rollout


class FakeRollout:
    def __init__(self, failure):
        self.failure = failure
        self.candidate = "gateway:candidate"
        self.current_image = "gateway:baseline"
        self.original_flags = {"proxy_enabled": True, "rollout_percent": 35, "tenants": {"special": False}}
        self.current_flags = self.original_flags.copy()
        self.deployments = []
        self.rollback_called = False

    def image(self):
        return self.current_image

    @contextlib.contextmanager
    def endpoints(self):
        yield ["http://replica"]

    def flags(self, _url):
        return {"flags": self.current_flags.copy()}

    def cohorts(self, _url):
        pass

    def smoke(self, _urls, flags):
        if self.failure == "baseline" or (self.failure == "smoke" and flags.get("rollout_percent") == 50):
            raise rollout.DeploymentError("smoke failed")

    def update(self, _url, flags):
        self.current_flags = flags.copy()
        if self.failure == "lost-put" and flags["rollout_percent"] == 0:
            raise rollout.DeploymentError("PUT response lost after write")

    def deploy(self, image):
        self.current_image = image
        self.deployments.append(image)
        if self.failure == "image" and image == self.candidate:
            raise rollout.DeploymentError("rollout status timed out")

    def rollback(self, image, flags):
        self.rollback_called = True
        if self.failure == "rollback":
            raise rollout.DeploymentError("baseline unhealthy")
        self.current_image, self.current_flags = image, flags.copy()


class FailureHandlingTests(unittest.TestCase):
    def run_deployment(self, failure):
        fake = FakeRollout(failure)
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            with patch.object(rollout, "Rollout", return_value=fake), \
                 patch.object(rollout.subprocess, "run", side_effect=rollout.DeploymentError("full smoke failed")), \
                 patch("sys.argv", ["rollout.py", "--report", str(report)]), \
                 contextlib.redirect_stdout(None):
                status = rollout.main()
            return fake, status, json.loads(report.read_text())

    def test_failures_restore_snapshot_and_keep_deployment_failed(self):
        for failure in ("smoke", "lost-put", "image", "full-smoke"):
            with self.subTest(failure=failure):
                fake, status, report = self.run_deployment(failure)
                self.assertEqual(status, 1)
                self.assertEqual(report["result"], "rolled_back")
                self.assertEqual(fake.current_image, "gateway:baseline")
                self.assertEqual(fake.current_flags, fake.original_flags)
                if failure == "lost-put":
                    self.assertEqual(fake.deployments, [])  # No promotion after an uncertain flag write.

    def test_unhealthy_baseline_never_mutates_deployment(self):
        fake, status, report = self.run_deployment("baseline")
        self.assertEqual(status, 1)
        self.assertEqual(report["result"], "failed")
        self.assertFalse(fake.rollback_called)
        self.assertEqual(fake.deployments, [])

    def test_rollback_failure_is_reported(self):
        _, status, report = self.run_deployment("rollback")
        self.assertEqual(status, 1)
        self.assertEqual(report["result"], "rollback_failed")
        self.assertEqual(report["rollback_error"], "baseline unhealthy")

    def test_unreachable_candidate_does_not_prevent_image_restore(self):
        instance = object.__new__(rollout.Rollout)
        calls = []

        @contextlib.contextmanager
        def endpoints():
            if not calls:
                raise rollout.DeploymentError("candidate API unreachable")
            yield ["http://baseline"]

        flags = {"proxy_enabled": False, "tenants": {"special": True}}
        with patch.object(instance, "endpoints", endpoints), \
             patch.object(instance, "deploy", side_effect=lambda image: calls.append(image)), \
             patch.object(instance, "update") as update, \
             patch.object(instance, "flags", return_value={"flags": flags}), \
             patch.object(instance, "smoke") as smoke, \
             patch.object(instance, "image", return_value="gateway:baseline"), \
             contextlib.redirect_stdout(None):
            instance.rollback("gateway:baseline", flags)
        self.assertEqual(calls, ["gateway:baseline"])
        update.assert_called_once_with("http://baseline", flags)
        smoke.assert_called_once_with(["http://baseline"], flags)


if __name__ == "__main__":
    unittest.main()
