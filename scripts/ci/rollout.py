#!/usr/bin/env python3
"""Exercise tenant-percentage rollout and restore image + flags on failure.

Standard library only. Operates exclusively on an explicit kind context.
Percentages gate proxy access by tenant; they do not route to different images.
"""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.error
import urllib.request
import uuid


class DeploymentError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise DeploymentError(message)


def bucket(tenant_id):
    # Matches internal/featureflags/flags.go: SHA256(id + NUL + flag), uint64 BE.
    digest = hashlib.sha256((tenant_id + "\0proxy_enabled").encode()).digest()
    return int.from_bytes(digest[:8], "big") % 100


def enabled(tenant, flags):
    overrides = flags.get("tenants") or {}
    if tenant["slug"] in overrides:
        return overrides[tenant["slug"]]
    percent = flags.get("rollout_percent")
    return flags["proxy_enabled"] and tenant["bucket"] < (100 if percent is None else percent)


class Rollout:
    def __init__(self):
        self.context = "kind-" + os.environ["KIND_CLUSTER"]
        self.key = os.environ["BOOTSTRAP_KEY"]
        self.candidate = os.environ["CANDIDATE_IMAGE"]
        self.artifacts = Path(os.environ["CI_ARTIFACTS"])
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.base_port = int(os.environ.get("CI_BASE_PORT", "18080"))
        self.tenants = []
        self.password = "ci-smoke-" + uuid.uuid4().hex

    def kubectl(self, *args):
        return subprocess.check_output(
            ["kubectl", "--context", self.context, "-n", "identity-gateway", *args],
            text=True, timeout=200,
        ).strip()

    def image(self):
        deployment = json.loads(self.kubectl("get", "deployment/gateway", "-o", "json"))
        containers = deployment["spec"]["template"]["spec"]["containers"]
        return next(c["image"] for c in containers if c["name"] == "gateway")

    def deploy(self, image):
        print(f"Deploying {image}", flush=True)
        self.kubectl("set", "image", "deployment/gateway", "gateway=" + image)
        print(self.kubectl("rollout", "status", "deployment/gateway", "--timeout=180s"), flush=True)
        require(self.image() == image, "Deployment did not retain the requested image")

    def request(self, url, path, *, method="GET", body=None, admin=False, tenant=None, token=None, revision=None):
        headers = {"User-Agent": "gateway-safe-deployment-ci"}
        if admin:
            headers["X-Bootstrap-Key"] = self.key
        if tenant:
            headers["X-Tenant"] = tenant["slug"]
        if token:
            headers["Authorization"] = "Bearer " + token
        if revision:
            headers["If-Match"] = '"' + revision + '"'
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url + path, data=data, headers=headers, method=method)
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            return response.code, json.loads(raw) if raw else {}

    def flags(self, url):
        status, doc = self.request(url, "/v1/admin/feature-flags", admin=True)
        require(status == 200, f"Reading shared flags returned HTTP {status}")
        return doc

    def update(self, url, flags):
        doc = self.flags(url)
        status, updated = self.request(
            url, "/v1/admin/feature-flags", method="PUT", admin=True,
            body=flags, revision=doc["revision"],
        )
        # Never blindly retry a PUT: a lost response or 412 must stop promotion.
        require(status == 200, f"Updating shared flags returned HTTP {status}")
        return updated

    @contextlib.contextmanager
    def endpoints(self):
        pods = json.loads(self.kubectl("get", "pods", "-l", "app=gateway", "-o", "json"))["items"]
        pods = [p for p in pods if not p["metadata"].get("deletionTimestamp") and
                any(c["type"] == "Ready" and c["status"] == "True" for c in p["status"].get("conditions", []))]
        deployment = json.loads(self.kubectl("get", "deployment/gateway", "-o", "json"))
        require(len(pods) == deployment["spec"]["replicas"], "Not every gateway replica is ready")
        processes, logs, urls = [], [], []
        try:
            for index, pod in enumerate(pods):
                port = self.base_port + index
                log = open(self.artifacts / f"port-forward-{uuid.uuid4().hex}.log", "w")
                logs.append(log)
                process = subprocess.Popen(
                    ["kubectl", "--context", self.context, "-n", "identity-gateway",
                     "port-forward", "pod/" + pod["metadata"]["name"], f"{port}:8080", "--address=127.0.0.1"],
                    stdout=log, stderr=subprocess.STDOUT,
                )
                processes.append(process)
                url = f"http://127.0.0.1:{port}"
                for _ in range(30):
                    require(process.poll() is None, "kubectl port-forward exited unexpectedly")
                    try:
                        status, _ = self.request(url, "/readyz")
                        if status == 200:
                            break
                    except (urllib.error.URLError, TimeoutError, ConnectionError):
                        pass
                    time.sleep(0.5)
                else:
                    raise DeploymentError("Replica readiness timed out")
                urls.append(url)
            yield urls
        finally:
            for process in processes:
                process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for log in logs:
                log.close()

    def cohorts(self, url):
        # Real tenant UUIDs are generated by the API. Select both sides of the
        # percentage boundary instead of assuming a random tenant is enabled.
        low, high = None, None
        for _ in range(256):
            slug = "ci-" + uuid.uuid4().hex
            email = "owner@" + slug + ".test"
            status, doc = self.request(url, "/v1/admin/tenants", method="POST", admin=True, body={
                "slug": slug, "name": "CI rollout", "admin": {"email": email, "password": self.password},
            })
            require(status == 201, f"Provisioning a rollout tenant returned HTTP {status}")
            tenant = doc["tenant"]
            tenant.update(bucket=bucket(tenant["id"]), email=email)
            if tenant["bucket"] < 10 and low is None:
                low = tenant
            if tenant["bucket"] >= 50 and high is None:
                high = tenant
            if low and high:
                self.tenants = [low, high]
                print("Verified tenant buckets: " + ", ".join(str(t["bucket"]) for t in self.tenants), flush=True)
                return
        raise DeploymentError("Could not select both rollout cohorts within 256 tenants")

    def login(self, url, tenant):
        status, doc = self.request(url, "/v1/auth/login", method="POST", tenant=tenant,
                                   body={"email": tenant["email"], "password": self.password})
        require(status == 200, f"Login returned HTTP {status}")
        status, doc = self.request(url, "/v1/auth/step-up", method="POST", tenant=tenant,
                                   token=doc["access_token"], body={"password": self.password})
        require(status == 200, f"Step-up returned HTTP {status}")
        return doc["access_token"]

    def smoke(self, urls, flags):
        for tenant in self.tenants:
            token = self.login(urls[0], tenant)
            for url in urls:
                status, _ = self.request(url, "/v1/auth/me", tenant=tenant, token=token)
                require(status == 200, f"Session verification returned HTTP {status}")
                for _ in range(20):
                    status, doc = self.request(url, "/v1/proxy/demo/hello", tenant=tenant, token=token)
                    if enabled(tenant, flags):
                        matches = status == 200 and doc.get("token_independently_verified") is True
                        matches = matches and doc.get("received_headers", {}).get("X-Gateway-Tenant-Id") == tenant["id"]
                    else:
                        matches = status == 503 and doc.get("error") == "feature_disabled"
                    if matches:
                        break
                    time.sleep(0.5)  # Redis pub/sub + reconciliation are asynchronous.
                else:
                    raise DeploymentError(f"Proxy smoke failed on {url}, bucket {tenant['bucket']}, HTTP {status}")
        print(f"Smoke passed on all {len(urls)} replicas at {flags.get('rollout_percent', 100)}%", flush=True)

    def rollback(self, image, flags):
        # Best effort to close the gate before replacing a broken candidate.
        # An unreachable API must never prevent restoring the baseline image.
        try:
            with self.endpoints() as urls:
                self.update(urls[0], {"proxy_enabled": False, "rollout_percent": 0, "tenants": {}})
        except Exception as error:
            print(f"Could not close the flag gate before image rollback: {error}", flush=True)
        self.deploy(image)
        with self.endpoints() as urls:
            self.update(urls[0], flags)
            require(self.flags(urls[0])["flags"] == flags, "Rollback did not restore the full flag snapshot")
            self.smoke(urls, flags)
        require(self.image() == image, "Rollback did not restore the baseline image")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inject-smoke-failure", action="store_true")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    rollout = Rollout()
    result = {"result": "failed", "injected_failure": False, "failed_stage": None}
    changed = False
    stage = "baseline"

    def interrupted(signum, _frame):
        raise DeploymentError(f"Interrupted by signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        old_image = rollout.image()
        result.update(baseline_image=old_image, candidate_image=rollout.candidate)
        with rollout.endpoints() as urls:
            old_flags = rollout.flags(urls[0])["flags"]
            # The zero-value seed omits tenants; accepted PUTs canonicalize it
            # to null. Retain equivalent semantics when verifying restoration.
            old_flags.setdefault("tenants", None)
            rollout.cohorts(urls[0])
            rollout.smoke(urls, old_flags)  # Verify the rollback target before any mutation.
            stage = 0
            changed = True  # A PUT's outcome may be uncertain even if it raises.
            rollout.update(urls[0], {"proxy_enabled": True, "rollout_percent": 0, "tenants": {}})
            rollout.smoke(urls, {"proxy_enabled": True, "rollout_percent": 0, "tenants": {}})
        stage = "image"
        rollout.deploy(rollout.candidate)
        with rollout.endpoints() as urls:
            for stage in (10, 50, 100):
                flags = {"proxy_enabled": True, "rollout_percent": stage, "tenants": {}}
                rollout.update(urls[0], flags)
                rollout.smoke(urls, flags)
                if args.inject_smoke_failure and stage == 10:
                    result["injected_failure"] = True
                    # A real HTTP smoke failure: an enabled cohort cannot reach
                    # an unconfigured upstream. Exercise the normal error path.
                    tenant = rollout.tenants[0]
                    token = rollout.login(urls[0], tenant)
                    status, _ = rollout.request(urls[0], "/v1/proxy/ci-missing/hello", tenant=tenant, token=token)
                    require(status == 200, f"Injected upstream smoke failure: HTTP {status}")
            stage = "full-smoke"
            subprocess.run(["bash", "scripts/smoke-test.sh"], check=True, timeout=120,
                           env={**os.environ, "BASE_URL": urls[0]})
        result["result"] = "promoted"
        return 0
    except Exception as error:
        result.update(error=str(error), failed_stage=stage)
        print(f"Deployment failed at {stage}: {error}", flush=True)
        if changed:
            try:
                rollout.rollback(old_image, old_flags)
                result["result"] = "rolled_back"
                print("Rollback verified: baseline image and complete flag snapshot restored", flush=True)
            except Exception as rollback_error:
                result.update(result="rollback_failed", rollback_error=str(rollback_error))
                print(f"ROLLBACK FAILED: {rollback_error}", flush=True)
        # A successful rollback never turns a failed deployment green.
        return 1
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
