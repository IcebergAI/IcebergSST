#!/usr/bin/env bash
#
# Lint and render the chart, then assert the properties the rendered manifests
# must have.
#
#   make helm-verify
#
# `helm lint` alone says the templates are well-formed. It cannot tell you that
# the engine Deployment carries no database credentials, that only the api runs
# migrations, or that both roles run unprivileged — and those are the reasons the
# chart is shaped the way it is (ADR 0002). So this renders the chart and checks
# the output, the same way verify-images.sh checks built images rather than
# Dockerfile text (#61, #62).
#
# Uses a local helm if there is one, otherwise the official image via Docker.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART_DIR="$REPO_ROOT/deploy/helm/icebergsst"
VALUES="$REPO_ROOT/deploy/helm/example-values.yaml"
HELM_IMAGE="${HELM_IMAGE:-alpine/helm:latest}"

failures=0
pass() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; failures=$((failures + 1)); }
group() { printf '\n\033[1m%s\033[0m\n' "$1"; }

if command -v helm >/dev/null 2>&1; then
  helm_cmd() { helm "$@"; }
  CHART_PATH="$CHART_DIR"
  VALUES_PATH="$VALUES"
else
  helm_cmd() {
    docker run --rm -v "$REPO_ROOT/deploy/helm:/charts" "$HELM_IMAGE" "$@"
  }
  CHART_PATH="/charts/icebergsst"
  VALUES_PATH="/charts/example-values.yaml"
fi

group "helm lint"
if helm_cmd lint "$CHART_PATH" >/dev/null 2>&1; then
  pass "chart lints"
else
  fail "chart lints"
  helm_cmd lint "$CHART_PATH" 2>&1 | sed 's/^/       /'
fi

group "helm template"
rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT
if helm_cmd template icebergsst "$CHART_PATH" -f "$VALUES_PATH" >"$rendered" 2>/dev/null; then
  pass "chart renders with deploy/helm/example-values.yaml"
else
  fail "chart renders with deploy/helm/example-values.yaml"
  helm_cmd template icebergsst "$CHART_PATH" -f "$VALUES_PATH" 2>&1 | tail -20 | sed 's/^/       /'
  printf '\n\033[31m%d check(s) failed\033[0m\n' "$failures"
  exit 1
fi

# Rendering with secrets supplied out of band must work too — that is the path a
# production deployment actually takes, and a `required` in the wrong place would
# make it fail only for the people doing it properly.
if helm_cmd template icebergsst "$CHART_PATH" \
    --set secrets.existingApiSecret=iceberg-api \
    --set secrets.existingEngineSecret=iceberg-engine >/dev/null 2>&1; then
  pass "chart renders against externally-managed Secrets"
else
  fail "chart renders against externally-managed Secrets"
fi

group "Rendered manifests"
python3 - "$rendered" <<'PY' || failures=$((failures + 1))
import re
import sys

import yaml

docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
failures = 0


def ok(msg: str) -> None:
    print(f"  \033[32mok\033[0m   {msg}")


def bad(msg: str) -> None:
    global failures
    failures += 1
    print(f"  \033[31mFAIL\033[0m {msg}")


def component(doc: dict) -> str:
    return doc.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component", "")


by_kind: dict[str, list[dict]] = {}
for doc in docs:
    by_kind.setdefault(doc["kind"], []).append(doc)

# ── ADR 0002: the engine holds no database credentials ────────────────────────
# The point of a rendered check: a template could reference the api's Secret from
# the engine Deployment and still lint perfectly.
DB_TOKENS = re.compile(r"DATABASE|POSTGRES|MASTER_KEY|SESSION_SECRET|ALEMBIC", re.I)
engine_docs = [d for d in docs if component(d) == "engine"]
if not engine_docs:
    bad("no engine manifests rendered")
offenders = [
    f"{d['kind']}/{d['metadata']['name']}"
    for d in engine_docs
    if DB_TOKENS.search(yaml.safe_dump(d))
]
if offenders:
    bad(f"engine manifests mention database configuration: {offenders}")
else:
    ok("no engine manifest carries database or master-key configuration")

api_secret_names = {
    d["metadata"]["name"] for d in by_kind.get("Secret", []) if component(d) == "api"
}
engine_deployments = [d for d in by_kind.get("Deployment", []) if component(d) == "engine"]
for deployment in engine_deployments:
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    referenced = {
        source.get("secretRef", {}).get("name")
        for source in container.get("envFrom", [])
        if "secretRef" in source
    }
    if referenced & api_secret_names:
        bad(f"engine Deployment mounts the api Secret: {referenced & api_secret_names}")
    else:
        ok("engine Deployment references only its own Secret")

# ── Only the api runs migrations ──────────────────────────────────────────────
jobs = by_kind.get("Job", [])
if not jobs:
    bad("no migration Job rendered")
for job in jobs:
    annotations = job["metadata"].get("annotations", {})
    hook = annotations.get("helm.sh/hook", "")
    if "pre-upgrade" in hook and "pre-install" in hook:
        ok("migrations run as a pre-install/pre-upgrade hook")
    else:
        bad(f"migration Job is not a pre-install/pre-upgrade hook: {hook!r}")
    container = job["spec"]["template"]["spec"]["containers"][0]
    if container["command"] == ["python", "-m", "iceberg_api", "migrate"]:
        ok("migration Job uses the packaged migrate entry point")
    else:
        bad(f"unexpected migration command: {container['command']}")
    if "api" in container["image"]:
        ok("migration Job runs the api image")
    else:
        bad(f"migration Job does not run the api image: {container['image']}")

# ── The migration Job's configuration exists by the time it runs ──────────────
# Helm creates every hook resource before any ordinary manifest, so a hook Job
# whose `envFrom` names a plain ConfigMap or Secret has nothing to read on a
# fresh install and waits out its deadline in CreateContainerConfigError. The
# annotations are visible in the template; only comparing weights across the
# rendered manifests shows the ordering, which is why this check lives here.
def hook_weight(doc: dict) -> int | None:
    """The doc's weight as a pre-install hook, or None if it is not one."""
    annotations = doc.get("metadata", {}).get("annotations") or {}
    if "pre-install" not in annotations.get("helm.sh/hook", ""):
        return None
    return int(annotations.get("helm.sh/hook-weight", "0"))


by_name = {(d["kind"], d["metadata"]["name"]): d for d in docs}
REF_KINDS = (("configMapRef", "ConfigMap"), ("secretRef", "Secret"))

for job in jobs:
    job_weight = hook_weight(job)
    if job_weight is None:
        continue
    container = job["spec"]["template"]["spec"]["containers"][0]
    for source in container.get("envFrom", []):
        for key, kind in REF_KINDS:
            if key not in source:
                continue
            name = source[key]["name"]
            referenced = by_name.get((kind, name))
            if referenced is None:
                bad(f"migration Job reads {kind}/{name}, which the chart does not render")
                continue
            weight = hook_weight(referenced)
            if weight is None:
                bad(f"{kind}/{name} is not a hook; the migration Job runs before it exists")
            elif weight >= job_weight:
                bad(f"{kind}/{name} has hook-weight {weight}, not below the Job's {job_weight}")
            else:
                ok(f"{kind}/{name} is created before the migration Job")
            # The Deployments read these for the life of the release. A hook
            # deleted on success would be deleted out from under them.
            policy = referenced["metadata"]["annotations"].get("helm.sh/hook-delete-policy", "")
            if "hook-succeeded" in policy or "hook-failed" in policy:
                bad(f"{kind}/{name} is deleted with the hook, but the Deployments still read it")

# Nothing else may migrate. An engine that ran migrations would need a database
# URL, which is the invariant above stated a second way.
for deployment in by_kind.get("Deployment", []):
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    command = " ".join(container.get("command", []) + container.get("args", []))
    if "migrate" in command:
        bad(f"{deployment['metadata']['name']} migrates on start")

# ── Hardening ─────────────────────────────────────────────────────────────────
for kind in ("Deployment", "Job"):
    for doc in by_kind.get(kind, []):
        spec = doc["spec"]["template"]["spec"]
        name = doc["metadata"]["name"]
        pod_ctx = spec.get("securityContext", {})
        if not pod_ctx.get("runAsNonRoot"):
            bad(f"{name} does not set runAsNonRoot")
        container = spec["containers"][0]
        ctx = container.get("securityContext", {})
        if ctx.get("allowPrivilegeEscalation") is not False:
            bad(f"{name} allows privilege escalation")
        if ctx.get("readOnlyRootFilesystem") is not True:
            bad(f"{name} has a writable root filesystem")
        if ctx.get("capabilities", {}).get("drop") != ["ALL"]:
            bad(f"{name} does not drop all capabilities")
        if not container.get("resources", {}).get("requests"):
            bad(f"{name} declares no resource requests")
ok("every workload runs non-root, unprivileged, read-only, with requests set")

# ── Scaling ───────────────────────────────────────────────────────────────────
hpas = by_kind.get("HorizontalPodAutoscaler", [])
engine_hpa = [h for h in hpas if component(h) == "engine"]
if engine_hpa:
    ok("engine has an HPA")
else:
    bad("no engine HPA rendered")

for deployment in by_kind.get("Deployment", []):
    if component(deployment) == "engine" and "replicas" in deployment["spec"]:
        # A static replica count alongside an HPA means every `helm upgrade`
        # resets what the autoscaler decided.
        bad("engine Deployment pins replicas while its HPA is enabled")

services = {component(s) for s in by_kind.get("Service", [])}
if "engine" in services:
    bad("engine has a Service; nothing should be able to call an engine")
else:
    ok("only the api is reachable; engines are consumers")

sys.exit(1 if failures else 0)
PY

group "Result"
if (( failures )); then
  printf '\033[31m%d check(s) failed\033[0m\n' "$failures"
  exit 1
fi
printf '\033[32mall checks passed\033[0m\n'
