# Runbook: production-oriented installation

This runbook describes the supported shape of an IcebergSST deployment. It is a procedure, not
evidence that a particular cluster has been rehearsed. Record the commands, image digests, chart
values, and verification results for each environment.

## Prerequisites

- Kubernetes with a policy-enforcing NetworkPolicy implementation and Helm.
- Operator-managed PostgreSQL and Redis with backups, TLS, monitoring, and recovery procedures.
- An OIDC application with an exact HTTPS callback and PKCE enabled.
- An external secret mechanism (for example, a sealed-secret or Vault injector).
- A private registry or another source of immutable, reviewed API and engine image digests.

The chart does not provision PostgreSQL or Redis. Do not put a master key, database URL, OIDC
secret, or broker credential in a Helm values file committed to source or in a release manifest.

## Install

1. Review `deploy/helm/example-values.yaml` and create an environment-specific values file that
   references pre-created API and engine Secrets. Set the public HTTPS host, OIDC issuer/client,
   trusted proxy hops, resource requests, and immutable image digests.
2. Verify the rendered chart before applying it:

   ```console
   make helm-verify
   helm template icebergsst deploy/helm/icebergsst -f production-values.yaml > /tmp/icebergsst.yaml
   kubectl apply --dry-run=server -f /tmp/icebergsst.yaml
   ```

3. Apply the chart and wait for the migration hook and API readiness:

   ```console
   helm upgrade --install icebergsst deploy/helm/icebergsst \
     --namespace iceberg --create-namespace -f production-values.yaml --wait
   kubectl -n iceberg get pods,job
   ```

4. From the API pod, mint an engine token through the documented command, deliver the token only
   to the engine Secret, and restart the engine deployment. Confirm the engine has no database URL
   or master key in its rendered environment.
5. Register the first operator, verify viewer-by-default onboarding, then deliberately assign
   analyst/admin roles. Confirm CSRF, OIDC issuer, callback, and secure-cookie behavior over HTTPS.
6. Run a synthetic canary scan against a dedicated source. Confirm the finding is masked, the
   audit trail is present, and no source credential or canary value appears in API, engine, or
   notification logs.

## Go-live checks

Do not call the deployment supported until the operator has recorded TLS for API, PostgreSQL, and
Redis; default-deny egress; secret-controller rotation; a backup/restore drill from
[`backup-restore.md`](backup-restore.md); and a scan with an engine restart and lease recovery.
The controlled-pilot runbook remains the safer first step for a new source.
