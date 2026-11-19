# OpenShift lab — Java4Shell (CVE-2026-114938)

Detect and mitigate Java4Shell on an OpenShift cluster (validated on SNO `api.rhcos9-sno.lab.local`).

## Prerequisites

```bash
export KUBECONFIG=/path/to/kubeconfig
oc whoami   # must succeed
```

Node CPU gate (one-time):

```bash
oc debug node/$(oc get nodes -o jsonpath='{.items[0].metadata.name}') --quiet -- \
  chroot /host grep -o avx512vbmi /proc/cpuinfo | head -1
```

## Detect

```bash
./scripts/detect-ocp-java4shell.sh
# optional namespaces:
./scripts/detect-ocp-java4shell.sh datagrid-system rhsso rhbk
```

Classifies each Java process found in target namespaces:

| Result | Meaning |
| --- | --- |
| `EXPOSED` | JDK 17+/21/25, no mitigation flag, (caller should confirm `avx512vbmi`) |
| `MITIGATED` | Flag present / `UseBASE64Intrinsics=false` |
| `NOT_THIS_PATH` | JDK 8 or 11 |
| `UNKNOWN` | Could not determine |

## Mitigate (product knobs)

| Product | Where | What |
| --- | --- | --- |
| Data Grid | Infinispan CR | `spec.container.extraJvmOpts: "-XX:-UseBASE64Intrinsics"` |
| RH-SSO | `keycloaks.keycloak.org` | `spec.keycloakDeploymentSpec.experimental.env` → `JAVA_OPTS_APPEND` |
| RHBK | `keycloaks.k8s.keycloak.org` | `spec.env` or `unsupported.podTemplate` → `JAVA_OPTS_APPEND` |
| Keycloak Operator | Subscription | `spec.config.env`: `JDK_JAVA_OPTIONS` (+ `JAVA_TOOL_OPTIONS`) |
| EAP | Deployment / CR | `JAVA_OPTS_APPEND` |
| AMQ Broker | ActiveMQArtemis CR | `JAVA_ARGS_APPEND` / `JDK_JAVA_OPTIONS` |
| Quarkus / custom | Deployment | `JAVA_OPTS_APPEND` (prefer append over replacing `JAVA_OPTS`) |

Example patches: [`manifests/`](manifests/).

Always **append** to existing option strings; never wipe product defaults.

## Verify

```bash
oc exec -n <ns> <pod> -- bash -c \
  'jcmd 1 VM.flags -all 2>/dev/null | grep UseBASE64Intrinsics || \
   jcmd $(pgrep -f java | head -1) VM.flags -all | grep UseBASE64Intrinsics'
```

Expected:

```text
bool UseBASE64Intrinsics = false
```

## Lab manifests

| File | Purpose |
| --- | --- |
| [`manifests/datagrid-java4shell.yaml`](manifests/datagrid-java4shell.yaml) | Infinispan CR with mitigation |
| [`manifests/rhsso-java4shell.yaml`](manifests/rhsso-java4shell.yaml) | RH-SSO Keycloak CR + experimental env |
| [`manifests/rhbk-mitigation-patch.yaml`](manifests/rhbk-mitigation-patch.yaml) | RHBK / Operator Subscription patches |
| [`manifests/amq-broker-mitigation-example.yaml`](manifests/amq-broker-mitigation-example.yaml) | Example ActiveMQArtemis env |
| [`manifests/eap-mitigation-example.yaml`](manifests/eap-mitigation-example.yaml) | Example EAP `JAVA_OPTS_APPEND` |

Apply only after operators exist and storage/pull secrets are ready for your lab.

## Report

[`reports/openshift-sno-java4shell.json`](reports/openshift-sno-java4shell.json) — snapshot from the rhcos9-sno validation run.

## Related

- Product matrix & backlog order: [`../docs/openshift-middleware.md`](../docs/openshift-middleware.md)
- Host/Podman Ansible detection: [`../ansible/README.md`](../ansible/README.md)
