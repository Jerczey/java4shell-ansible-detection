# CVE-2026-114938 — Java4Shell

Lab and guidance for **detecting** and **mitigating** [CVE-2026-114938](https://access.redhat.com/security/cve/CVE-2026-114938) (“Java4Shell”) on RHEL hosts and Red Hat middleware on OpenShift.

Red Hat bulletin: [RHSB-2026-018](https://access.redhat.com/security/vulnerabilities/RHSB-2026-018).

## Vulnerability in one line

OpenJDK **17.0.6+ / 21 / 25** on **x86-64** CPUs with **`avx512vbmi`** can hit a memory-corruption path in the accelerated Base64 decoder. OpenJDK **8** and **11** do not include that code path.

Interim mitigation (preferred):

```text
-XX:-UseBASE64Intrinsics
```

Verify on the **live** JVM (env alone is not enough):

```bash
jcmd <pid> VM.flags -all | grep -F UseBASE64Intrinsics
# expect: bool UseBASE64Intrinsics = false
```

## Repository layout

| Path | Purpose |
| --- | --- |
| [`ansible/`](ansible/) | Host / Podman inventory + detection playbooks |
| [`openshift/`](openshift/) | OpenShift SNO lab: manifests, detect script, product mitigate map |
| [`docs/`](docs/) | Cached advisories (RHSB, CISA, Keycloak, CERT-EU, …) |
| [`docs/openshift-middleware.md`](docs/openshift-middleware.md) | Middleware exposure matrix + detect→mitigate plan |

## Quick start

### Ansible (RHEL / Podman)

```bash
cd ansible
ansible-playbook playbooks/detect-java4shell.yml
# local lab:
ansible-playbook -i inventory/hosts.local.yml playbooks/detect-java4shell.yml
```

See [`ansible/README.md`](ansible/README.md).

### OpenShift (SNO lab)

```bash
export KUBECONFIG=/path/to/kubeconfig   # e.g. rhcos9-sno out/auth/kubeconfig
cd openshift
./scripts/detect-ocp-java4shell.sh
```

Manifests and product-specific mitigate knobs: [`openshift/README.md`](openshift/README.md).

## Middleware on OpenShift (summary)

| Priority | Product | Java? | Typical mitigate env / CR field |
| --- | --- | --- | --- |
| P0 | RHBK / Keycloak | Yes (17/21/25) | `JAVA_OPTS_APPEND`; operator: `JDK_JAVA_OPTIONS` via Subscription |
| P0 | Data Grid | Yes (often 17/21/25) | `spec.container.extraJvmOpts` → `JAVA_OPTIONS` |
| P1 | EAP 7.4 / 8 | Yes | `JAVA_OPTS_APPEND` |
| P1 | AMQ Broker | Yes | `JAVA_ARGS_APPEND` / `JDK_JAVA_OPTIONS` on ActiveMQArtemis CR |
| P1 | AMQ Streams (Kafka) | Yes | `JAVA_OPTS` / `STRIMZI_JAVA_OPTS` / component env |
| P2 | JBoss Web Server | Yes | `CATALINA_OPTS` / `JAVA_OPTS(_APPEND)` |
| P2 | Quarkus / Apicurio / Cryostat / Fuse | Yes | `JAVA_OPTS_APPEND` or `JDK_JAVA_OPTIONS` |
| — | RH-SSO 7.6 on OpenJDK **11** | Image default | Not on vulnerable path; still inventory |
| — | 3scale | No (main comps) | Out of scope for this CVE’s Java path |
| — | AMQ Interconnect | No (C) | Out of scope |

Full matrix and lab order: [`docs/openshift-middleware.md`](docs/openshift-middleware.md).

## Lab status (rhcos9-sno)

Validated on `api.rhcos9-sno.lab.local` (node has `avx512vbmi`):

| Workload | JDK | Before | Mitigation | After |
| --- | --- | --- | --- | --- |
| Data Grid `java4shell-dg` | 25.0.4.1 | exposed | `extraJvmOpts` | `UseBASE64Intrinsics=false` |
| RH-SSO `java4shell-rhsso` | 11.0.33 | not this path | `JAVA_OPTS_APPEND` | flag applied |
| RHBK `keycloak-rhhi` | 21.0.12 | exposed | `JAVA_OPTS_APPEND` | `UseBASE64Intrinsics=false` |
| Keycloak Operator | — | exposed | Subscription `JDK_JAVA_OPTIONS` | `UseBASE64Intrinsics=false` |

Snapshot: [`openshift/reports/openshift-sno-java4shell.json`](openshift/reports/openshift-sno-java4shell.json).

## References

- [RHSB-2026-018](https://access.redhat.com/security/vulnerabilities/RHSB-2026-018)
- [Keycloak Java4Shell advisory](https://www.keycloak.org/2026/11/java4shell-vulnerability-cve-2026-114938)
- [Quarkus Java4Shell status](https://quarkus.io/blog/java4shell/)
- Local copies under [`docs/`](docs/)
