# OpenShift middleware — Java4Shell exposure plan

How to **detect** and **mitigate** [CVE-2026-114938](https://access.redhat.com/security/cve/CVE-2026-114938) for Red Hat middleware on OpenShift. 3scale is excluded (no Java in main components).

## Exposure conditions (all required)

1. OpenJDK **17.0.6+**, **21**, or **25**
2. Node CPU reports **`avx512vbmi`**
3. JVM **not** started with `-XX:-UseBASE64Intrinsics` (preferred) or `-XX:UseAVX=2`

## Detect → mitigate → verify

```text
1. Node gate     → oc debug node/… -- chroot /host grep -o avx512vbmi /proc/cpuinfo
2. Inventory     → operators/CSVs + pods with Java-ish images
3. Per JVM       → java -version / /proc cmdline + jcmd UseBASE64Intrinsics
4. Classify      → exposed | not this path (JDK 8/11) | mitigated
5. Mitigate      → product-specific APPEND env / CR field (never clobber existing opts)
6. Roll pods     → Operator/STS/Deployment restart
7. Verify        → jcmd … UseBASE64Intrinsics = false  (env alone ≠ fixed)
```

Scripted detect: [`../openshift/scripts/detect-ocp-java4shell.sh`](../openshift/scripts/detect-ocp-java4shell.sh).

## Product matrix

| Product | Java? | Priority | Detect focus | Mitigate on OpenShift |
| --- | --- | --- | --- | --- |
| **RHBK / Keycloak** | Yes | P0 | Server + Operator JVMs; pre-auth Base64 | Server: `JAVA_OPTS_APPEND`. Operator: `JDK_JAVA_OPTIONS` (+ optional `JAVA_TOOL_OPTIONS`) via **Subscription `spec.config.env`** so OLM keeps it. CR: `spec.env` or `spec.unsupported.podTemplate` |
| **Data Grid** | Yes | P0 | Infinispan pods (bundled JDK often 17/21/25) | Infinispan CR: `spec.container.extraJvmOpts: "-XX:-UseBASE64Intrinsics"` (maps to `JAVA_OPTIONS`). Do not set conflicting `JAVA_OPTIONS` env at the same time |
| **RH-SSO 7.6** | Yes | P1* | Image JDK major | Official `sso76-openshift-rhel8` is **OpenJDK 11** → not on vulnerable path. If customized to JDK 17+: `JAVA_OPTS_APPEND` via `keycloak.org` CR `spec.keycloakDeploymentSpec.experimental.env` |
| **EAP 7.4 / 8** | Yes | P1 | EAP pods / S2I | `JAVA_OPTS_APPEND` on Deployment / EAP CR / template |
| **AMQ Broker** | Yes | P1 | Artemis pods | ActiveMQArtemis CR `spec.env`: `JAVA_ARGS_APPEND` (append) or `JDK_JAVA_OPTIONS` (prepend) |
| **AMQ Streams** | Yes | P1 | Kafka, Entity Operator, Connect, MM2 | Component `jvmOptions` / `JAVA_OPTS` / `STRIMZI_JAVA_OPTS` (per operand) |
| **JBoss Web Server** | Yes | P2 | Tomcat + JDK | `CATALINA_OPTS` or `JAVA_OPTS` / `JAVA_OPTS_APPEND` |
| **Quarkus apps** | Yes | P2 | UBI OpenJDK runtime images | `JAVA_OPTS_APPEND` — **do not** replace `JAVA_OPTS` (image defaults) |
| **Apicurio Registry** | Yes | P2 | Registry Deployment | Same Quarkus / Deployment env pattern |
| **Cryostat** | Yes | P2 | Operator + instance | `JDK_JAVA_OPTIONS` / product env on Deployment / Subscription |
| **Fuse / Camel K** | Yes | P2 | Integration JVMs | `JAVA_OPTS_APPEND` / Quarkus-Spring Boot pattern |
| **Custom Java** | Maybe | P2 | Any app image | Inventory JDK; set `JAVA_OPTS_APPEND` or `JDK_JAVA_OPTIONS` on Deployment |
| **3scale** | No* | — | — | Main components not Java; risk is usually via integrated IdP (RHBK/RH-SSO) |
| **AMQ Interconnect** | No | — | — | C (`qdrouterd`) |

\*RH-SSO priority rises to P0 if the deployment actually runs OpenJDK 17+.

## Operator vs operand

| Layer | How Java starts | Knob |
| --- | --- | --- |
| Operand (server) | Product start script (`standalone.sh`, `kc.sh`, `server.sh`, …) | Product APPEND var (`JAVA_OPTS_APPEND`, `JAVA_ARGS_APPEND`, `extraJvmOpts`, …) |
| Operator pod | Often `java -jar …` directly | `JDK_JAVA_OPTIONS` / `JAVA_TOOL_OPTIONS` on Deployment; persist with Subscription `spec.config.env` |

Mitigating the Operator does **not** mitigate managed pods — apply both when both run JVMs.

## Suggested lab order (this SNO)

1. **Done:** Data Grid, RH-SSO, RHBK (+ Keycloak Operator) — see [`../openshift/reports/openshift-sno-java4shell.json`](../openshift/reports/openshift-sno-java4shell.json)
2. **Next:** custom `rhhi-demo/java-backend` (detect JDK → Deployment env)
3. **Then:** EAP **or** AMQ Broker sample (highest field relevance after IdP/cache)
4. **Optional:** AMQ Streams, Apicurio, Cryostat

## References

- [RHSB-2026-018](https://access.redhat.com/security/vulnerabilities/RHSB-2026-018)
- [Keycloak Java4Shell](https://www.keycloak.org/2026/11/java4shell-vulnerability-cve-2026-114938)
- [Quarkus Java4Shell](https://quarkus.io/blog/java4shell/)
- Data Grid Operator — [JVM options / `extraJvmOpts`](https://docs.redhat.com/en/documentation/red_hat_data_grid/8.6/html/data_grid_operator_guide/creating-services)
- AMQ Broker on OCP — [env / `JAVA_ARGS_APPEND`](https://docs.redhat.com/en/documentation/red_hat_amq_broker/7.13/html/deploying_amq_broker_on_openshift/proc-br-setting-environment-variables_broker-container_broker-ocp)
- EAP on OCP — `JAVA_OPTS_APPEND` in [image env reference](https://docs.redhat.com/en/documentation/red_hat_jboss_enterprise_application_platform/8.1/html/using_jboss_eap_on_openshift_container_platform/assembly_reference-information-for-openshift-container-platform_default)
