# CVE-2026-114938 (Java4Shell) — Ansible detection

Playbooks de inventario y detección para evaluar exposición a **CVE-2026-114938** (“Java4Shell”) en hosts RHEL / middleware (RH-SSO, RHBK, EAP, etc.).

La vulnerabilidad está en el decoder Base64 acelerado de OpenJDK (17.0.6+ / 21 / 25) en CPUs **x86-64** con **`avx512vbmi`**. OpenJDK 8 y 11 no incluyen el code path vulnerable. Referencia Red Hat: [RHSB-2026-018](https://access.redhat.com/security/vulnerabilities/RHSB-2026-018).

## Qué detecta

| # | Chequeo | Detalle |
|---|---|---|
| 1 | JVM en ejecución | Procesos Java vía `/proc` (+ fallback `ps`). No depende solo de `java -version` ni de RPM instalado. Opcionalmente escanea contenedores **Podman**. |
| 2 | Flag CPU | `grep -o avx512vbmi /proc/cpuinfo \| head -1` |
| 3 | Mitigaciones (opcional) | Busca en el cmdline: `-XX:-UseBASE64Intrinsics` (preferida) y `-XX:UseAVX=2` (solo x86-64) |

## Estructura

```
ansible/
├── ansible.cfg
├── inventory/
│   ├── hosts.yml           # 3 clusters × 4 nodos (rellenar)
│   ├── hosts.local.yml     # prueba en localhost
│   └── group_vars/all.yml
├── files/
│   ├── collect_java_processes.sh
│   └── collect_podman_java.sh
├── playbooks/
│   ├── detect-java4shell.yml
│   └── lab-podman-eap-rhsso.yml
└── reports/                # salida JSON/CSV (no versionada)
```

## Requisitos

- Ansible (probado con ansible-core 2.20+)
- Acceso SSH a los nodos (o `connection: local` para lab)
- Para el lab: Podman + login a `registry.redhat.io`

## Inventario

Editar `inventory/hosts.yml`:

- `ansible_user`
- `ansible_host` por nodo
- clave SSH (`ansible_ssh_private_key_file`) o contraseña

Layout de ejemplo: **3 clusters × 4 nodos** (`cluster1`, `cluster2`, `cluster3`) + grupo `lab_podman`.

## Uso

Desde este directorio:

```bash
# Detección en todos los hosts del inventario
ansible-playbook playbooks/detect-java4shell.yml

# Solo un cluster
ansible-playbook playbooks/detect-java4shell.yml -l cluster1

# Sin chequeo de mitigaciones / sin escaneo Podman
ansible-playbook playbooks/detect-java4shell.yml \
  -e check_mitigations=false \
  -e scan_podman_containers=false

# Prueba local
ansible-playbook -i inventory/hosts.local.yml playbooks/detect-java4shell.yml
```

Reportes en `reports/`:

- `<hostname>.json` — detalle por host
- `aggregate-java4shell.json` / `.csv` — resumen

## Lab Podman (EAP 8 + RH-SSO)

Útil para generar JVMs de prueba (EAP 8 / OpenJDK 17 y RH-SSO 7.6):

```bash
export RH_REGISTRY_USER='...'
export RH_REGISTRY_PASSWORD='...'
# o: podman login registry.redhat.io

ansible-playbook playbooks/lab-podman-eap-rhsso.yml -l lab_podman
ansible-playbook playbooks/lab-podman-eap-rhsso.yml -l lab_podman -e lab_action=status
ansible-playbook playbooks/lab-podman-eap-rhsso.yml -l lab_podman -e lab_action=stop
```

Luego volver a ejecutar `detect-java4shell.yml` (con `scan_podman_containers=true`) para ver Java dentro de los contenedores.

## Cómo interpretar

Un host es **candidato a exposición** si:

1. Hay una JVM OpenJDK **17+ / 21 / 25** en ejecución, **y**
2. La CPU reporta **`avx512vbmi`**, **y**
3. El cmdline **no** tiene `-XX:-UseBASE64Intrinsics` ni `-XX:UseAVX=2`

Mitigación temporal recomendada por Red Hat hasta aplicar OpenJDK parchado:

```text
-XX:-UseBASE64Intrinsics
```

En RHBK / Keycloak suele ir en `JAVA_OPTS_APPEND`. En el Operator usar `JDK_JAVA_OPTIONS`.

## Alcance producto (contexto)

| Producto | Notas |
|---|---|
| **RHBK** | Alta prioridad: OpenJDK 17/21/25; Base64 pre-auth (JWT/SAML/Basic). |
| **RH-SSO** | Solo si corre OpenJDK 17.0.6+; 8/11 no afectados por este code path. |
| **3scale** | Componentes principales no son Java; riesgo principalmente vía IdP integrado. |

Este repositorio **no aplica** el parche; solo inventaría y reporta indicadores.
