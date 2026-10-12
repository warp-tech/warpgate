{{/*
Expand the name of the chart.
*/}}
{{- define "warpgate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "warpgate.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "warpgate.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "warpgate.labels" -}}
helm.sh/chart: {{ include "warpgate.chart" . }}
{{ include "warpgate.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "warpgate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "warpgate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Checksum of inputs that produce /data/warpgate.yaml: the config ConfigMap and,
when variables are substituted into it, the resolved env Secret values.
Empty when nothing applies or lookup is unavailable (helm template / dry-run).
*/}}
{{- define "warpgate.configChecksum" -}}
{{- $configContent := "" -}}
{{- if or .Values.overrides_config (include "warpgate.renderConfig" .) -}}
  {{- $configContent = include (print $.Template.BasePath "/configmap.yaml") . -}}
{{- end -}}
{{- $envParts := list -}}
{{- if and (include "warpgate.configEnvVarReplace" .) .Values.setup.envFromSecret -}}
  {{- range $key, $val := .Values.setup.envFromSecret -}}
    {{- $ref := split "/" $val -}}
    {{- $secret := lookup "v1" "Secret" $.Release.Namespace $ref._0 -}}
    {{- if and $secret (hasKey ($secret.data | default dict) $ref._1) -}}
      {{- $envParts = append $envParts (printf "%s=%s" $key (index $secret.data $ref._1)) -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
{{- if or $configContent $envParts -}}
{{- printf "%s\n%s" $configContent ($envParts | sortAlpha | join "\n") | sha256sum -}}
{{- end -}}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "warpgate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "warpgate.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Bundled PostgreSQL resource name.
*/}}
{{- define "warpgate.postgresql.fullname" -}}
{{- printf "%s-postgresql" (include "warpgate.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Labels of the bundled PostgreSQL pod. The name label must differ from
"warpgate.selectorLabels" so that the Warpgate Service and Deployment don't
select the database pod.
*/}}
{{- define "warpgate.postgresql.selectorLabels" -}}
app.kubernetes.io/name: {{ include "warpgate.name" . }}-postgresql
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Secret reference holding the bundled database's password, as <secret>/<key>:
the operator's own when they supply one, otherwise the chart's generated Secret.
*/}}
{{- define "warpgate.postgresql.passwordSecret" -}}
{{- .Values.postgresql.passwordSecret | default (printf "%s/password" (include "warpgate.postgresql.fullname" .)) -}}
{{- end }}

{{/*
Database URL for setup and for the rendered config. The bundled database's
password stays out of the manifests as a literal $WARPGATE_DB_PASSWORD:
Kubernetes expands it in the setup arguments, and `internal-install-files`
substitutes it into the config.
*/}}
{{- define "warpgate.databaseUrl" -}}
{{- if .Values.setup.databaseUrl -}}
{{- .Values.setup.databaseUrl -}}
{{- else if .Values.postgresql.enabled -}}
{{- printf "postgres://warpgate:$WARPGATE_DB_PASSWORD@%s:5432/warpgate" (include "warpgate.postgresql.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Names of the environment variables `internal-install-files` substitutes into
the config file.
*/}}
{{- define "warpgate.configEnvVarReplace" -}}
{{- $vars := list }}
{{- with .Values.config_env_var_replace }}{{- $vars = append $vars . }}{{- end }}
{{- if and .Values.postgresql.enabled (not .Values.setup.databaseUrl) }}{{- $vars = append $vars "WARPGATE_DB_PASSWORD" }}{{- end }}
{{- join " " $vars }}
{{- end }}

{{/*
Environment of the setup containers: the configured secret references plus the
bundled database's password.
*/}}
{{- define "warpgate.setupEnv" -}}
{{- range $key, $val := .Values.setup.envFromSecret }}
- name: {{ $key }}
  valueFrom:
    secretKeyRef:
      name: {{ (split "/" $val)._0 }}
      key: {{ (split "/" $val)._1 }}
{{- end }}
{{- if and .Values.postgresql.enabled (not .Values.setup.databaseUrl) }}
{{- $ref := split "/" (include "warpgate.postgresql.passwordSecret" .) }}
- name: WARPGATE_DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ $ref._0 }}
      key: {{ $ref._1 }}
{{- end }}
{{- end }}

{{/*
`unattended-setup` arguments of the setup init container. `$VAR` / `${VAR}` in the database URL become Kubernetes' `$(VAR)`,
expanded from the container's environment.
*/}}
{{- define "warpgate.unattendedSetupArgs" -}}
- --data-path=/data
{{- with .Values.setup.http }}
- --http-port={{ . }}
{{- end }}
{{- with .Values.setup.ssh }}
- --ssh-port={{ . }}
{{- end }}
{{- with .Values.setup.mysql }}
- --mysql-port={{ . }}
{{- end }}
{{- with .Values.setup.pgsql }}
- --postgres-port={{ . }}
{{- end }}
{{- with .Values.setup.kubernetes }}
- --kubernetes-port={{ . }}
{{- end }}
{{- with include "warpgate.databaseUrl" . }}
- {{ printf "--database-url=%s" (regexReplaceAll `\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)` . "$$(${1}${2})") | quote }}
{{- end }}
{{- if .Values.setup.recordSessions }}
- --record-sessions
{{- end }}
{{- if .Values.setup.disableIpV6 }}
- --listen-address=0.0.0.0
{{- end }}
{{- end }}

{{/*
Image, security context and environment of the containers that run setup
steps.
*/}}
{{- define "warpgate.setupContainer" -}}
{{- with .Values.securityContext }}
securityContext:
  {{- toYaml . | nindent 2 }}
{{- end }}
image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
{{- with include "warpgate.setupEnv" . }}
env:
  {{- . | trim | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Projected volume sources laid out as the files must end up in /data, where
`internal-install-files` copies them on every pod start. Empty when there is nothing to
copy.
*/}}
{{- define "warpgate.seedSources" -}}
{{- with include "warpgate.tlsSecretName" . }}
- secret:
    name: {{ . }}
    items:
      - key: tls.crt
        path: tls.certificate.pem
      - key: tls.key
        path: tls.key.pem
{{- end }}
{{- with .Values.ssh_keys_secret }}
- secret:
    name: {{ . }}
    items:
      {{- range list "client-ed25519" "client-rsa" "host-ed25519" "host-rsa" }}
      - key: {{ . }}
        path: ssh-keys/{{ . }}
      {{- end }}
{{- end }}
{{- with include "warpgate.configMapName" . }}
- configMap:
    name: {{ . }}
    items:
      - key: warpgate.yaml
        path: warpgate.yaml
{{- end }}
{{- end }}

{{/*
Volume mounts of the deployment's init containers.
*/}}
{{- define "warpgate.initVolumeMounts" -}}
- name: data
  mountPath: /data
{{- if include "warpgate.seedSources" . }}
- name: seed
  mountPath: /seed
{{- end }}
{{- with .Values.volume_mounts }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Non-empty when the chart itself has to provide /data/warpgate.yaml and a
certificate: on an emptyDir they are gone with every pod, and regenerating
them means running setup from scratch against the shared database on every
start. Only for a shared database - a config pointing at a per-pod SQLite file
would be a working config for an empty database.
*/}}
{{- define "warpgate.renderConfig" -}}
{{- if and (include "warpgate.databaseUrl" .) (not .Values.overrides_config) (not .Values.data.pvc.enabled) -}}
true
{{- end -}}
{{- end }}

{{/*
ConfigMap holding the config copied to /data/warpgate.yaml, empty when the pods
get their config from elsewhere.
*/}}
{{- define "warpgate.configMapName" -}}
{{- if or .Values.overrides_config (include "warpgate.renderConfig" .) -}}
{{- printf "%s-config-overrides" (include "warpgate.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Secret holding the TLS certificate served by all listeners.
*/}}
{{- define "warpgate.tlsSecretName" -}}
{{- if .Values.tls_cert_secret -}}
{{- .Values.tls_cert_secret -}}
{{- else if include "warpgate.renderConfig" . -}}
{{- printf "%s-tls" (include "warpgate.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Hostnames the generated certificate is issued for.
*/}}
{{- define "warpgate.tlsHostnames" -}}
{{- $names := list (include "warpgate.fullname" .) (printf "%s.%s.svc" (include "warpgate.fullname" .) .Release.Namespace) }}
{{- range .Values.ingress.hosts }}{{- $names = append $names .host }}{{- end }}
{{- range .Values.httpRoute.hostnames }}{{- $names = append $names . }}{{- end }}
{{- $names | uniq | join "," }}
{{- end }}

{{/*
Warpgate config equivalent to what `unattended-setup` generates, for the pods
that don't get one from a volume. Ports mirror the setup values; everything
else is left at its default.
*/}}
{{- define "warpgate.config" -}}
{{- $host := ternary "0.0.0.0" "[::]" (.Values.setup.disableIpV6 | default false) -}}
database_url: {{ include "warpgate.databaseUrl" . | quote }}
http:
  listen: "{{ $host }}:{{ .Values.setup.http | default 8888 }}"
  certificate: /data/tls.certificate.pem
  key: /data/tls.key.pem
{{- with .Values.setup.ssh }}
ssh:
  enable: true
  listen: "{{ $host }}:{{ . }}"
{{- end }}
{{- with .Values.setup.mysql }}
mysql:
  enable: true
  listen: "{{ $host }}:{{ . }}"
  certificate: /data/tls.certificate.pem
  key: /data/tls.key.pem
{{- end }}
{{- with .Values.setup.pgsql }}
postgres:
  enable: true
  listen: "{{ $host }}:{{ . }}"
  certificate: /data/tls.certificate.pem
  key: /data/tls.key.pem
{{- end }}
{{- with .Values.setup.kubernetes }}
kubernetes:
  enable: true
  listen: "{{ $host }}:{{ . }}"
  certificate: /data/tls.certificate.pem
  key: /data/tls.key.pem
{{- end }}
{{- end }}
