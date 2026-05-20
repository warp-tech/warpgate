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
Checksum of inputs that produce /data/warpgate.yaml: the override ConfigMap
and, when config_env_var_replace is set, the resolved env Secret values.
Empty when nothing applies or lookup is unavailable (helm template / dry-run).
*/}}
{{- define "warpgate.configChecksum" -}}
{{- $configContent := "" -}}
{{- if .Values.overrides_config -}}
  {{- $configContent = include (print $.Template.BasePath "/configmap.yaml") . -}}
{{- end -}}
{{- $envParts := list -}}
{{- if and .Values.config_env_var_replace .Values.setup.envFromSecret -}}
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
