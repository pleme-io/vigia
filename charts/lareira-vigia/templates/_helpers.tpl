{{- define "lareira-vigia.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lareira-vigia.fullname" -}}
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

{{- define "lareira-vigia.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lareira-vigia.labels" -}}
app.kubernetes.io/name: {{ include "lareira-vigia.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: saguao
helm.sh/chart: {{ include "lareira-vigia.chart" . }}
{{- end }}

{{- define "lareira-vigia.selectorLabels" -}}
app.kubernetes.io/name: {{ include "lareira-vigia.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "lareira-vigia.serviceAccountName" -}}
{{- default (include "lareira-vigia.fullname" .) .Values.serviceAccount.name }}
{{- end }}

{{/*
Validate required identity fields. vigia is per-cluster and the
HelmRelease MUST set .cluster + .location to its own identity.
*/}}
{{- define "lareira-vigia.validate" -}}
{{- if not .Values.cluster }}
  {{- fail "lareira-vigia: .cluster is required (e.g., 'rio') — set per-cluster in the HelmRelease values" }}
{{- end }}
{{- if not .Values.location }}
  {{- fail "lareira-vigia: .location is required (e.g., 'bristol')" }}
{{- end }}
{{- end }}
