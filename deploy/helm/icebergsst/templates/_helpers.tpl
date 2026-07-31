{{/*
Naming and labels. Two roles share a release, so almost everything here takes a
role and produces per-role names — one Deployment, Service, ServiceAccount and
Secret each, so nothing is shared that should not be.
*/}}

{{- define "icebergsst.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "icebergsst.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "icebergsst.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Labels every object carries. */}}
{{- define "icebergsst.labels" -}}
helm.sh/chart: {{ include "icebergsst.chart" . }}
app.kubernetes.io/name: {{ include "icebergsst.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: icebergsst
{{- end -}}

{{/*
Selector labels for one role. `component` is what keeps the two Deployments'
pods apart — and what a NetworkPolicy selects on to say "only the api reaches
Postgres".

Usage: {{ include "icebergsst.selectorLabels" (dict "context" . "role" "api") }}
*/}}
{{- define "icebergsst.selectorLabels" -}}
app.kubernetes.io/name: {{ include "icebergsst.name" .context }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
app.kubernetes.io/component: {{ .role }}
{{- end -}}

{{- define "icebergsst.componentName" -}}
{{- printf "%s-%s" (include "icebergsst.fullname" .context) .role | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Image reference for a role, defaulting the tag to the chart's appVersion. */}}
{{- define "icebergsst.image" -}}
{{- $image := index .context.Values.image .role -}}
{{- $tag := default .context.Chart.AppVersion $image.tag -}}
{{- if .context.Values.image.registry -}}
{{- printf "%s/%s:%s" .context.Values.image.registry $image.repository $tag -}}
{{- else -}}
{{- printf "%s:%s" $image.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "icebergsst.serviceAccountName" -}}
{{- $override := index .context.Values.serviceAccount (printf "%sName" .role) -}}
{{- if $override -}}
{{- $override -}}
{{- else if .context.Values.serviceAccount.create -}}
{{- include "icebergsst.componentName" . -}}
{{- else -}}
default
{{- end -}}
{{- end -}}

{{/*
Which Secret each role reads. Separate names, deliberately: the engine's Secret
does not contain a database URL or a master key, so a compromised engine has
nothing to read even if it can read its own Secret (ADR 0002).
*/}}
{{- define "icebergsst.apiSecretName" -}}
{{- default (printf "%s-api" (include "icebergsst.fullname" .)) .Values.secrets.existingApiSecret -}}
{{- end -}}

{{- define "icebergsst.engineSecretName" -}}
{{- default (printf "%s-engine" (include "icebergsst.fullname" .)) .Values.secrets.existingEngineSecret -}}
{{- end -}}

{{- define "icebergsst.configMapName" -}}
{{- printf "%s-config" (include "icebergsst.fullname" .) -}}
{{- end -}}

{{/*
Environment shared by every role. Nothing sensitive, and nothing role-specific:
if a variable belongs to only one role it goes in that role's template, so
"what does the engine get?" is answerable by reading one file.
*/}}
{{- define "icebergsst.commonEnv" -}}
- name: ICEBERG_ENVIRONMENT
  valueFrom:
    configMapKeyRef:
      name: {{ include "icebergsst.configMapName" . }}
      key: ICEBERG_ENVIRONMENT
- name: ICEBERG_LOG_LEVEL
  valueFrom:
    configMapKeyRef:
      name: {{ include "icebergsst.configMapName" . }}
      key: ICEBERG_LOG_LEVEL
{{- end -}}
