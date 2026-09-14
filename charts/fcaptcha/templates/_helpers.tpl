{{- define "fcaptcha.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "fcaptcha.fullname" -}}
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

{{- define "fcaptcha.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "fcaptcha.labels" -}}
helm.sh/chart: {{ include "fcaptcha.chart" . }}
{{ include "fcaptcha.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: fcaptcha
{{- end }}

{{- define "fcaptcha.selectorLabels" -}}
app.kubernetes.io/name: {{ include "fcaptcha.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "fcaptcha.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "fcaptcha.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
The Secret holding FCAPTCHA_SECRET — either one we create or one the operator
manages.
*/}}
{{- define "fcaptcha.secretName" -}}
{{- if .Values.existingSecret }}{{ .Values.existingSecret }}{{ else }}{{ include "fcaptcha.fullname" . }}{{ end }}
{{- end }}

{{/*
Refuses to render without a signing key.

Both the chart and server require a signing key. Catch missing values at render
time so operators see the configuration error before scheduling a pod.
*/}}
{{- define "fcaptcha.validateSecret" -}}
{{- if and (not .Values.secret) (not .Values.existingSecret) -}}
{{- fail "fcaptcha: a signing key is required. Use --set secret=$(openssl rand -hex 32) or --set existingSecret=my-fcaptcha-secret. The server rejects missing, short and repetitive keys." -}}
{{- end -}}
{{- end -}}

{{/* Multiple Go pods require shared security state. */}}
{{- define "fcaptcha.validateSharedState" -}}
{{- $multiple := or (gt (int .Values.replicaCount) 1) .Values.autoscaling.enabled -}}
{{- $redisConfigured := or .Values.redis.url .Values.redis.existingSecret -}}
{{- if and $multiple (not $redisConfigured) -}}
{{- fail "\n\nfcaptcha: multiple replicas require Redis-backed shared state.\n\nSet redis.url or redis.existingSecret, or keep replicaCount=1 and autoscaling.enabled=false.\n" -}}
{{- end -}}
{{- end -}}
