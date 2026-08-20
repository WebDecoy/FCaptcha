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

The server falls back to `dev-secret-change-in-production`, which is published in
the source, so a deployment that forgets this does not fail — it silently accepts
tokens anyone can mint. A template error is the only way to make that impossible
to do by accident, and it costs one line of setup to satisfy.
*/}}
{{- define "fcaptcha.validateSecret" -}}
{{- if and (not .Values.secret) (not .Values.existingSecret) -}}
{{- fail "\n\nfcaptcha: a token signing key is required.\n\n  --set secret=$(openssl rand -hex 32)\n\nor point at one you already manage:\n\n  --set existingSecret=my-fcaptcha-secret\n\nWithout it the server falls back to a key published in its own source, and\nanyone can mint tokens your backend will accept.\n" -}}
{{- end -}}
{{- end -}}
