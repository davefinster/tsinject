{{/*
Standard naming/labels. NOTE on fixed names: the operator binary locates its
webhook Service ("tsinject-webhook"), the webhook configuration
("tsinject-mutating"), and the cert Secret ("tsinject-webhook-cert") by
constant name — so those objects are NOT release-name-templated, and the
chart is single-instance-per-cluster (which a cluster-scoped admission
operator is anyway).
*/}}

{{- define "tsinject.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tsinject.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else if contains (include "tsinject.name" .) .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "tsinject.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "tsinject.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "tsinject.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "tsinject.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tsinject.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Name of the Secret carrying the operator's tailnet credentials
(key secret.json): an existing Secret if referenced, else the chart-created
one from tailscale.tailnets or inline clientId/clientSecret.
*/}}
{{- define "tsinject.oauthSecretName" -}}
{{- if .Values.tailscale.oauth.existingSecret -}}
{{- .Values.tailscale.oauth.existingSecret -}}
{{- else if or .Values.tailscale.tailnets (and .Values.tailscale.oauth.clientId .Values.tailscale.oauth.clientSecret) -}}
{{- printf "%s-tailscale-oauth" (include "tsinject.fullname" .) -}}
{{- else -}}
{{- fail "set tailscale.oauth.existingSecret, tailscale.tailnets, or tailscale.oauth.clientId and tailscale.oauth.clientSecret" -}}
{{- end -}}
{{- end -}}
