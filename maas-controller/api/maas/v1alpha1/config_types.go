/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	netwv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// ConfigKind is the API kind for the cluster-scoped MaaS platform anchor.
	ConfigKind = "Config"
	// ConfigInstanceName is the singleton resource name enforced by the API.
	ConfigInstanceName = "default"

	// ConfigConditionTenantsHealthy is the condition type set on Config.Status
	// to report the aggregate health of all AITenant CRs across the cluster.
	// It follows the ADR ODH-ADR-MS-0003 three-state model (Healthy/Degraded/Blocked).
	ConfigConditionTenantsHealthy = "TenantsHealthy"

	// ConfigConditionRemoteUsageLogsConfigured reports whether the remote OTLP
	// exporter described by spec.usageLogs.remoteOtlp could be rendered. It is
	// absent when remoteOtlp is unset.
	ConfigConditionRemoteUsageLogsConfigured = "RemoteUsageLogsConfigured"
)

// MaaSAPIEgressNetworkPolicyMode controls maas-controller reconciliation of
// maas-api-egress-restrict.
// +kubebuilder:validation:Enum=Managed;Disabled
type MaaSAPIEgressNetworkPolicyMode string

const (
	// MaaSAPIEgressNetworkPolicyManaged applies maas-api-egress-restrict (default).
	MaaSAPIEgressNetworkPolicyManaged MaaSAPIEgressNetworkPolicyMode = "Managed"
	// MaaSAPIEgressNetworkPolicyDisabled stops reconciling maas-api-egress-restrict
	// so customers can manage egress NetworkPolicies themselves.
	MaaSAPIEgressNetworkPolicyDisabled MaaSAPIEgressNetworkPolicyMode = "Disabled"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=maasconfig
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="Config name must be default"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`,description="Ready"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Config is a cluster-scoped anchor for MaaS platform resources. Namespaced and
// cluster-scoped operands created by maas-controller reference this object as their controller
// owner so Kubernetes garbage collection can tear down the full graph when the Config
// is deleted (subject to finalizers on dependents).
type Config struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConfigSpec   `json:"spec,omitempty"`
	Status ConfigStatus `json:"status,omitempty"`
}

// ConfigSpec defines the desired state of Config.
// Admission CEL keeps a low-cost shape check; strict restricted-egress validation
// (both to and ports, except the Kubernetes API port-only rule) runs at reconcile
// time in tenantreconcile.validateRestrictedEgressRules.
// +kubebuilder:validation:XValidation:rule="!has(self.networkPolicyEgressRules) || self.networkPolicyEgressRules.all(r, (has(r.ports) && size(r.ports) > 0) || (has(r.to) && size(r.to) > 0))",message="each networkPolicyEgressRules entry must specify at least one port or one destination"
// +kubebuilder:validation:XValidation:rule="!has(self.networkPolicyAdditionalEgressRules) || self.networkPolicyAdditionalEgressRules.all(r, (has(r.ports) && size(r.ports) > 0) || (has(r.to) && size(r.to) > 0))",message="each networkPolicyAdditionalEgressRules entry must specify at least one port or one destination"
// +kubebuilder:validation:XValidation:rule="!has(self.maasApiEgressNetworkPolicy) || self.maasApiEgressNetworkPolicy != 'Disabled' || ((!has(self.networkPolicyEgressRules) || size(self.networkPolicyEgressRules) == 0) && (!has(self.networkPolicyAdditionalEgressRules) || size(self.networkPolicyAdditionalEgressRules) == 0))",message="networkPolicyEgressRules and networkPolicyAdditionalEgressRules must be unset when maasApiEgressNetworkPolicy is Disabled"
type ConfigSpec struct {
	// LimitadorScrapeInterval defines the scrape interval for Limitador metrics in the ServiceMonitor.
	// Defaults to "30s" if not specified.
	// +optional
	// +kubebuilder:default="30s"
	// +kubebuilder:validation:Pattern=`^([0-9]+(\.[0-9]+)?(ms|s|m|h))+$`
	// +kubebuilder:validation:MaxLength=16
	LimitadorScrapeInterval string `json:"limitadorScrapeInterval,omitempty"`

	// UsageLogging is retained for compatibility and does not gate deployment.
	// When true, the gateway EnvoyFilter exports usage logs to usage-logs-collector.
	// When false or unset, it exports to data-science-usage-logs-collector.
	// When MaasTenantConfig telemetry is enabled and usageLogging is false or unset,
	// MaasTenantConfig is Degraded unless DSCInitialization reports LokiStackAvailable,
	// UsageLogsCollectorAvailable, and PersesAvailable as True.
	// When usageLogging is true and telemetry is enabled, MaasTenantConfig is Degraded
	// unless PersesAvailable is True.
	// User identity (user_id) is included in those logs only when
	// MaasTenantConfig.spec.telemetry.logs.captureUser is true.
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	UsageLogging *bool `json:"usageLogging,omitempty"`

	// MaasAPIEgressNetworkPolicy controls whether maas-controller reconciles
	// maas-api-egress-restrict. Managed (default) applies the operand egress policy;
	// Disabled deletes it so customers can manage egress NetworkPolicies themselves.
	// +optional
	// +kubebuilder:validation:Enum=Managed;Disabled
	// +kubebuilder:default=Managed
	MaasAPIEgressNetworkPolicy MaaSAPIEgressNetworkPolicyMode `json:"maasApiEgressNetworkPolicy,omitempty"`

	// NetworkPolicyEgressRules, when non-empty, replaces the default egress block of
	// maas-api-egress-restrict. The caller must include DNS, Kubernetes API, database,
	// and any other required destinations. When empty, the operator applies DNS, API
	// ports, and allow-all egress for customer-provided dependencies.
	// Rules from NetworkPolicyAdditionalEgressRules are appended after this list.
	// +optional
	// +kubebuilder:validation:MaxItems=32
	NetworkPolicyEgressRules []netwv1.NetworkPolicyEgressRule `json:"networkPolicyEgressRules,omitempty"`

	// NetworkPolicyAdditionalEgressRules specifies egress rules appended after the
	// base egress block (either defaults or NetworkPolicyEgressRules). Use for
	// non-standard ports or extra database peers when retaining default allow-all.
	// +optional
	// +kubebuilder:validation:MaxItems=32
	NetworkPolicyAdditionalEgressRules []netwv1.NetworkPolicyEgressRule `json:"networkPolicyAdditionalEgressRules,omitempty"`

	// UsageMetricsDashboard deploys the legacy Prometheus-based Perses usage dashboard
	// (dashboard-3-maas-usage-admin). When disabled (the default), the controller
	// removes any controller-owned copy of that dashboard and does not mark
	// MaasTenantConfig Degraded when the ODH monitoring stack is unavailable.
	// When enabled and MaasTenantConfig telemetry is enabled, an unavailable monitoring
	// stack sets MaasTenantConfig phase to Degraded.
	// Prefer the logs-based usage dashboards, which are deployed with the usage-log resources.
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	UsageMetricsDashboard *bool `json:"usageMetricsDashboard,omitempty"`

	// UsageLogs contains advanced usage-log routing settings. It is additive to
	// UsageLogging, which remains the feature gate: when UsageLogging is false or
	// unset nothing here is rendered.
	// +optional
	UsageLogs *UsageLogsConfig `json:"usageLogs,omitempty"`
}

// UsageLogsConfig holds advanced usage-log settings.
type UsageLogsConfig struct {
	// RemoteOtlp forwards a copy of every usage record to an upstream OTLP/HTTP
	// receiver, in addition to the spoke-local LokiStack. The local export is
	// unaffected. Unset means no remote export.
	// +optional
	RemoteOtlp *RemoteOtlpConfig `json:"remoteOtlp,omitempty"`
}

// RemoteOtlpConfig configures the remote OTLP/HTTP exporter.
type RemoteOtlpConfig struct {
	// Endpoint is the OTLP/HTTP base URL of the receiver, including the tenant
	// path but excluding the /v1/logs suffix, which the exporter appends itself.
	// Example: https://usage-logs-hub.example.com/api/logs/v1/infrastructure/otlp
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https?://`
	Endpoint string `json:"endpoint"`

	// HeadersSecret names a Secret in the monitoring namespace whose every
	// key/value pair is sent as an HTTP header on the remote export, so a bearer
	// token is supplied as a key named Authorization with value "Bearer <token>".
	// Values are projected as environment variables and referenced from the
	// collector config; they are never written into the collector spec.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	HeadersSecret string `json:"headersSecret"`

	// TLS configures trust for the remote endpoint. Omit it when the endpoint
	// presents a publicly trusted certificate.
	// +optional
	TLS *RemoteOtlpTLSConfig `json:"tls,omitempty"`

	// Attributes overrides the cluster identity stamped onto remote records.
	// Anything left empty is auto-detected.
	// +optional
	Attributes *RemoteOtlpAttributesConfig `json:"attributes,omitempty"`
}

// RemoteOtlpTLSConfig defines TLS parameters for the remote exporter.
type RemoteOtlpTLSConfig struct {
	// CABundleSecret names a Secret in the monitoring namespace holding a
	// ca-bundle.crt key, mounted into the collector and used to verify the
	// remote endpoint.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	CABundleSecret string `json:"caBundleSecret,omitempty"`
}

// RemoteOtlpAttributesConfig overrides the resource attributes identifying this
// cluster on remote records. These are applied only to the remote pipeline, so
// they never reach the spoke-local LokiStack.
type RemoteOtlpAttributesConfig struct {
	// ClusterName overrides the auto-detected cluster_name.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	ClusterName string `json:"cluster_name,omitempty"`

	// ClusterID overrides the auto-detected cluster_id.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	ClusterID string `json:"cluster_id,omitempty"`
}

// ConfigStatus defines the observed state of Config.
type ConfigStatus struct {
	// Conditions represent the latest available observations of the MaaS platform state.
	// The Ready condition aggregates status from the default AITenant and MaasTenantConfig
	// so that the platform operator (DSC) can report configuration issues without watching
	// MaaS operands directly.
	// The TenantsHealthy condition aggregates the Ready state of all AITenant CRs into a
	// three-state model (Healthy/Degraded/Blocked) per ADR ODH-ADR-MS-0003.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// ConfigList contains a list of Config.
type ConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Config `json:"items"`
}

func init() {
	register(&Config{}, &ConfigList{})
}
