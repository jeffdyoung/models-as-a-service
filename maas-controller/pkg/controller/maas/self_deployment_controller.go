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

package maas

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netwv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	maasv1alpha1 "github.com/opendatahub-io/models-as-a-service/maas-controller/api/maas/v1alpha1"
	"github.com/opendatahub-io/models-as-a-service/maas-controller/pkg/oteljson"
	"github.com/opendatahub-io/models-as-a-service/maas-controller/pkg/platform/tenantreconcile"
)

// CleanupFinalizer was historically added to the maas-controller Deployment for coordinated
// teardown when ODH removed MaaS. It is no longer set; this constant remains so reconciles
// can strip it from older installs.
const CleanupFinalizer = "maas.opendatahub.io/cleanup"

// usageLogsCollectorClusterRoleBindingName grants the usage-logs collector write
// access to application logs. It is removed when the collector CRD is unavailable
// (CWE-863). Disabling usageLogging removes it with the rest of the usage-logs-only
// resources.
const usageLogsCollectorClusterRoleBindingName = "usage-collector-application-logs-write"

// usageLogsDsciManagedKustomizeDir is the kustomization rendered when usageLogging is false or omitted.
const usageLogsDsciManagedKustomizeDir = "dsci-managed"

// usageLogsTenancyProxyDeploymentName is the Deployment for the Loki query tenancy proxy.
const usageLogsTenancyProxyDeploymentName = "usage-logs-tenancy-proxy"

// usageLogsTenancyProxyContainerName is the proxy container in the tenancy proxy Deployment.
const usageLogsTenancyProxyContainerName = "proxy"

// usageLogsCollectorEgressPolicyName is the egress NetworkPolicy rendered by the
// usage-logs bundle. It permits DNS and the local LokiStack gateway only, so a
// remote exporter times out until it is widened.
const usageLogsCollectorEgressPolicyName = "usage-logs-collector-egress-restrict"

// usageLogsCollectorName is the OpenTelemetryCollector rendered by the usage-logs bundle.
const usageLogsCollectorName = "usage-logs"

// Names used by the remote OTLP export added on top of the rendered collector.
const (
	// remoteOtlpExporterKey is the exporter added alongside otlp_http/loki.
	remoteOtlpExporterKey = "otlphttp/remote"
	// remoteOtlpPipelineKey is the pipeline carrying the remote export. It is
	// separate from the local logs pipeline so the cluster identity processor
	// cannot leak into the spoke-local write.
	remoteOtlpPipelineKey = "logs/remote"
	// remoteOtlpResourceProcessorKey stamps cluster identity on remote records only.
	remoteOtlpResourceProcessorKey = "resource/remote"
	// remoteOtlpCAVolumeName mounts the CA bundle used to verify the remote endpoint.
	remoteOtlpCAVolumeName = "remote-otlp-ca"
	// remoteOtlpTrustedCAConfigMap holds the cluster's trusted CA bundle, injected
	// by the network operator. It is used when no caBundleSecret is supplied,
	// because the collector's own trust store is replaced by the service CA mount
	// and therefore cannot verify publicly trusted endpoints.
	remoteOtlpTrustedCAConfigMap = "usage-logs-remote-trusted-ca"
	// remoteOtlpCAMountPath is where that bundle is mounted in the collector.
	remoteOtlpCAMountPath = "/etc/pki/remote-otlp-ca"
	// remoteOtlpCAKey is the Secret key expected to hold the bundle.
	remoteOtlpCAKey = "ca-bundle.crt"
	// remoteOtlpEnvPrefix namespaces the env vars projected from headersSecret.
	remoteOtlpEnvPrefix = "REMOTE_OTLP_HDR_"
	// unknownClusterID / unknownClusterName are stamped when identity cannot be
	// detected and no override was supplied, so records are still attributable
	// to "a cluster we could not identify" rather than silently unlabelled.
	unknownClusterID   = "unknown-cluster-id"
	unknownClusterName = "unknown-cluster-name"
)

// remoteOtlpEnvSanitizer maps Secret keys onto legal environment variable names.
var remoteOtlpEnvSanitizer = regexp.MustCompile(`[^A-Z0-9_]`)

// LifecycleReconciler watches the maas-controller Deployment. It is the sole creator of the
// cluster-scoped Config/default anchor when the Deployment exists and is not terminating (so
// standalone installs do not race applying a Config manifest before the Config CRD is ready).
// It links the default AITenant and default MaasTenantConfig to Config via non-controller
// ownerReferences. The Deployment itself deliberately does NOT get an ownerReference to
// Config: this reconciler's own workload must keep running independent of Config's lifecycle
// (self-heal after an accidental Config deletion, and reporting TeardownCompletedAnnotation
// once Config is deleted during teardown), so it must not be a GC dependent of the resource
// it manages. Legacy CleanupFinalizer entries and any legacy Deployment->Config
// ownerReference (set by older maas-controller versions) are removed when present.
type LifecycleReconciler struct {
	client.Client
	// APIReader performs uncached reads. The manager's Secret informer is
	// deliberately scoped to the infrastructure namespace, so Secrets elsewhere
	// — such as the remote-OTLP headersSecret in the monitoring namespace —
	// must be read directly rather than through the cache.
	APIReader                   client.Reader
	Scheme                      *runtime.Scheme
	DeploymentName              string
	DeploymentNS                string
	TenantSubscriptionNamespace string
	AITenantNamespace           string
	GatewayName                 string
	GatewayNamespace            string
	ObservabilityManifestsPath  string
	MonitoringNamespace         string
	UsageLogsManifestPath       string
	DiscoveryEnabled            bool
	DiscoveryManifestPath       string
	DiscoveryImage              string
	DiscoveryLogLevel           string
	DiscoveryNamespace          string
	DiscoveryReplicas           *int32

	staleResourcesCleanupMu        sync.Mutex
	staleResourcesCleanupCompleted bool
}

//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=apps,resources=deployments/finalizers,verbs=update
//+kubebuilder:rbac:groups=maas.opendatahub.io,resources=configs,verbs=get;list;watch
//+kubebuilder:rbac:groups=maas.opendatahub.io,resources=configs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=maas.opendatahub.io,resources=maastenantconfigs,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=maas.opendatahub.io,resources=aitenants,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups=cluster.open-cluster-management.io,resources=clusterclaims,verbs=get;list;watch
//+kubebuilder:rbac:groups=operator.open-cluster-management.io,resources=klusterlets,verbs=get;list;watch
//+kubebuilder:rbac:groups=perses.dev,resources=persesdashboards;persesdatasources,verbs=get;list;watch;create;patch;delete
//+kubebuilder:rbac:groups=opentelemetry.io,resources=opentelemetrycollectors,verbs=get;list;watch;create;patch;delete
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings;rolebindings,verbs=get;list;watch;create;patch;delete
//+kubebuilder:rbac:groups=loki.grafana.com,resources=application,resourceNames=logs,verbs=create;get
//+kubebuilder:rbac:groups="",resources=pods/log,verbs=get
//+kubebuilder:rbac:groups=security.openshift.io,resources=securitycontextconstraints,resourceNames=nonroot-v2,verbs=use

func (r *LifecycleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ctx = oteljson.IntoContext(ctx)
	log := oteljson.FromContext(ctx).WithName("self-deployment").WithValues("deployment", req.NamespacedName)

	var dep appsv1.Deployment
	if err := r.Get(ctx, req.NamespacedName, &dep); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if dep.DeletionTimestamp.IsZero() {
		// Strip before anything else so that, if teardown is requested below, Config
		// deletion can never cascade-delete the Deployment via a stale ownerReference
		// from a pre-self-teardown install.
		if err := r.stripLegacyDeploymentConfigOwnerReference(ctx, log, req.NamespacedName); err != nil {
			return ctrl.Result{}, err
		}
		teardownRequested := TeardownRequestedOnDeployment(&dep)
		cfg, res, err := r.ensureSingletonConfig(ctx, &dep)
		if err != nil {
			return ctrl.Result{}, err
		}
		if res != nil {
			return *res, nil
		}
		if teardownRequested {
			if cfg == nil {
				log.Info("teardown requested on maas-controller Deployment; running best-effort cleanup without Config/default")
			}
			return r.handleRequestedTeardown(ctx, &dep, cfg)
		}
		if res, err := r.ensureDefaultAITenantReferencesConfig(ctx); err != nil {
			return ctrl.Result{}, err
		} else if res != nil {
			return *res, nil
		}
		if res, err := r.ensureTenantReferencesConfig(ctx); err != nil {
			return ctrl.Result{}, err
		} else if res != nil {
			return *res, nil
		}
		// Upgrade cleanup is independent of observability and other module setup.
		if err := r.cleanupStaleResources(ctx, log); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.ensureObservability(ctx, log); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.ensureDiscoveryService(ctx, log); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.stripLegacyCleanupFinalizer(ctx, log, req.NamespacedName); err != nil {
			return ctrl.Result{}, err
		}
		if cfg != nil {
			if err := r.syncModuleStatus(ctx, cfg); err != nil {
				return ctrl.Result{}, err
			}
			if err := r.syncTenantsHealth(ctx, cfg); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Terminating: remove legacy finalizer only so deletion is not blocked.
	if err := r.stripLegacyCleanupFinalizer(ctx, log, req.NamespacedName); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// ensureDefaultAITenantReferencesConfig links the automatically bootstrapped
// default AITenant to Config/default. The bootstrap runnable may create the
// AITenant shell before owner refs converge.
func (r *LifecycleReconciler) ensureDefaultAITenantReferencesConfig(ctx context.Context) (*ctrl.Result, error) {
	if r.AITenantNamespace == "" {
		return nil, nil
	}
	if r.Scheme == nil {
		return nil, nil
	}
	log := oteljson.FromContext(ctx)
	cfgKey := client.ObjectKey{Name: maasv1alpha1.ConfigInstanceName}
	var cfg maasv1alpha1.Config
	if err := r.Get(ctx, cfgKey, &cfg); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Config anchor not found when linking default AITenant; requeueing")
			res := ctrl.Result{RequeueAfter: 2 * time.Second}
			return &res, nil
		}
		return nil, err
	}
	if !cfg.DeletionTimestamp.IsZero() {
		log.Info("Config anchor is terminating when linking default AITenant; requeueing")
		res := ctrl.Result{RequeueAfter: 10 * time.Second}
		return &res, nil
	}
	if cfg.UID == "" {
		res := ctrl.Result{RequeueAfter: 2 * time.Second}
		return &res, nil
	}

	aitenantKey := client.ObjectKey{Name: tenantreconcile.DefaultAITenantName, Namespace: r.AITenantNamespace}
	var aitenant maasv1alpha1.AITenant
	if err := r.Get(ctx, aitenantKey, &aitenant); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if !aitenant.DeletionTimestamp.IsZero() || aitenant.Status.Phase == "Terminating" {
		log.V(1).Info("skipping Config owner reference on terminating default AITenant",
			"namespace", r.AITenantNamespace)
		return nil, nil
	}
	if aitenantReferencesConfig(&aitenant, &cfg) {
		return nil, nil
	}
	base := aitenant.DeepCopy()
	if err := controllerutil.SetOwnerReference(&cfg, &aitenant, r.Scheme); err != nil {
		return nil, fmt.Errorf("set Config owner reference on default AITenant: %w", err)
	}
	if err := r.Patch(ctx, &aitenant, client.MergeFrom(base)); err != nil {
		return nil, fmt.Errorf("patch default AITenant ownerReferences: %w", err)
	}
	log.Info("set Config owner reference on default AITenant", "namespace", r.AITenantNamespace)
	return nil, nil
}

func (r *LifecycleReconciler) stripLegacyCleanupFinalizer(ctx context.Context, log logr.Logger, key types.NamespacedName) error {
	var dep appsv1.Deployment
	if err := r.Get(ctx, key, &dep); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !controllerutil.ContainsFinalizer(&dep, CleanupFinalizer) {
		return nil
	}
	base := dep.DeepCopy()
	controllerutil.RemoveFinalizer(&dep, CleanupFinalizer)
	if err := r.Patch(ctx, &dep, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("remove legacy cleanup finalizer from Deployment: %w", err)
	}
	log.Info("removed legacy cleanup finalizer from Deployment")
	return nil
}

// stripLegacyDeploymentConfigOwnerReference removes an ownerReference from the Deployment
// to Config/default if present. Pre-self-teardown maas-controller versions set this
// non-controller ownerReference (see the removed ensureDeploymentReferencesConfig); it must
// not survive an upgrade, or deleting Config could cascade-delete the Deployment itself
// before this reconciler can report TeardownCompletedAnnotation. New installs never set
// this ownerReference, so this is a no-op for them.
func (r *LifecycleReconciler) stripLegacyDeploymentConfigOwnerReference(ctx context.Context, log logr.Logger, key types.NamespacedName) error {
	var dep appsv1.Deployment
	if err := r.Get(ctx, key, &dep); err != nil {
		return client.IgnoreNotFound(err)
	}

	filtered := make([]metav1.OwnerReference, 0, len(dep.OwnerReferences))
	changed := false
	for _, ref := range dep.OwnerReferences {
		if isConfigOwnerReference(ref) {
			changed = true
			continue
		}
		filtered = append(filtered, ref)
	}
	if !changed {
		return nil
	}

	base := dep.DeepCopy()
	dep.OwnerReferences = filtered
	if err := r.Patch(ctx, &dep, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("remove legacy Config owner reference from Deployment: %w", err)
	}
	log.Info("removed legacy Config owner reference from Deployment")
	return nil
}

// isConfigOwnerReference reports whether ref points at the singleton Config/default
// resource. Config is cluster-scoped and singleton, so matching by name (in addition to
// kind and API version) is precise without needing to fetch Config to compare UIDs.
func isConfigOwnerReference(ref metav1.OwnerReference) bool {
	return ref.Kind == maasv1alpha1.ConfigKind &&
		ref.APIVersion == maasv1alpha1.GroupVersion.String() &&
		ref.Name == maasv1alpha1.ConfigInstanceName
}

// ensureSingletonConfig creates Config/default when it is missing and the watched Deployment
// is still running. If Config is terminating, requeues until teardown completes (avoids racing
// intentional anchor deletion). After accidental deletion while the Deployment remains, the
// anchor is recreated on a later reconcile.
func (r *LifecycleReconciler) ensureSingletonConfig(ctx context.Context, dep *appsv1.Deployment) (*maasv1alpha1.Config, *ctrl.Result, error) {
	if dep == nil || !dep.DeletionTimestamp.IsZero() {
		return nil, nil, nil
	}
	key := client.ObjectKey{Name: maasv1alpha1.ConfigInstanceName}
	var cfg maasv1alpha1.Config
	switch err := r.Get(ctx, key, &cfg); {
	case err == nil:
		if !cfg.DeletionTimestamp.IsZero() {
			return &cfg, nil, nil
		}
		if cfg.UID == "" {
			return nil, &ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}
		return &cfg, nil, nil
	case apierrors.IsNotFound(err):
		if TeardownRequestedOnDeployment(dep) {
			return nil, nil, nil
		}
		toCreate := &maasv1alpha1.Config{
			TypeMeta: metav1.TypeMeta{
				APIVersion: maasv1alpha1.GroupVersion.String(),
				Kind:       maasv1alpha1.ConfigKind,
			},
			ObjectMeta: metav1.ObjectMeta{Name: maasv1alpha1.ConfigInstanceName},
		}
		if err := r.Create(ctx, toCreate); err != nil && !apierrors.IsAlreadyExists(err) {
			return nil, nil, err
		}
		if err := r.Get(ctx, key, &cfg); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, &ctrl.Result{RequeueAfter: 2 * time.Second}, nil
			}
			return nil, nil, err
		}
		if cfg.UID == "" {
			return nil, &ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}
		return &cfg, nil, nil
	default:
		return nil, nil, err
	}
}

// ensureTenantReferencesConfig links MaasTenantConfig/default-tenant to Config/default via the same non-controller
// ownerReference pattern as the Deployment. The cluster bootstrap runnable may create the config
// shell without owner refs; this reconciler converges them once Config has a UID.
func (r *LifecycleReconciler) ensureTenantReferencesConfig(ctx context.Context) (*ctrl.Result, error) {
	if r.TenantSubscriptionNamespace == "" {
		return nil, nil
	}
	if r.Scheme == nil {
		return nil, nil
	}
	log := oteljson.FromContext(ctx)
	cfgKey := client.ObjectKey{Name: maasv1alpha1.ConfigInstanceName}
	var cfg maasv1alpha1.Config
	if err := r.Get(ctx, cfgKey, &cfg); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Config anchor not found when linking MaasTenantConfig; requeueing")
			res := ctrl.Result{RequeueAfter: 2 * time.Second}
			return &res, nil
		}
		return nil, err
	}
	if !cfg.DeletionTimestamp.IsZero() {
		log.Info("Config anchor is terminating when linking MaasTenantConfig; requeueing")
		res := ctrl.Result{RequeueAfter: 10 * time.Second}
		return &res, nil
	}
	if cfg.UID == "" {
		res := ctrl.Result{RequeueAfter: 2 * time.Second}
		return &res, nil
	}
	tKey := client.ObjectKey{Name: maasv1alpha1.MaasTenantConfigInstanceName, Namespace: r.TenantSubscriptionNamespace}
	var tenant maasv1alpha1.MaasTenantConfig
	if err := r.Get(ctx, tKey, &tenant); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if tenantReferencesConfig(&tenant, &cfg) {
		return nil, nil
	}
	base := tenant.DeepCopy()
	if err := controllerutil.SetOwnerReference(&cfg, &tenant, r.Scheme); err != nil {
		return nil, fmt.Errorf("set Config owner reference on MaasTenantConfig: %w", err)
	}
	if err := r.Patch(ctx, &tenant, client.MergeFrom(base)); err != nil {
		return nil, fmt.Errorf("patch MaasTenantConfig ownerReferences: %w", err)
	}
	log.Info("set Config owner reference on MaasTenantConfig/default-tenant", "namespace", r.TenantSubscriptionNamespace)
	return nil, nil
}

func tenantReferencesConfig(tenant *maasv1alpha1.MaasTenantConfig, ct *maasv1alpha1.Config) bool {
	for _, ref := range tenant.OwnerReferences {
		if ref.UID == ct.UID &&
			ref.Kind == maasv1alpha1.ConfigKind &&
			ref.APIVersion == maasv1alpha1.GroupVersion.String() {
			return true
		}
	}
	return false
}

func aitenantReferencesConfig(aitenant *maasv1alpha1.AITenant, ct *maasv1alpha1.Config) bool {
	for _, ref := range aitenant.OwnerReferences {
		if ref.UID == ct.UID &&
			ref.Kind == maasv1alpha1.ConfigKind &&
			ref.APIVersion == maasv1alpha1.GroupVersion.String() {
			return true
		}
	}
	return false
}

func (r *LifecycleReconciler) ensureObservability(ctx context.Context, log logr.Logger) error {
	if r.MonitoringNamespace == "" {
		log.V(1).Info("monitoring namespace not configured; skipping observability setup")
		return nil
	}

	var ns corev1.Namespace
	if err := r.Get(ctx, client.ObjectKey{Name: r.MonitoringNamespace}, &ns); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("monitoring namespace does not exist; skipping observability setup",
				"namespace", r.MonitoringNamespace)
			return nil
		}
		return fmt.Errorf("checking monitoring namespace %q: %w", r.MonitoringNamespace, err)
	}

	if err := r.ensureLimitadorServiceMonitor(ctx); err != nil {
		return err
	}
	if err := r.ensureUsageDashboard(ctx, log); err != nil {
		return err
	}
	if err := r.ensureUsageLogs(ctx, log); err != nil {
		return err
	}
	return nil
}

// ensureLimitadorServiceMonitor creates or updates the Limitador ServiceMonitor in the operator namespace.
// This ServiceMonitor ensures metrics are scraped from the Limitador pod and get to the DSC's monitoring stack.
// If the ServiceMonitor CRD is not available, this is a no-op (allows running without the monitoring stack).
// TODO: need to set the overall status of MaaS to Degraded if COO is missing.
func (r *LifecycleReconciler) ensureLimitadorServiceMonitor(ctx context.Context) error {
	var cfg maasv1alpha1.Config
	if err := r.Get(ctx, client.ObjectKey{Name: maasv1alpha1.ConfigInstanceName}, &cfg); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	scrapeInterval := cfg.Spec.LimitadorScrapeInterval
	if scrapeInterval == "" {
		scrapeInterval = "30s"
	}

	sm := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "monitoring.coreos.com/v1",
			"kind":       "ServiceMonitor",
			"metadata": map[string]any{
				"name":      "limitador-metrics",
				"namespace": r.MonitoringNamespace,
				"labels": map[string]any{
					"app":                              "limitador",
					"monitoring.opendatahub.io/scrape": "true",
				},
			},
			"spec": map[string]any{
				"endpoints": []any{
					map[string]any{
						"interval": scrapeInterval,
						"path":     "/metrics",
						"port":     "http",
					},
				},
				"namespaceSelector": map[string]any{
					"any": true,
				},
				"selector": map[string]any{
					"matchLabels": map[string]any{
						"app": "limitador",
					},
				},
			},
		},
	}

	if err := controllerutil.SetOwnerReference(&cfg, sm, r.Scheme); err != nil {
		return fmt.Errorf("set owner reference on ServiceMonitor: %w", err)
	}

	if err := r.Apply(ctx, client.ApplyConfigurationFromUnstructured(sm), client.ForceOwnership, client.FieldOwner("maas-controller")); err != nil {
		// If ServiceMonitor CRD is not installed, skip creation (monitoring stack is optional)
		if apierrors.IsNotFound(err) || apimeta.IsNoMatchError(err) {
			return nil
		}
		return fmt.Errorf("apply ServiceMonitor: %w", err)
	}

	return nil
}

// ensureUsageDashboard deploys or removes the legacy metrics-based usage dashboard
// based on the Config's usageMetricsDashboard feature gate.
// Uses the existing kustomize infrastructure to render manifests from ObservabilityManifestsPath.
// If ObservabilityManifestsPath is not set or Perses CRDs are not installed, gracefully skips.
func (r *LifecycleReconciler) ensureUsageDashboard(ctx context.Context, log logr.Logger) error {
	// Skip if observability manifests path not configured
	if r.ObservabilityManifestsPath == "" {
		log.Info("WARNING: Observability manifests path not configured; skipping observability dashboards")
		return nil
	}

	var cfg maasv1alpha1.Config
	if err := r.Get(ctx, client.ObjectKey{Name: maasv1alpha1.ConfigInstanceName}, &cfg); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	// Render kustomization (reuses tenant reconciler's kustomize logic)
	// TODO: move kustomize logic to a separate package and reuse it here.
	resources, err := tenantreconcile.RenderKustomize(r.ObservabilityManifestsPath, r.MonitoringNamespace)
	if err != nil {
		return fmt.Errorf("render observability dashboards: %w", err)
	}

	if !ptr.Deref(cfg.Spec.UsageMetricsDashboard, false) {
		return r.deleteOwnedRenderedResources(ctx, log, cfg, resources, "usageMetricsDashboard")
	}

	// Apply each resource with Config as controller owner
	for _, resource := range resources {
		res := resource // avoid loop variable aliasing
		if err := controllerutil.SetControllerReference(&cfg, &res, r.Scheme); err != nil {
			return fmt.Errorf("set controller reference on %s %s: %w", res.GetKind(), res.GetName(), err)
		}

		if err := r.Apply(ctx, client.ApplyConfigurationFromUnstructured(&res), client.ForceOwnership, client.FieldOwner("maas-controller")); err != nil {
			if isOptionalAPIGroup(res.GroupVersionKind().Group) && (apimeta.IsNoMatchError(err) || apierrors.IsNotFound(err)) {
				// CRD not yet registered for a known optional dependency (e.g. Perses CRDs
				// installed by COO which may not be present yet). Skip so the rest of the
				// platform manifests are applied and Tenant reconcile does not fail.
				// The CRD watch will re-trigger reconcile once the CRDs appear.
				oteljson.FromContext(ctx).Info("skipping resource: optional CRD not yet registered, will apply once installed",
					"group", res.GroupVersionKind().Group, "kind", res.GetKind(),
					"name", res.GetName(), "namespace", res.GetNamespace())
				continue
			}
			return fmt.Errorf("apply %s %s/%s: %w", res.GetKind(), res.GetNamespace(), res.GetName(), err)
		}
	}

	return nil
}

// ensureUsageLogs deploys usage-log dashboards, the tenancy proxy, and related RBAC.
// usageLogging true renders usage-logs. false and omitted render dsci-managed.
// Objects rendered by both bundles are applied in place. Controller-owned objects
// rendered only by the other bundle are deleted.
func (r *LifecycleReconciler) ensureUsageLogs(ctx context.Context, log logr.Logger) error {
	if r.UsageLogsManifestPath == "" {
		log.Info("WARNING: Usage logs manifest path not configured; skipping usage logs")
		return nil
	}

	var cfg maasv1alpha1.Config
	if err := r.Get(ctx, client.ObjectKey{Name: maasv1alpha1.ConfigInstanceName}, &cfg); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	usageLogging := ptr.Deref(cfg.Spec.UsageLogging, false)
	manifestPath := usageLogsKustomizeDir(r.UsageLogsManifestPath, usageLogging)
	inactivePath := usageLogsKustomizeDir(r.UsageLogsManifestPath, !usageLogging)
	resources, err := tenantreconcile.RenderKustomize(manifestPath, r.MonitoringNamespace)
	if err != nil {
		return fmt.Errorf("render usage logs: %w", err)
	}
	inactive, err := tenantreconcile.RenderKustomize(inactivePath, r.MonitoringNamespace)
	if err != nil {
		return fmt.Errorf("render inactive usage logs: %w", err)
	}

	// Remote OTLP export (RHAI-8084) is layered onto the rendered collector.
	// usageLogging remains the feature gate: when it is false the usage-logs
	// bundle is not rendered at all, so remoteOtlp cannot take effect.
	var (
		remoteOtlp        *maasv1alpha1.RemoteOtlpConfig
		remoteHeaderKeys  []string
		remoteClusterID   string
		remoteClusterName string
	)
	if usageLogging && cfg.Spec.UsageLogs != nil && cfg.Spec.UsageLogs.RemoteOtlp != nil {
		remote := cfg.Spec.UsageLogs.RemoteOtlp
		keys, err := r.remoteOtlpHeaderKeys(ctx, remote)
		if err != nil {
			// Surface the problem and leave the local pipeline rendering. A bad
			// remote reference must not take spoke-local usage logging down with it.
			apimeta.SetStatusCondition(&cfg.Status.Conditions, metav1.Condition{
				Type:    maasv1alpha1.ConfigConditionRemoteUsageLogsConfigured,
				Status:  metav1.ConditionFalse,
				Reason:  "HeadersSecretUnusable",
				Message: err.Error(),
			})
			if statusErr := r.Status().Update(ctx, &cfg); statusErr != nil {
				log.Error(statusErr, "update Config status after headersSecret failure")
			}
			log.Error(err, "remote usage-log export disabled")
		} else {
			remoteOtlp = remote
			remoteHeaderKeys = keys
			remoteClusterID, remoteClusterName = r.resolveClusterIdentity(ctx, remote.Attributes)
			if remote.TLS == nil || remote.TLS.CABundleSecret == "" {
				if caErr := r.ensureRemoteOtlpTrustedCA(ctx, &cfg); caErr != nil {
					log.Error(caErr, "ensure trusted CA bundle for remote usage-log export")
				}
			}
			apimeta.SetStatusCondition(&cfg.Status.Conditions, metav1.Condition{
				Type:   maasv1alpha1.ConfigConditionRemoteUsageLogsConfigured,
				Status: metav1.ConditionTrue,
				Reason: "Configured",
				Message: fmt.Sprintf("Exporting usage logs to %s as cluster_id=%s cluster_name=%s",
					remote.Endpoint, remoteClusterID, remoteClusterName),
			})
			if statusErr := r.Status().Update(ctx, &cfg); statusErr != nil {
				log.Error(statusErr, "update Config status after configuring remote export")
			}
		}
	} else {
		// Clean removal: unsetting remoteOtlp drops the condition along with the
		// exporter and pipeline, which simply stop being rendered. The trusted-CA
		// ConfigMap is not rendered from the bundle, so nothing stops reconciling
		// it — it has to be deleted explicitly. It is owned by the Config and so
		// would be collected eventually, but leaving a ~220KB ConfigMap that the
		// network operator keeps refreshing is not a clean removal.
		if caErr := r.removeRemoteOtlpTrustedCA(ctx); caErr != nil {
			log.Error(caErr, "remove trusted CA bundle after disabling remote usage-log export")
		}
		if apimeta.FindStatusCondition(cfg.Status.Conditions,
			maasv1alpha1.ConfigConditionRemoteUsageLogsConfigured) != nil {
			apimeta.RemoveStatusCondition(&cfg.Status.Conditions,
				maasv1alpha1.ConfigConditionRemoteUsageLogsConfigured)
			if statusErr := r.Status().Update(ctx, &cfg); statusErr != nil {
				log.Error(statusErr, "update Config status after removing remote export")
			}
		}
	}

	// Track if the collector is skipped due to missing CRD (CWE-863).
	// If the OpenTelemetryCollector CRD is unavailable, we must skip the entire
	// bundle to prevent orphaned ClusterRoleBinding from granting cluster-logging-application-write
	// permissions to a ServiceAccount (usage-logs-collector) that anyone could then create and exploit.
	collectorSkipped := false

	for _, resource := range resources {
		if collectorSkipped {
			continue
		}
		res := resource // avoid loop variable aliasing
		if err := patchTenancyProxyImage(&res); err != nil {
			return fmt.Errorf("patch %s %s: %w", res.GetKind(), res.GetName(), err)
		}
		if err := patchPersesDatasourceURL(&res); err != nil {
			return fmt.Errorf("patch %s %s: %w", res.GetKind(), res.GetName(), err)
		}
		if remoteOtlp != nil {
			if err := patchRemoteOtlpExporter(&res, remoteOtlp, remoteHeaderKeys,
				remoteClusterID, remoteClusterName); err != nil {
				return fmt.Errorf("patch %s %s: %w", res.GetKind(), res.GetName(), err)
			}
			if err := patchRemoteOtlpEgress(&res, remoteOtlp); err != nil {
				return fmt.Errorf("patch %s %s: %w", res.GetKind(), res.GetName(), err)
			}
		}
		if err := controllerutil.SetControllerReference(&cfg, &res, r.Scheme); err != nil {
			return fmt.Errorf("set controller reference on %s %s: %w", res.GetKind(), res.GetName(), err)
		}

		if err := r.Apply(ctx, client.ApplyConfigurationFromUnstructured(&res), client.ForceOwnership, client.FieldOwner("maas-controller")); err != nil {
			if isOptionalAPIGroup(res.GroupVersionKind().Group) && (apimeta.IsNoMatchError(err) || apierrors.IsNotFound(err)) {
				log.Info("skipping usage-logs resource: optional CRD not yet registered, will apply once installed",
					"group", res.GroupVersionKind().Group, "kind", res.GetKind(),
					"name", res.GetName(), "namespace", res.GetNamespace())
				if res.GetKind() == "OpenTelemetryCollector" {
					collectorSkipped = true
				}
				continue
			}
			return fmt.Errorf("apply %s %s/%s: %w", res.GetKind(), res.GetNamespace(), res.GetName(), err)
		}
	}

	// If the collector was skipped, delete any orphaned RBAC resources that may have
	// been created in a prior reconcile when the CRD was available (CWE-863).
	if collectorSkipped {
		gvkClusterRoleBinding := schema.GroupVersionKind{
			Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRoleBinding",
		}
		crb := &unstructured.Unstructured{}
		crb.SetGroupVersionKind(gvkClusterRoleBinding)
		crb.SetName(usageLogsCollectorClusterRoleBindingName)

		if err := r.Get(ctx, client.ObjectKeyFromObject(crb), crb); err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("get orphaned ClusterRoleBinding after collector skip: %w", err)
			}
		} else if isOwnedByConfigOrController(crb, cfg.UID) {
			if err := r.Delete(ctx, crb); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete orphaned ClusterRoleBinding after collector skip: %w", err)
			}
			log.Info("deleted orphaned usage-logs ClusterRoleBinding (collector CRD unavailable)")
		}
	}

	// Delete controller-owned objects that only the inactive bundle renders.
	// Shared objects stay and were updated by the apply above. Unowned objects
	// with the same names are left in place.
	if err := r.deleteOwnedRenderedResources(ctx, log, cfg, resourcesAbsentFrom(inactive, resources), "usageLogging"); err != nil {
		return err
	}

	return nil
}

// resourcesAbsentFrom returns objects in have whose group, version, kind,
// namespace, and name are not present in keep.
func resourcesAbsentFrom(have, keep []unstructured.Unstructured) []unstructured.Unstructured {
	present := make(map[string]struct{}, len(keep))
	for _, obj := range keep {
		present[renderedResourceID(obj)] = struct{}{}
	}
	stale := make([]unstructured.Unstructured, 0)
	for _, obj := range have {
		if _, ok := present[renderedResourceID(obj)]; ok {
			continue
		}
		stale = append(stale, obj)
	}
	return stale
}

func renderedResourceID(obj unstructured.Unstructured) string {
	gvk := obj.GroupVersionKind()
	return strings.Join([]string{gvk.Group, gvk.Version, gvk.Kind, obj.GetNamespace(), obj.GetName()}, "/")
}

// usageLogsKustomizeDir selects the usage-logs kustomization.
// usageLogging true uses the usage-logs directory; false and omitted use dsci-managed.
func usageLogsKustomizeDir(base string, usageLogging bool) string {
	if usageLogging {
		return base
	}
	return filepath.Join(base, usageLogsDsciManagedKustomizeDir)
}

// deleteOwnedRenderedResources deletes resources from a rendered kustomize bundle
// that are owned by Config or labeled as managed by maas-controller. Unowned
// resources with the same names are left untouched (CWE-284).
func (r *LifecycleReconciler) deleteOwnedRenderedResources(
	ctx context.Context,
	log logr.Logger,
	cfg maasv1alpha1.Config,
	resources []unstructured.Unstructured,
	disabledFeature string,
) error {
	for _, resource := range resources {
		res := resource.DeepCopy()
		key := client.ObjectKeyFromObject(res)
		existing := &unstructured.Unstructured{}
		existing.SetGroupVersionKind(res.GroupVersionKind())

		if err := r.Get(ctx, key, existing); err != nil {
			if apierrors.IsNotFound(err) || apimeta.IsNoMatchError(err) {
				continue
			}
			return fmt.Errorf("get %s %s/%s before delete: %w", res.GetKind(), res.GetNamespace(), res.GetName(), err)
		}

		if !isOwnedByConfigOrController(existing, cfg.UID) {
			log.V(1).Info("skipping deletion of unowned resource",
				"feature", disabledFeature,
				"kind", res.GetKind(), "name", res.GetName(), "namespace", res.GetNamespace())
			continue
		}

		if err := r.Delete(ctx, existing); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("delete %s %s/%s: %w", res.GetKind(), res.GetNamespace(), res.GetName(), err)
		}
		log.V(1).Info("deleted controller-owned rendered resource",
			"feature", disabledFeature,
			"kind", res.GetKind(), "name", res.GetName(), "namespace", res.GetNamespace())
	}
	return nil
}

// isOwnedByConfigOrController verifies whether a resource is owned by the Config controller
// or has the trusted managed-by label. This prevents accidental deletion of pre-existing
// foreign resources with the same name (CWE-284).
func isOwnedByConfigOrController(obj client.Object, configUID types.UID) bool {
	// Check if owned by Config via OwnerReferences
	for _, ref := range obj.GetOwnerReferences() {
		if ref.UID == configUID && ref.Controller != nil && *ref.Controller {
			return true
		}
	}

	// Check for trusted managed-by label
	labels := obj.GetLabels()
	if labels != nil && labels["app.kubernetes.io/managed-by"] == "maas-controller" {
		return true
	}

	return false
}

// patchPersesDatasourceURL expands short service references in PersesDatasource URLs to FQDNs.
// Rewrites URLs like "https://service-name:port" to "https://service-name.{namespace}.svc:port"
// using the datasource's deployed namespace. This allows YAML to use simple service references
// while ensuring they work correctly in any namespace.
func patchPersesDatasourceURL(res *unstructured.Unstructured) error {
	if res.GetKind() != "PersesDatasource" {
		return nil
	}

	namespace := res.GetNamespace()
	if namespace == "" {
		// No namespace set, skip patching
		return nil
	}

	urlPath := []string{"spec", "config", "plugin", "spec", "proxy", "spec", "url"}
	url, found, err := unstructured.NestedString(res.Object, urlPath...)
	if err != nil {
		return fmt.Errorf("read datasource URL: %w", err)
	}
	if !found {
		// URL field doesn't exist in this datasource
		return nil
	}

	// Only patch if URL doesn't already have .svc (i.e., it's a short service reference)
	if !strings.Contains(url, ".svc") {
		// Pattern: https://service-name:port/path -> https://service-name.{namespace}.svc:port/path
		// Use regex to insert .{namespace}.svc before the port
		re := regexp.MustCompile(`(https?://[^:]+)(:\d+)`)
		patchedURL := re.ReplaceAllString(url, fmt.Sprintf("$1.%s.svc$2", namespace))

		if err := unstructured.SetNestedField(res.Object, patchedURL, urlPath...); err != nil {
			return fmt.Errorf("set datasource URL: %w", err)
		}
	}

	return nil
}

// patchTenancyProxyImage sets the tenancy-proxy container image to RELATED_IMAGE_ODH_PYTHON_312_IMAGE
// if configured, otherwise uses DefaultUsageLogsTenancyProxyImage. This enables disconnected deployments
// to mirror the image while maintaining a code-defined default.
func patchTenancyProxyImage(res *unstructured.Unstructured) error {
	if res.GetKind() != "Deployment" || res.GetName() != usageLogsTenancyProxyDeploymentName {
		return nil
	}

	image := os.Getenv("RELATED_IMAGE_ODH_PYTHON_312_IMAGE")
	if image == "" {
		image = DefaultUsageLogsTenancyProxyImage
	}

	containers, found, err := unstructured.NestedSlice(res.Object, "spec", "template", "spec", "containers")
	if err != nil {
		return fmt.Errorf("read containers in deployment: %w", err)
	}
	if !found {
		return errors.New("containers not found in usage-logs-tenancy-proxy deployment")
	}

	for i, c := range containers {
		cm, ok := c.(map[string]any)
		if !ok || cm["name"] != usageLogsTenancyProxyContainerName {
			continue
		}
		cm["image"] = image
		containers[i] = cm
		return unstructured.SetNestedSlice(res.Object, containers, "spec", "template", "spec", "containers")
	}

	return errors.New("proxy container not found in usage-logs-tenancy-proxy deployment")
}

// remoteOtlpEnvVarName derives a legal environment variable name for a
// headersSecret key, so that "X-Scope-OrgID" becomes REMOTE_OTLP_HDR_X_SCOPE_ORGID.
func remoteOtlpEnvVarName(key string) string {
	return remoteOtlpEnvPrefix + remoteOtlpEnvSanitizer.ReplaceAllString(strings.ToUpper(key), "_")
}

// patchRemoteOtlpEgress widens the usage-logs egress NetworkPolicy so the remote
// exporter can reach its endpoint. Without this the export fails as a *timeout*
// rather than a refusal — NetworkPolicy drops packets silently — which looks
// like an unresponsive receiver rather than a local policy.
//
// The rule is deliberately broad. A remote endpoint is typically a Route behind
// a cloud load balancer whose addresses cannot be pinned, so there is no stable
// CIDR to allow. Link-local is excluded to keep the cloud metadata endpoint out
// of reach, which is the single most valuable restriction retained.
func patchRemoteOtlpEgress(res *unstructured.Unstructured, remote *maasv1alpha1.RemoteOtlpConfig) error {
	if res.GetKind() != "NetworkPolicy" || res.GetName() != usageLogsCollectorEgressPolicyName {
		return nil
	}

	port, err := remoteOtlpPort(remote.Endpoint)
	if err != nil {
		return err
	}

	egress, _, err := unstructured.NestedSlice(res.Object, "spec", "egress")
	if err != nil {
		return fmt.Errorf("read egress in %s: %w", usageLogsCollectorEgressPolicyName, err)
	}
	egress = append(egress, map[string]any{
		"to": []any{
			map[string]any{
				"ipBlock": map[string]any{
					"cidr":   "0.0.0.0/0",
					"except": []any{"169.254.0.0/16"},
				},
			},
		},
		"ports": []any{
			map[string]any{"protocol": "TCP", "port": port},
		},
	})
	if err := unstructured.SetNestedSlice(res.Object, egress, "spec", "egress"); err != nil {
		return fmt.Errorf("set egress in %s: %w", usageLogsCollectorEgressPolicyName, err)
	}
	return nil
}

// remoteOtlpPort returns the TCP port implied by the endpoint URL.
func remoteOtlpPort(endpoint string) (int64, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return 0, fmt.Errorf("parse remote endpoint %q: %w", endpoint, err)
	}
	if p := u.Port(); p != "" {
		n, err := strconv.ParseInt(p, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("parse port in remote endpoint %q: %w", endpoint, err)
		}
		return n, nil
	}
	if u.Scheme == "http" {
		return 80, nil
	}
	return 443, nil
}

// resolveClusterIdentity determines the cluster_id and cluster_name stamped on
// remote records. Explicit overrides win; otherwise identity is read from ACM's
// ClusterClaim and Klusterlet.
//
// Both lookups are best-effort. On a cluster not managed by ACM neither object
// exists, and the CRDs may not be registered at all, so failures fall through to
// placeholders rather than blocking the export: an attributable-but-unknown
// record is more useful than no record.
func (r *LifecycleReconciler) resolveClusterIdentity(
	ctx context.Context,
	overrides *maasv1alpha1.RemoteOtlpAttributesConfig,
) (clusterID, clusterName string) {
	if overrides != nil {
		clusterID = overrides.ClusterID
		clusterName = overrides.ClusterName
	}

	readClaim := func(name string) string {
		claim := &unstructured.Unstructured{}
		claim.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   "cluster.open-cluster-management.io",
			Version: "v1alpha1",
			Kind:    "ClusterClaim",
		})
		if err := r.Get(ctx, client.ObjectKey{Name: name}, claim); err != nil {
			return ""
		}
		value, found, err := unstructured.NestedString(claim.Object, "spec", "value")
		if err != nil || !found {
			return ""
		}
		return value
	}

	if clusterID == "" {
		clusterID = readClaim("id.k8s.io")
	}

	if clusterName == "" {
		klusterlet := &unstructured.Unstructured{}
		klusterlet.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   "operator.open-cluster-management.io",
			Version: "v1",
			Kind:    "Klusterlet",
		})
		if err := r.Get(ctx, client.ObjectKey{Name: "klusterlet"}, klusterlet); err == nil {
			if value, found, err := unstructured.NestedString(klusterlet.Object, "spec", "clusterName"); err == nil && found {
				clusterName = value
			}
		}
	}
	if clusterName == "" {
		clusterName = readClaim("kubernetes.io/cluster-name")
	}

	if clusterID == "" {
		clusterID = unknownClusterID
	}
	if clusterName == "" {
		clusterName = unknownClusterName
	}
	return clusterID, clusterName
}

// ensureRemoteOtlpTrustedCA creates the ConfigMap that the network operator fills
// with the cluster's trusted CA bundle. It is needed because the usage-logs
// collector mounts the service CA over the system trust path, leaving it unable
// to verify publicly trusted endpoints on its own. Only used when the caller did
// not supply their own caBundleSecret.
func (r *LifecycleReconciler) ensureRemoteOtlpTrustedCA(ctx context.Context, cfg *maasv1alpha1.Config) error {
	cm := &unstructured.Unstructured{}
	cm.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"})
	cm.SetName(remoteOtlpTrustedCAConfigMap)
	cm.SetNamespace(r.MonitoringNamespace)
	// The cluster network operator fills this from a LABEL, not an annotation —
	// unlike the service-CA injector next door, which uses an annotation. Getting
	// the two confused yields an empty ConfigMap and a mount with no ca-bundle.crt.
	cm.SetLabels(map[string]string{
		"app.kubernetes.io/part-of":                   "maas-observability",
		"app.kubernetes.io/managed-by":                "maas-controller",
		"config.openshift.io/inject-trusted-cabundle": "true",
	})
	if err := controllerutil.SetControllerReference(cfg, cm, r.Scheme); err != nil {
		return fmt.Errorf("set controller reference on %s: %w", remoteOtlpTrustedCAConfigMap, err)
	}
	if err := r.Apply(ctx, client.ApplyConfigurationFromUnstructured(cm),
		client.ForceOwnership, client.FieldOwner("maas-controller")); err != nil {
		return fmt.Errorf("apply %s: %w", remoteOtlpTrustedCAConfigMap, err)
	}
	return nil
}

// removeRemoteOtlpTrustedCA deletes the injected trusted-CA ConfigMap. Safe to
// call when it does not exist, which is the common case.
func (r *LifecycleReconciler) removeRemoteOtlpTrustedCA(ctx context.Context) error {
	cm := &unstructured.Unstructured{}
	cm.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"})
	cm.SetName(remoteOtlpTrustedCAConfigMap)
	cm.SetNamespace(r.MonitoringNamespace)
	if err := r.Delete(ctx, cm); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete %s: %w", remoteOtlpTrustedCAConfigMap, err)
	}
	return nil
}

// remoteOtlpHeaderKeys validates the referenced headersSecret and returns its
// sorted key names. Keys are sorted so the rendered collector is stable across
// reconciles and does not churn the object on every apply.
func (r *LifecycleReconciler) remoteOtlpHeaderKeys(
	ctx context.Context,
	remote *maasv1alpha1.RemoteOtlpConfig,
) ([]string, error) {
	secret := &corev1.Secret{}
	key := client.ObjectKey{Namespace: r.MonitoringNamespace, Name: remote.HeadersSecret}
	// Uncached: see APIReader on LifecycleReconciler.
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	if err := reader.Get(ctx, key, secret); err != nil {
		return nil, fmt.Errorf("headersSecret %q in namespace %q: %w",
			remote.HeadersSecret, r.MonitoringNamespace, err)
	}
	if len(secret.Data) == 0 {
		return nil, fmt.Errorf("headersSecret %q contains no data keys", remote.HeadersSecret)
	}
	keys := make([]string, 0, len(secret.Data))
	for k := range secret.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// patchRemoteOtlpExporter adds a second OTLP/HTTP exporter and its own pipeline to
// the rendered usage-logs collector, leaving the spoke-local export untouched.
//
// It follows the same post-render shape as patchTenancyProxyImage: the collector
// is static YAML from the kustomize bundle, so the remote export is layered on
// here rather than expressed in the manifest.
//
// headerKeys are the keys of the referenced Secret, already read and validated by
// the caller. Only the key names are needed: each value is projected as an
// environment variable and referenced as ${env:...}, so no secret material is
// written into the collector spec.
func patchRemoteOtlpExporter(
	res *unstructured.Unstructured,
	remote *maasv1alpha1.RemoteOtlpConfig,
	headerKeys []string,
	clusterID, clusterName string,
) error {
	if res.GetKind() != "OpenTelemetryCollector" || res.GetName() != usageLogsCollectorName {
		return nil
	}

	exporters, found, err := unstructured.NestedMap(res.Object, "spec", "config", "exporters")
	if err != nil || !found {
		return fmt.Errorf("read exporters in %s collector: %w", usageLogsCollectorName, err)
	}
	processors, found, err := unstructured.NestedMap(res.Object, "spec", "config", "processors")
	if err != nil || !found {
		return fmt.Errorf("read processors in %s collector: %w", usageLogsCollectorName, err)
	}
	pipelines, found, err := unstructured.NestedMap(res.Object, "spec", "config", "service", "pipelines")
	if err != nil || !found {
		return fmt.Errorf("read pipelines in %s collector: %w", usageLogsCollectorName, err)
	}

	// Headers reference environment variables rather than carrying values.
	headers := map[string]any{}
	env, _, err := unstructured.NestedSlice(res.Object, "spec", "env")
	if err != nil {
		return fmt.Errorf("read env in %s collector: %w", usageLogsCollectorName, err)
	}
	for _, key := range headerKeys {
		varName := remoteOtlpEnvVarName(key)
		headers[key] = fmt.Sprintf("${env:%s}", varName)
		env = append(env, map[string]any{
			"name": varName,
			"valueFrom": map[string]any{
				"secretKeyRef": map[string]any{
					"name": remote.HeadersSecret,
					"key":  key,
				},
			},
		})
	}
	if err := unstructured.SetNestedSlice(res.Object, env, "spec", "env"); err != nil {
		return fmt.Errorf("set env in %s collector: %w", usageLogsCollectorName, err)
	}

	exporter := map[string]any{
		"endpoint": remote.Endpoint,
		"headers":  headers,
	}

	// Trust for the remote endpoint. The collector mounts the service CA over
	// /etc/pki/ca-trust/extracted/pem, which shadows the image's public bundle, so
	// it cannot verify a publicly trusted endpoint without being given a bundle
	// explicitly. Use the caller's Secret when supplied, otherwise the cluster's
	// injected trusted bundle.
	{
		volumes, _, err := unstructured.NestedSlice(res.Object, "spec", "volumes")
		if err != nil {
			return fmt.Errorf("read volumes in %s collector: %w", usageLogsCollectorName, err)
		}
		caVolume := map[string]any{
			"name":      remoteOtlpCAVolumeName,
			"configMap": map[string]any{"name": remoteOtlpTrustedCAConfigMap},
		}
		if remote.TLS != nil && remote.TLS.CABundleSecret != "" {
			caVolume = map[string]any{
				"name":   remoteOtlpCAVolumeName,
				"secret": map[string]any{"secretName": remote.TLS.CABundleSecret},
			}
		}
		volumes = append(volumes, caVolume)
		if err := unstructured.SetNestedSlice(res.Object, volumes, "spec", "volumes"); err != nil {
			return fmt.Errorf("set volumes in %s collector: %w", usageLogsCollectorName, err)
		}

		mounts, _, err := unstructured.NestedSlice(res.Object, "spec", "volumeMounts")
		if err != nil {
			return fmt.Errorf("read volumeMounts in %s collector: %w", usageLogsCollectorName, err)
		}
		mounts = append(mounts, map[string]any{
			"name":      remoteOtlpCAVolumeName,
			"mountPath": remoteOtlpCAMountPath,
			"readOnly":  true,
		})
		if err := unstructured.SetNestedSlice(res.Object, mounts, "spec", "volumeMounts"); err != nil {
			return fmt.Errorf("set volumeMounts in %s collector: %w", usageLogsCollectorName, err)
		}

		exporter["tls"] = map[string]any{
			"ca_file": fmt.Sprintf("%s/%s", remoteOtlpCAMountPath, remoteOtlpCAKey),
		}
	}

	exporters[remoteOtlpExporterKey] = exporter

	// Cluster identity is stamped by a processor used only by the remote
	// pipeline, so it cannot reach the spoke-local LokiStack.
	//
	// Both actions must be `upsert`, not `insert`. The gateway access log already
	// carries a `cluster_name` resource attribute holding the *Envoy* upstream
	// cluster (e.g. "maas-default-gateway-openshift-default.openshift-ingress"),
	// which has nothing to do with the Kubernetes cluster. `insert` is a no-op on
	// an existing key, so it would leave that value in place and silently
	// misattribute every record on the hub.
	processors[remoteOtlpResourceProcessorKey] = map[string]any{
		"attributes": []any{
			map[string]any{"key": "cluster_id", "value": clusterID, "action": "upsert"},
			map[string]any{"key": "cluster_name", "value": clusterName, "action": "upsert"},
		},
	}

	// The remote pipeline runs the bundle's own `resource` processor as well as
	// `resource/remote`. Without the former, remote records lose log_type,
	// service.name and kubernetes_namespace_name — and log_type is one of the
	// handful of attributes Loki promotes to an index label, so records arrive
	// but the documented query misses them. `resource/remote` stays exclusive to
	// this pipeline so cluster identity never reaches the local write.
	pipelines[remoteOtlpPipelineKey] = map[string]any{
		"receivers":  []any{"otlp"},
		"processors": []any{"memory_limiter", "resource", remoteOtlpResourceProcessorKey, "batch"},
		"exporters":  []any{remoteOtlpExporterKey},
	}

	if err := unstructured.SetNestedMap(res.Object, exporters, "spec", "config", "exporters"); err != nil {
		return fmt.Errorf("set exporters in %s collector: %w", usageLogsCollectorName, err)
	}
	if err := unstructured.SetNestedMap(res.Object, processors, "spec", "config", "processors"); err != nil {
		return fmt.Errorf("set processors in %s collector: %w", usageLogsCollectorName, err)
	}
	if err := unstructured.SetNestedMap(res.Object, pipelines, "spec", "config", "service", "pipelines"); err != nil {
		return fmt.Errorf("set pipelines in %s collector: %w", usageLogsCollectorName, err)
	}
	return nil
}

// tenantsHealthReason enumerates reasons used for ConfigConditionTenantsHealthy.
type tenantsHealthReason string

// Tenant health aggregation reasons (ADR ODH-ADR-MS-0003 three-state model).
const (
	tenantsHealthReasonAllTenantsHealthy tenantsHealthReason = "AllTenantsHealthy"
	tenantsHealthReasonTenantsDegraded   tenantsHealthReason = "TenantsDegraded"
	tenantsHealthReasonTenantsBlocked    tenantsHealthReason = "TenantsBlocked"
	tenantsHealthReasonNoTenantsFound    tenantsHealthReason = "NoTenantsFound"
)

// conditionMessageMaxLen is the maximum length enforced by the Kubernetes condition message
// schema (maxLength: 32768). Messages that exceed this limit are truncated on a valid UTF-8
// rune boundary and suffixed with "…" so the stored value is always within spec.
const conditionMessageMaxLen = 32768

func truncateConditionMessage(msg string) string {
	return truncateMessage(msg, conditionMessageMaxLen)
}

// truncateMessage truncates msg to at most maxLen bytes on a UTF-8 boundary, suffixed with "…".
func truncateMessage(msg string, maxLen int) string {
	if len(msg) <= maxLen {
		return msg
	}
	const suffix = "…"
	limit := maxLen - len(suffix)
	truncated := msg[:limit]
	// Walk back until the prefix is valid UTF-8. This handles both continuation
	// bytes and incomplete leading bytes (e.g. 0xE2 without its two following
	// bytes) that may appear at the truncation boundary.
	for len(truncated) > 0 && !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated + suffix
}

// syncModuleStatus aggregates the Ready condition from the default AITenant and the default
// MaasTenantConfig into Config.Status.Conditions so that the platform operator (DSC) can
// surface configuration errors (e.g. missing gateway, missing postgres secret) without
// watching MaaS operands directly.
func (r *LifecycleReconciler) syncModuleStatus(ctx context.Context, cfg *maasv1alpha1.Config) error {
	if cfg == nil || cfg.UID == "" {
		return nil
	}

	// Fetch the default AITenant.
	var aitenantReady bool
	var aitenantMsg string
	if r.AITenantNamespace != "" {
		aitenantKey := client.ObjectKey{Name: tenantreconcile.DefaultAITenantName, Namespace: r.AITenantNamespace}
		var aitenant maasv1alpha1.AITenant
		switch err := r.Get(ctx, aitenantKey, &aitenant); {
		case err == nil:
			aitenantReady = apimeta.IsStatusConditionTrue(aitenant.Status.Conditions, maasv1alpha1.AITenantConditionReady)
			if !aitenantReady {
				if cond := apimeta.FindStatusCondition(aitenant.Status.Conditions, maasv1alpha1.AITenantConditionReady); cond != nil {
					aitenantMsg = cond.Message
				} else {
					aitenantMsg = fmt.Sprintf("AITenant phase=%s", aitenant.Status.Phase)
				}
			}
		case apierrors.IsNotFound(err):
			aitenantMsg = "default AITenant not yet created"
		default:
			return fmt.Errorf("get default AITenant for module status: %w", err)
		}
	} else {
		aitenantReady = true // AITenant namespace not configured; skip the check.
	}

	// Fetch the default MaasTenantConfig.
	var tenantReady bool
	var tenantMsg string
	if r.TenantSubscriptionNamespace != "" {
		tKey := client.ObjectKey{Name: maasv1alpha1.MaasTenantConfigInstanceName, Namespace: r.TenantSubscriptionNamespace}
		var tenant maasv1alpha1.MaasTenantConfig
		switch err := r.Get(ctx, tKey, &tenant); {
		case err == nil:
			tenantReady = apimeta.IsStatusConditionTrue(tenant.Status.Conditions, tenantreconcile.ReadyConditionType)
			if !tenantReady {
				if cond := apimeta.FindStatusCondition(tenant.Status.Conditions, tenantreconcile.ReadyConditionType); cond != nil {
					tenantMsg = cond.Message
				} else {
					tenantMsg = fmt.Sprintf("MaasTenantConfig phase=%s", tenant.Status.Phase)
				}
			}
		case apierrors.IsNotFound(err):
			tenantMsg = "default MaasTenantConfig not yet created"
		default:
			return fmt.Errorf("get default MaasTenantConfig for module status: %w", err)
		}
	} else {
		tenantReady = true // namespace not configured; skip the check.
	}

	readyStatus := metav1.ConditionTrue
	readyReason := "AllOperandsReady"
	readyMessage := "Default AITenant and tenant configuration are ready"
	if !aitenantReady || !tenantReady {
		readyStatus = metav1.ConditionFalse
		readyReason = "OperandNotReady"
		var parts []string
		if !aitenantReady && aitenantMsg != "" {
			parts = append(parts, "AITenant: "+aitenantMsg)
		}
		if !tenantReady && tenantMsg != "" {
			parts = append(parts, "MaasTenantConfig: "+tenantMsg)
		}
		if len(parts) > 0 {
			readyMessage = truncateConditionMessage(strings.Join(parts, "; "))
		} else {
			readyMessage = "one or more MaaS operands are not ready"
		}
	}

	base := cfg.DeepCopy()
	apimeta.SetStatusCondition(&cfg.Status.Conditions, metav1.Condition{
		Type:               tenantreconcile.ReadyConditionType,
		Status:             readyStatus,
		Reason:             readyReason,
		Message:            readyMessage,
		ObservedGeneration: cfg.Generation,
		LastTransitionTime: metav1.Now(),
	})
	if err := r.Status().Patch(ctx, cfg, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("patch Config status: %w", err)
	}
	return nil
}

// syncTenantsHealth aggregates the Ready condition from all AITenant CRs across the cluster
// into a TenantsHealthy condition on Config.Status using the ADR ODH-ADR-MS-0003 three-state
// model so that the platform operator (ai-gateway-operator / DSC) can observe per-tenant
// health without listing MaaS operands directly.
func (r *LifecycleReconciler) syncTenantsHealth(ctx context.Context, cfg *maasv1alpha1.Config) error {
	if cfg == nil || cfg.UID == "" {
		return nil
	}

	var allTenants maasv1alpha1.AITenantList
	if err := r.List(ctx, &allTenants, client.InNamespace(r.AITenantNamespace)); err != nil {
		return fmt.Errorf("list AITenants for tenant health aggregation: %w", err)
	}

	base := cfg.DeepCopy()

	if len(allTenants.Items) == 0 {
		apimeta.SetStatusCondition(&cfg.Status.Conditions, metav1.Condition{
			Type:               maasv1alpha1.ConfigConditionTenantsHealthy,
			Status:             metav1.ConditionTrue,
			Reason:             string(tenantsHealthReasonNoTenantsFound),
			Message:            "no AITenant resources found",
			ObservedGeneration: cfg.Generation,
		})
		if err := r.Status().Patch(ctx, cfg, client.MergeFrom(base)); err != nil {
			return fmt.Errorf("patch Config TenantsHealthy status: %w", err)
		}
		return nil
	}

	var unhealthy []string
	total := len(allTenants.Items)
	for i := range allTenants.Items {
		at := &allTenants.Items[i]
		if !apimeta.IsStatusConditionTrue(at.Status.Conditions, maasv1alpha1.AITenantConditionReady) {
			unhealthy = append(unhealthy, at.Namespace+"/"+at.Name)
		}
	}

	var cond metav1.Condition
	switch {
	case len(unhealthy) == 0:
		cond = metav1.Condition{
			Type:               maasv1alpha1.ConfigConditionTenantsHealthy,
			Status:             metav1.ConditionTrue,
			Reason:             string(tenantsHealthReasonAllTenantsHealthy),
			Message:            fmt.Sprintf("all %d tenant(s) healthy", total),
			ObservedGeneration: cfg.Generation,
		}
	case len(unhealthy) == total:
		cond = metav1.Condition{
			Type:               maasv1alpha1.ConfigConditionTenantsHealthy,
			Status:             metav1.ConditionFalse,
			Reason:             string(tenantsHealthReasonTenantsBlocked),
			Message:            truncateConditionMessage(fmt.Sprintf("all %d tenant(s) unhealthy: %s", total, formatTenantList(unhealthy, 5))),
			ObservedGeneration: cfg.Generation,
		}
	default:
		cond = metav1.Condition{
			Type:               maasv1alpha1.ConfigConditionTenantsHealthy,
			Status:             metav1.ConditionFalse,
			Reason:             string(tenantsHealthReasonTenantsDegraded),
			Message:            truncateConditionMessage(fmt.Sprintf("%d of %d tenant(s) unhealthy: %s", len(unhealthy), total, formatTenantList(unhealthy, 5))),
			ObservedGeneration: cfg.Generation,
		}
	}

	apimeta.SetStatusCondition(&cfg.Status.Conditions, cond)
	if err := r.Status().Patch(ctx, cfg, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("patch Config TenantsHealthy status: %w", err)
	}
	return nil
}

func formatTenantList(tenants []string, maxItems int) string {
	if len(tenants) <= maxItems {
		return strings.Join(tenants, ", ")
	}
	return strings.Join(tenants[:maxItems], ", ") + fmt.Sprintf(" (and %d more)", len(tenants)-maxItems)
}

// SetupWithManager registers the controller to watch only the maas-controller Deployment.
func (r *LifecycleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	selfOnly := predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetName() == r.DeploymentName && o.GetNamespace() == r.DeploymentNS
	})
	cfgSingleton := predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetName() == maasv1alpha1.ConfigInstanceName
	})
	defaultTenant := predicate.NewPredicateFuncs(func(o client.Object) bool {
		if r.TenantSubscriptionNamespace == "" {
			return false
		}
		return o.GetNamespace() == r.TenantSubscriptionNamespace && o.GetName() == maasv1alpha1.MaasTenantConfigInstanceName
	})
	// Watch all AITenants so that both the default tenant link
	// (ensureDefaultAITenantReferencesConfig) and the cross-tenant health
	// aggregation (syncTenantsHealth) stay current.

	return ctrl.NewControllerManagedBy(mgr).
		For(&appsv1.Deployment{}, builder.WithPredicates(selfOnly)).
		Watches(
			&maasv1alpha1.Config{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, _ client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{
					Namespace: r.DeploymentNS,
					Name:      r.DeploymentName,
				}}}
			}),
			builder.WithPredicates(cfgSingleton),
		).
		Watches(
			&maasv1alpha1.MaasTenantConfig{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, _ client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{
					Namespace: r.DeploymentNS,
					Name:      r.DeploymentName,
				}}}
			}),
			builder.WithPredicates(defaultTenant),
		).
		Watches(
			&maasv1alpha1.AITenant{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, _ client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{
					Namespace: r.DeploymentNS,
					Name:      r.DeploymentName,
				}}}
			}),
			builder.WithPredicates(aitenantReadyChanged()),
		).
		// Re-reconcile when optional operator CRDs (e.g. Perses from COO) are installed
		// so that resources previously skipped due to missing CRDs are applied immediately.
		// Metadata-only: avoids caching full CRD objects (50–200KB each with OpenAPI schemas).
		WatchesMetadata(
			crdPartialMetadata(),
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, _ client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{
					Namespace: r.DeploymentNS,
					Name:      r.DeploymentName,
				}}}
			}),
			builder.WithPredicates(crdInOptionalAPIGroup()),
		).
		// Watch managed usage-log resources so deletions/modifications trigger reconciliation
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, _ client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{
					Namespace: r.DeploymentNS,
					Name:      r.DeploymentName,
				}}}
			}),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(o client.Object) bool {
				return o.GetNamespace() == r.MonitoringNamespace &&
					o.GetLabels()["app.kubernetes.io/managed-by"] == "maas-controller"
			})),
		).
		Watches(
			&rbacv1.ClusterRoleBinding{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, _ client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{
					Namespace: r.DeploymentNS,
					Name:      r.DeploymentName,
				}}}
			}),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(o client.Object) bool {
				return o.GetLabels()["app.kubernetes.io/managed-by"] == "maas-controller"
			})),
		).
		Watches(
			&netwv1.NetworkPolicy{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, _ client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{
					Namespace: r.DeploymentNS,
					Name:      r.DeploymentName,
				}}}
			}),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(o client.Object) bool {
				return o.GetNamespace() == r.MonitoringNamespace &&
					o.GetLabels()["app.kubernetes.io/managed-by"] == "maas-controller"
			})),
		).
		// Watch maas-discovery Deployment for reconvergence on external changes
		Watches(
			&appsv1.Deployment{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, _ client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{
					Namespace: r.DeploymentNS,
					Name:      r.DeploymentName,
				}}}
			}),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(o client.Object) bool {
				discoveryNS := r.DiscoveryNamespace
				if discoveryNS == "" {
					discoveryNS = r.DeploymentNS
				}
				return o.GetName() == discoveryDeploymentName && o.GetNamespace() == discoveryNS
			})),
		).
		Complete(r)
}

// aitenantReadyChanged admits an AITenant event only when the Ready condition
// status changes or generation changes. Create, Delete, and Generic events pass
// by default so that adding or removing a tenant re-runs health aggregation.
func aitenantReadyChanged() predicate.Predicate {
	readyStatus := func(o client.Object) metav1.ConditionStatus {
		at, ok := o.(*maasv1alpha1.AITenant)
		if !ok {
			return metav1.ConditionUnknown
		}
		if cond := apimeta.FindStatusCondition(at.Status.Conditions, maasv1alpha1.AITenantConditionReady); cond != nil {
			return cond.Status
		}
		return metav1.ConditionUnknown
	}
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			if e.ObjectOld == nil || e.ObjectNew == nil {
				return false
			}
			if readyStatus(e.ObjectOld) != readyStatus(e.ObjectNew) {
				return true
			}
			return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()
		},
	}
}

// crdInOptionalAPIGroup matches CRDs belonging to optional platform operator API groups
// (e.g. perses.dev from COO). CRD names follow the pattern "<plural>.<group>", so a
// suffix check is sufficient to identify the group without parsing the spec.
func crdInOptionalAPIGroup() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(o client.Object) bool {
		for group := range OptionalAPIGroups {
			if strings.HasSuffix(o.GetName(), "."+group) {
				return true
			}
		}
		return false
	})
}
