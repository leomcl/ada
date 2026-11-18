// Sandbox types are copied from sigs.k8s.io/agent-sandbox/api/v1beta1 to avoid pulling in controller-runtime.
package sandbox

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	GroupName   = "agents.x-k8s.io"
	Version     = "v1beta1"
	SandboxKind = "Sandbox"
)

var (
	SandboxGroupVersion = schema.GroupVersion{Group: GroupName, Version: Version}
	SandboxGVR          = SandboxGroupVersion.WithResource("sandboxes")
)

type ConditionType string

const (
	SandboxConditionReady ConditionType = "Ready"

	SandboxReasonPodSucceeded         = "PodSucceeded"
	SandboxReasonPodFailed            = "PodFailed"
	SandboxReasonInvalidConfiguration = "InvalidConfiguration"
	SandboxReasonExpired              = "SandboxExpired"
)

type SandboxOperatingMode string

const (
	SandboxOperatingModeRunning SandboxOperatingMode = "Running"
)

type ShutdownPolicy string

const (
	ShutdownPolicyDelete ShutdownPolicy = "Delete"
)

type PodMetadata struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type PodTemplate struct {
	Spec       corev1.PodSpec `json:"spec"`
	ObjectMeta PodMetadata    `json:"metadata,omitempty"`
}

type Lifecycle struct {
	ShutdownTime   *metav1.Time    `json:"shutdownTime,omitempty"`
	ShutdownPolicy *ShutdownPolicy `json:"shutdownPolicy,omitempty"`
}

type SandboxBlueprint struct {
	PodTemplate PodTemplate `json:"podTemplate"`
}

type SandboxSpec struct {
	SandboxBlueprint `json:",inline"`
	Lifecycle        `json:",inline"`
	OperatingMode    SandboxOperatingMode `json:"operatingMode,omitempty"`
}

type SandboxStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

type Sandbox struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`
	Spec              SandboxSpec   `json:"spec"`
	Status            SandboxStatus `json:"status,omitempty,omitzero"`
}
