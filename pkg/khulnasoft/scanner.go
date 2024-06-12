package khulnasoft

import (
	"encoding/json"
	"fmt"
	"io"

	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft/starboard/pkg/scanners"

	"github.com/google/uuid"

	"github.com/khulnasoft/starboard-operator/pkg/scanner"

	"github.com/khulnasoft/starboard-operator/pkg/etc"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
)

const (
	secretName = "starboard-operator"
)

type khulnasoftScanner struct {
	version etc.VersionInfo
	config  etc.ScannerKhulnasoftCSP
}

func NewScanner(version etc.VersionInfo, config etc.ScannerKhulnasoftCSP) scanner.VulnerabilityScanner {
	return &khulnasoftScanner{
		version: version,
		config:  config,
	}
}

func (s *khulnasoftScanner) NewScanJob(meta scanner.JobMeta, options scanner.Options, spec corev1.PodSpec) (*batchv1.Job, error) {
	jobName := uuid.New().String()
	initContainerName := jobName

	scanJobContainers := make([]corev1.Container, len(spec.Containers))
	for i, container := range spec.Containers {
		scanJobContainers[i] = s.newScanJobContainer(container)
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        jobName,
			Namespace:   options.Namespace,
			Labels:      meta.Labels,
			Annotations: meta.Annotations,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: scanners.GetActiveDeadlineSeconds(options.ScanJobTimeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      meta.Labels,
					Annotations: meta.Annotations,
				},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyNever,
					ServiceAccountName:           options.ServiceAccountName,
					AutomountServiceAccountToken: pointer.BoolPtr(false),
					NodeName:                     spec.NodeName,
					Volumes: []corev1.Volume{
						{
							Name: "scannercli",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
						{
							Name: "dockersock",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/run/docker.sock",
								},
							},
						},
					},
					InitContainers: []corev1.Container{
						{
							Name:  initContainerName,
							Image: s.config.ImageRef,
							Command: []string{
								"cp",
								"/opt/khulnasoft/scannercli",
								"/downloads/scannercli",
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "scannercli",
									MountPath: "/downloads",
								},
							},
						},
					},
					Containers: scanJobContainers,
				},
			},
		},
	}, nil
}

func (s *khulnasoftScanner) newScanJobContainer(podContainer corev1.Container) corev1.Container {
	return corev1.Container{
		Name:            podContainer.Name,
		Image:           fmt.Sprintf("khulnasoft/starboard-scanner-khulnasoft:%s", s.version.Version),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command: []string{
			"/bin/sh",
			"-c",
			fmt.Sprintf("/usr/local/bin/scanner --host $(OPERATOR_SCANNER_KHULNASOFT_CSP_HOST) --user $(OPERATOR_SCANNER_KHULNASOFT_CSP_USERNAME) --password $(OPERATOR_SCANNER_KHULNASOFT_CSP_PASSWORD) %s 2> %s",
				podContainer.Image,
				corev1.TerminationMessagePathDefault),
		},
		Env: []corev1.EnvVar{
			{
				Name: "OPERATOR_SCANNER_KHULNASOFT_CSP_HOST",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secretName,
						},
						Key: "OPERATOR_SCANNER_KHULNASOFT_CSP_HOST",
					},
				},
			},
			{
				Name: "OPERATOR_SCANNER_KHULNASOFT_CSP_USERNAME",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secretName,
						},
						Key: "OPERATOR_SCANNER_KHULNASOFT_CSP_USERNAME",
					},
				},
			},
			{
				Name: "OPERATOR_SCANNER_KHULNASOFT_CSP_PASSWORD",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secretName,
						},
						Key: "OPERATOR_SCANNER_KHULNASOFT_CSP_PASSWORD",
					},
				},
			},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("100M"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("500M"),
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "scannercli",
				MountPath: "/usr/local/bin/scannercli",
				SubPath:   "scannercli",
			},
			{
				Name:      "dockersock",
				MountPath: "/var/run/docker.sock",
			},
		},
	}
}

func (s *khulnasoftScanner) ParseVulnerabilityScanResult(_ string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityScanResult, error) {
	var report v1alpha1.VulnerabilityScanResult
	err := json.NewDecoder(logsReader).Decode(&report)
	return report, err
}
