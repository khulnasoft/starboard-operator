package api

import (
	"strings"

	"github.com/khulnasoft/starboard-operator/pkg/khulnasoft/client"
	"github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
)

const (
	adHocScansRegistry = "Ad Hoc Scans"
)

type Scanner struct {
	clientset client.Clientset
}

func NewScanner(clientset client.Clientset) *Scanner {
	return &Scanner{
		clientset: clientset,
	}
}

func (s *Scanner) Scan(imageRef string) (v1alpha1.VulnerabilityScanResult, error) {
	registries, err := s.clientset.Registries().List()
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}

	var registryName string
	for _, r := range registries {
		for _, p := range r.Prefixes {
			if strings.HasPrefix(imageRef, p) {
				registryName = r.Name
				break
			}
		}
	}

	if registryName == "" {
		// Fallback to ad hoc scans registry
		registryName = adHocScansRegistry
	}

	reference, err := name.ParseReference(imageRef)
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}

	vulnerabilities, err := s.clientset.Images().Vulnerabilities(registryName, reference.Context().RepositoryStr(), reference.Identifier())
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}

	return s.convert(reference, vulnerabilities)
}

func (s *Scanner) convert(ref name.Reference, response client.VulnerabilitiesResponse) (v1alpha1.VulnerabilityScanResult, error) {
	items := make([]v1alpha1.Vulnerability, 0)

	for _, result := range response.Results {
		items = append(items, v1alpha1.Vulnerability{
			VulnerabilityID:  result.Name,
			Resource:         result.Resource.Name,
			InstalledVersion: result.Resource.Version,
			Severity:         s.toSeverity(result),
			FixedVersion:     result.FixVersion,
			Description:      result.Description,
			Links:            []string{},
		})
	}

	artifact := v1alpha1.Artifact{
		Repository: ref.Context().RepositoryStr(),
	}
	switch t := ref.(type) {
	case name.Tag:
		artifact.Tag = t.TagStr()
	case name.Digest:
		artifact.Digest = t.DigestStr()
	}

	return v1alpha1.VulnerabilityScanResult{
		Scanner: v1alpha1.Scanner{
			Name:    "Khulnasoft CSP",
			Version: "Khulnasoft Security",
		},
		Registry: v1alpha1.Registry{
			Server: ref.Context().RegistryStr(),
		},
		Artifact:        artifact,
		Summary:         s.toSummary(items),
		Vulnerabilities: items,
	}, nil
}

// TODO we have the same method for parsing scannercli output
func (s *Scanner) toSeverity(v client.VulnerabilitiesResponseResult) v1alpha1.Severity {
	switch severity := v.KhulnasoftSeverity; severity {
	case "critical":
		return v1alpha1.SeverityCritical
	case "high":
		return v1alpha1.SeverityHigh
	case "medium":
		return v1alpha1.SeverityMedium
	case "low":
		return v1alpha1.SeverityLow
	case "negligible":
		// TODO We should have severity None defined in k8s-security-crds
		return v1alpha1.SeverityUnknown
	default:
		return v1alpha1.SeverityUnknown
	}
}

func (s *Scanner) toSummary(items []v1alpha1.Vulnerability) v1alpha1.VulnerabilitySummary {
	summary := v1alpha1.VulnerabilitySummary{}
	for _, item := range items {
		switch item.Severity {
		case v1alpha1.SeverityCritical:
			summary.CriticalCount++
		case v1alpha1.SeverityHigh:
			summary.HighCount++
		case v1alpha1.SeverityMedium:
			summary.MediumCount++
		case v1alpha1.SeverityLow:
			summary.LowCount++
		default:
			summary.UnknownCount++
		}
	}
	return summary
}
