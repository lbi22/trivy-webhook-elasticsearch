package tools

import "github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"

func GetVulnScore(d v1alpha1.Vulnerability) float64 {
	if d.Score != nil {
		return *d.Score
	}
	return 0.0
}
