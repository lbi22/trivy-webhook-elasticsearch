package tools

import "github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"

func GetVulnScore(d v1alpha1.Vulnerability) float64 {
	if d.Score != nil {
		return *d.Score
	}
	return 0.0
}


.github	
	workflows
		pre-release.yml
		release.yml
charts
	trivy-webhook-elasticsearch
		templates
			_helpers.templates
			deployments.yaml
			hpa.yaml
			service.yaml
			serviceaccount.yaml
		Chart.yaml
		readme.Methods
		values.yaml
tools
	main.go
.gitignore
Dockerfile
go.mod 
go.sum 
main.go
read.me
