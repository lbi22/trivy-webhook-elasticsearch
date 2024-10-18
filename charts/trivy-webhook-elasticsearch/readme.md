
# Trivy Webhook for AWS Security Hub

This application integrates [Trivy](https://github.com/aquasecurity/trivy), a popular container vulnerability scanning tool, with [AWS Security Hub](https://aws.amazon.com/security-hub/). It acts as a webhook receiver that listens for vulnerability reports sent by Trivy and imports the findings into AWS Security Hub, enabling centralized vulnerability management for container images in your AWS environment.

## Features
- **Webhook Receiver**: Accepts vulnerability reports in JSON format from Trivy.
- **AWS Security Hub Integration**: Automatically imports container vulnerabilities as findings into AWS Security Hub.
- **Seamless Kubernetes Integration**: Works with the Trivy Operator in Kubernetes for automated vulnerability scans.

## Prerequisites
- AWS account with [Security Hub](https://aws.amazon.com/security-hub/) enabled.
- Kubernetes cluster with [Trivy Operator](https://github.com/aquasecurity/trivy-operator) installed.
- [Helm](https://helm.sh/) installed for deployment.
- IAM role created with access to AWS Security Hub or set the AWS env Variables.

## How to Install
Add the Helm repository:

```bash
helm repo add trivy-webhook-elasticsearch https://lbi22.github.io/trivy-webhook-elasticsearch/
```

Install the Helm chart:

```bash
helm install trivy-webhook trivy-webhook-elasticsearch/trivy-webhook-elasticsearch \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"="arn:aws:iam::xxx:role/trivy-webhook-elasticsearch-role"
```

- Replace `arn:aws:iam::xxx:role/trivy-webhook-elasticsearch-role` with your actual IAM role ARN.
- The IAM role should have permissions to write findings into AWS Security Hub.

### Explanation:
- The `serviceAccount.annotations` sets the necessary IAM role for the service to access AWS resources securely.
- By specifying `eks.amazonaws.com/role-arn`, the Trivy webhook can assume the specified IAM role and import vulnerability findings into Security Hub.

## Parameters

### Common Parameters

| Name                                         | Description                                                                                                         | Value                                               |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `replicaCount`                               | Number of secret-sync replicas                                                                                      | `1`                                                 |
| `image.repository`                           | The repository to use for the secret-sync image.                                                                    | `ghcr.io/lbi22/trivy-webhook-elasticsearch` |
| `image.pullPolicy`                           | The pull policy to use for the secret-sync image.                                                                   | `IfNotPresent`                                      |
| `image.tag`                                  | The secret-sync image tag. Defaults to the chart's AppVersion.                                                      | `""`                                                |
| `imagePullSecrets`                           | A list of image pull secrets for the container image.                                                               | `[]`                                                |
| `nameOverride`                               | Override for the name of the Helm release.                                                                          | `""`                                                |
| `fullnameOverride`                           | Override for the full name of the Helm release.                                                                     | `""`                                                |
| `serviceAccount.annotations`                 | Annotations for service account. Evaluated as a template. Only used if `create` is `true`.                          | `{}`                                                |
| `serviceAccount.create`                      | Specifies whether a ServiceAccount should be created.                                                               | `true`                                              |
| `serviceAccount.automount`                   | Specifies whether the ServiceAccount should auto-mount API credentials.                                             | `true`                                              |
| `serviceAccount.name`                        | Name of the service account to use. If not set and create is true, a name is generated using the fullname template. | `""`                                                |
| `podAnnotations`                             | Add extra annotations to the secret-sync pod(s).                                                                    | `{}`                                                |
| `podLabels`                                  | Add custom labels to the secret-sync pod(s).                                                                        | `{}`                                                |
| `podSecurityContext`                         | Add extra podSecurityContext to the secret-sync pod(s).                                                             | `{}`                                                |
| `securityContext`                            | Add extra securityContext to the secret-sync pod(s).                                                                | `{}`                                                |
| `service.type`                               | Service type to expose the secret-sync.                                                                             | `ClusterIP`                                         |
| `service.port`                               | Port number to expose the secret-sync service.                                                                      | `80`                                                |
| `resources.limits`                           | The resources limits for the secret-sync container.                                                                 | `{}`                                                |
| `resources.requests`                         | The requested resources for the secret-sync container.                                                              | `{}`                                                |
| `livenessProbe.httpGet.path`                 | Path for the liveness probe HTTP GET request.                                                                       | `/healthz`                                          |
| `livenessProbe.httpGet.port`                 | Port for the liveness probe HTTP GET request.                                                                       | `http`                                              |
| `readinessProbe.httpGet.path`                | Path for the readiness probe HTTP GET request.                                                                      | `/healthz`                                          |
| `readinessProbe.httpGet.port`                | Port for the readiness probe HTTP GET request.                                                                      | `http`                                              |
| `autoscaling.enabled`                        | Enable or disable autoscaling.                                                                                      | `false`                                             |
| `autoscaling.minReplicas`                    | Minimum number of replicas for autoscaling.                                                                         | `1`                                                 |
| `autoscaling.maxReplicas`                    | Maximum number of replicas for autoscaling.                                                                         | `2`                                                 |
| `autoscaling.targetCPUUtilizationPercentage` | Target CPU utilization percentage for autoscaling.                                                                  | `80`                                                |
| `volumes`                                    | Additional volumes to be mounted on the secret-sync pods.                                                           | `[]`                                                |
| `volumeMounts`                               | Additional volume mounts for the secret-sync containers.                                                            | `[]`                                                |
| `nodeSelector`                               | Node selector for pod placement.                                                                                    | `{}`                                                |
| `tolerations`                                | Tolerations for pods.                                                                                               | `[]`                                                |
| `affinity`                                   | Affinity rules for pod placement.                                                                                   | `{}`                                                |

## Setting Up Trivy Operator

To send vulnerability reports from the Trivy Operator to the webhook, configure the following setting in the `trivy-operator` Helm chart:

```bash
--set operator.webhookBroadcastURL=http://<service-name>.<namespace>/trivy-webhook
```

Example:

```bash
--set operator.webhookBroadcastURL=http://trivy-webhook-elasticsearch.default/trivy-webhook
```

This ensures that the Trivy Operator sends its scan results to the Trivy webhook, which will then process and forward them to AWS Security Hub.

## How It Works

1. **Trivy Scan**: Trivy scans container images for vulnerabilities.
2. **Webhook**: The Trivy Operator sends the scan report to the Trivy Webhook via the `/trivy-webhook` endpoint.
3. **AWS Security Hub**: The webhook processes the report and imports the findings into AWS Security Hub, enabling centralized vulnerability management.

## Customization

You can customize various parameters of the Helm chart, such as:
- **ServiceAccount annotations** for IAM role-based access.
- **Replicas** to scale the webhook deployment.
- **Resource requests and limits** for container sizing.

For a full list of configurable values, refer to the `values.yaml` file in the Helm chart.

## License

This project is licensed under the GNU General Public License v3.0.
