# Trivy Webhook for Elasticsearch

This application integrates [Trivy](https://github.com/aquasecurity/trivy), a popular container vulnerability scanning tool, with [Elasticsearch](https://www.elastic.co/). It acts as a webhook receiver that listens for vulnerability reports sent by Trivy and imports the findings into an Elasticsearch index, enabling centralized vulnerability management for container images.

## Features
- **Webhook Receiver**: Accepts vulnerability reports in JSON format from Trivy.
- **Elasticsearch Integration**: Automatically indexes container vulnerabilities into Elasticsearch for analysis and visualization.
- **Seamless Kubernetes Integration**: Works with the Trivy Operator in Kubernetes for automated vulnerability scans.

## Prerequisites
- Access to an Elasticsearch instance with a valid username, password, and endpoint.
- Kubernetes cluster with [Trivy Operator](https://github.com/aquasecurity/trivy-operator) installed.
- [Helm](https://helm.sh/) installed for deployment.
  
## How to Install
Add the Helm repository:

```bash
helm repo add trivy-webhook-elasticsearch https://lbi22.github.io/trivy-webhook-elasticsearch/
```
## Parameters

### Common Parameters

| Name                                         | Description                                                                                                         | Value                                               |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `replicaCount`                               | Number of webhook replicas                                                                                          | `1`                                                 |
| `image.repository`                           | The repository to use for the webhook image.                                                                        | `ghcr.io/lbi22/trivy-webhook-elasticsearch`         |
| `image.pullPolicy`                           | The pull policy to use for the image.                                                                               | `IfNotPresent`                                      |
| `image.tag`                                  | The webhook image tag. Defaults to the chart's AppVersion.                                                          | `""`                                                |
| `imagePullSecrets`                           | A list of image pull secrets for the container image.                                                               | `[]`                                                |
| `nameOverride`                               | Override for the name of the Helm release.                                                                          | `""`                                                |
| `fullnameOverride`                           | Override for the full name of the Helm release.                                                                     | `""`                                                |
| `elasticsearch.endpoint`                     | The Elasticsearch endpoint where vulnerability findings will be indexed.                                            | `"http://localhost:9200"`                           |
| `elasticsearch.username`                     | The username for Elasticsearch authentication.                                                                      | `""`                                                |
| `elasticsearch.password`                     | The password for Elasticsearch authentication.                                                                      | `""`                                                |
| `elasticsearch.fieldsToPush`                     | Extra fieds and value that you might want to add to Elasticsearch                                                                     | `{}`                                                |
| `podAnnotations`                             | Add extra annotations to the webhook pod(s).                                                                        | `{}`                                                |
| `podLabels`                                  | Add custom labels to the webhook pod(s).                                                                            | `{}`                                                |
| `podSecurityContext`                         | Add extra podSecurityContext to the webhook pod(s).                                                                 | `{}`                                                |
| `securityContext`                            | Add extra securityContext to the webhook pod(s).                                                                    | `{}`                                                |
| `service.type`                               | Service type to expose the webhook.                                                                                 | `ClusterIP`                                         |
| `service.port`                               | Port number to expose the webhook service.                                                                          | `80`                                                |
| `resources.limits`                           | The resources limits for the webhook container.                                                                     | `{}`                                                |
| `resources.requests`                         | The requested resources for the webhook container.                                                                  | `{}`                                                |
| `livenessProbe.httpGet.path`                 | Path for the liveness probe HTTP GET request.                                                                       | `/healthz`                                          |
| `livenessProbe.httpGet.port`                 | Port for the liveness probe HTTP GET request.                                                                       | `http`                                              |
| `readinessProbe.httpGet.path`                | Path for the readiness probe HTTP GET request.                                                                      | `/healthz`                                          |
| `readinessProbe.httpGet.port`                | Port for the readiness probe HTTP GET request.                                                                      | `http`                                              |
| `autoscaling.enabled`                        | Enable or disable autoscaling.                                                                                      | `false`                                             |
| `autoscaling.minReplicas`                    | Minimum number of replicas for autoscaling.                                                                         | `1`                                                 |
| `autoscaling.maxReplicas`                    | Maximum number of replicas for autoscaling.                                                                         | `2`                                                 |
| `autoscaling.targetCPUUtilizationPercentage` | Target CPU utilization percentage for autoscaling.                                                                  | `80`                                                |
| `volumes`                                    | Additional volumes to be mounted on the webhook pods.                                                               | `[]`                                                |
| `volumeMounts`                               | Additional volume mounts for the webhook containers.                                                                | `[]`                                                |
| `nodeSelector`                               | Node selector for pod placement.                                                                                    | `{}`                                                |
| `tolerations`                                | Tolerations for pods.                                                                                               | `[]`                                                |
| `affinity`                                   | Affinity rules for pod placement.                                                                                   | `{}`                                                |

## Setting Up Trivy Operator

To send vulnerability reports from the Trivy Operator to the webhook, configure the following setting in the `trivy-operator` Helm chart:

```bash
--set operator.webhookBroadcastURL=http://<service-name>.<namespace>/webhook
```
Example:

```bash
--set operator.webhookBroadcastURL=http://trivy-webhook-elasticsearch.default/webhook
```
This ensures that the Trivy Operator sends its scan results to the Trivy webhook, which will then process and forward them to Elasticsearch.

## How It Works

1. **Trivy Scan**: Trivy scans container images for vulnerabilities.
2. **Webhook**: The Trivy Operator sends the scan report to the Trivy Webhook via the `/webhook` endpoint.
3. **Elasticsearch**: The webhook processes the report and indexes the findings into Elasticsearch, enabling centralized vulnerability management.

## Customization

You can customize various parameters of the Helm chart, such as:
- **Elasticsearch settings** for endpoint, username, and password.
- **Replicas** to scale the webhook deployment.
- **Resource requests and limits** for container sizing.

For a full list of configurable values, refer to the `values.yaml` file in the Helm chart.

## License

This project is licensed under the GNU General Public License v3.0.

