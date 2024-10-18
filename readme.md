# Trivy Webhook Elasticsearch

This application processes vulnerability reports from Trivy, a vulnerability scanning tool for containers, and imports the findings into an Elasticsearch index. It acts as a webhook receiver that listens for vulnerability reports sent by Trivy and processes them before forwarding the results to Elasticsearch.

## Features

- Receives vulnerability reports via an HTTP POST request.
- Supports importing CVE findings into an Elasticsearch index.
- Designed for integration with container image scanning.
- Logs and reports errors for easier troubleshooting.

## How It Works

1. **Vulnerability Report**: The application listens for incoming vulnerability reports in JSON format from Trivy via a `/webhook` endpoint.
2. **Validation**: The incoming report is validated to ensure it's of type `VulnerabilityReport`, and only then are the vulnerabilities processed.
3. **Elasticsearch Integration**: Vulnerabilities are indexed into the specified Elasticsearch index for further analysis and visualization.
4. **Health Check**: The `/healthz` endpoint provides a simple health check for the application.

## Prerequisites

- **Elasticsearch**: You must have access to an Elasticsearch instance with the appropriate credentials (username, password, and endpoint).
- **Trivy**: You must set up Trivy to scan container images and send reports to the webhook endpoint.
- **Go**: The application is written in Go, so you'll need Go installed to build and run it.

## Setup and Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/lbi22/trivy-webhook-elasticsearch.git
   cd trivy-webhook-elasticsearch

2. **Build the application**:

   Make sure Go is installed and set up correctly:
   ```bash
   git clone https://github.com/lbi22/trivy-webhook-elasticsearch.git
   cd trivy-webhook-elasticsearch

3. **Run the application**:

    You can start the application locally:
    ```bash
    Copy code
    ./trivy-webhook-elasticsearch
    The server will start and listen on port 8080.

4. **Set up Trivy**:

    Configure Trivy to send vulnerability reports to the /webhook endpoint of the running application.

    Example Trivy command:

    ```bash
    Copy code
    trivy image --format json --output result.json <image>
    curl -X POST -H "Content-Type: application/json" --data @result.json http://localhost:8080/webhook

## Environment Variables

You can configure Elasticsearch credentials using the following environment variables:

- `ELASTICSEARCH_ENDPOINT`: The Elasticsearch endpoint.
- `ELASTICSEARCH_USERNAME`: The Elasticsearch username.
- `ELASTICSEARCH_PASSWORD`: The Elasticsearch password.

These are automatically loaded by the Go application to connect to Elasticsearch.

## API Endpoints

- **POST** `/webhook`: Receives vulnerability reports in JSON format. Only processes reports of type `VulnerabilityReport` and indexes CVE findings to Elasticsearch.
- **GET** `/healthz`: Health check endpoint that returns a simple `OK` response.

## Example Vulnerability Report (from Trivy)

```json
{
  "kind": "VulnerabilityReport",
  "metadata": {
    "name": "example",
    "labels": {
      "trivy-operator.container.name": "example-container"
    }
  },
  "report": {
    "registry": {
      "server": "docker.io"
    },
    "artifact": {
      "repository": "library/nginx",
      "digest": "sha256:exampledigest"
    },
    "vulnerabilities": [
      {
        "vulnerabilityID": "CVE-2021-12345",
        "title": "Example Vulnerability",
        "severity": "HIGH",
        "resource": "nginx",
        "installedVersion": "1.18.0",
        "fixedVersion": "1.19.0",
        "primaryLink": "https://example.com/CVE-2021-12345"
      }
    ]
  }
}
```
## Helm Chart

This application includes a Helm Chart to simplify deployment to Kubernetes. You can find the chart in the `charts/` directory.

### Install the Helm Chart

1. Ensure Helm is installed on your system.
2. Use the provided chart to install the application:

   ```bash
   helm install trivy-webhook charts/trivy-webhook-elasticsearch

## Contributing

We welcome contributions! To contribute, follow these steps:

1. Fork the repository.
2. Create a new feature branch: `git checkout -b my-feature`.
3. Commit your changes: `git commit -m 'Add my feature'`.
4. Push to the branch: `git push origin my-feature`.
5. Create a new pull request.

## License

This project is licensed under the GNU General Public License v3.0 License - see the [LICENSE](LICENSE) file for details.

