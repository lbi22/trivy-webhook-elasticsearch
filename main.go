package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/lbi22/trivy-webhook-elasticsearch/tools"
	"github.com/gorilla/mux"
	"github.com/elastic/go-elasticsearch/v8"
    "github.com/elastic/go-elasticsearch/v8/esapi"
)

type webhook struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
}

// ProcessTrivyWebhook processes incoming vulnerability reports
func ProcessTrivyWebhook(w http.ResponseWriter, r *http.Request) {
	var report webhook

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		log.Printf("Error reading request body: %v", err)
		return
	}

	// Validate request body is not empty
	if len(body) == 0 {
		http.Error(w, "Empty request body", http.StatusBadRequest)
		log.Printf("Empty request body")
		return
	}

	// Decode JSON
	err = json.Unmarshal(body, &report)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		log.Printf("Error decoding JSON: %v", err)
		return
	}

	var findings []types.AwsSecurityFinding
	switch report.Kind {
	case "ConfigAuditReport":
		findings, err = getConfigAuditReportFindings(body)
		if err != nil {
			http.Error(w, "Error processing report", http.StatusInternalServerError)
			log.Printf("Error processing report: %v", err)
			return
		}
	case "InfraAssessmentReport":
		findings, err = getInfraAssessmentReport(body)
		if err != nil {
			http.Error(w, "Error processing report", http.StatusInternalServerError)
			log.Printf("Error processing report: %v", err)
			return
		}
	case "ClusterComplianceReport":
		findings, err = getClusterComplianceReport(body)
		if err != nil {
			http.Error(w, "Error processing report", http.StatusInternalServerError)
			log.Printf("Error processing report: %v", err)
			return
		}
	case "VulnerabilityReport":
		findings, err = getVulnerabilityReportFindings(body)
		if err != nil {
			http.Error(w, "Error processing report", http.StatusInternalServerError)
			log.Printf("Error processing report: %v", err)
			return
		}
	default: // Unknown report type
		http.Error(w, "unknown report type", http.StatusBadRequest)
		log.Printf("unknown report type: %s", report.Kind)
		return
	}

	//send findings to security hub
	err = importFindingsToSecurityHub(findings)
	if err != nil {
		http.Error(w, "Error importing findings to Security Hub", http.StatusInternalServerError)
		log.Printf("Error importing findings to Security Hub: %v", err)
		return
	}

	// Return a success response
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte("Vulnerabilities processed and imported to Security Hub"))
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}

}

func createElasticsearchClient(endpoint, username, password string) (*elasticsearch.Client, error) {
    cfg := elasticsearch.Config{
        Addresses: []string{
            endpoint,
        },
        Username: username,
        Password: password,
    }

    es, err := elasticsearch.NewClient(cfg)
    if err != nil {
        return nil, err
    }

    // Ping Elasticsearch to verify connection
    res, err := es.Ping()
    if err != nil || res.StatusCode != 200 {
        return nil, fmt.Errorf("Failed to connect to Elasticsearch: %v", err)
    }

    return es, nil
}

func handleTrivyReport(w http.ResponseWriter, r *http.Request, es *elasticsearch.Client) {
    var report v1alpha1.VulnerabilityReport
    if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Convert the report to JSON for Elasticsearch
    reportData, err := json.Marshal(report)
    if err != nil {
        http.Error(w, "Failed to serialize report", http.StatusInternalServerError)
        return
    }

    // Index the report in Elasticsearch
    req := esapi.IndexRequest{
        Index:      "trivy-vulnerabilities",
        DocumentID: fmt.Sprintf("%s-%s", report.Namespace, report.Name),
        Body:       bytes.NewReader(reportData),
        Refresh:    "true",
    }

    res, err := req.Do(context.Background(), es)
    if err != nil || res.IsError() {
        http.Error(w, "Failed to index document", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Report indexed successfully"))
}


func main() {
    // Load Elasticsearch configuration from environment variables
    endpoint := os.Getenv("ELASTICSEARCH_ENDPOINT")
    username := os.Getenv("ELASTICSEARCH_USERNAME")
    password := os.Getenv("ELASTICSEARCH_PASSWORD")

    // Create Elasticsearch client
    es, err := createElasticsearchClient(endpoint, username, password)
    if err != nil {
        log.Fatalf("Error creating Elasticsearch client: %s", err)
    }

    // Create a new router
    r := mux.NewRouter()

    // Define the webhook route
    r.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
        handleTrivyReport(w, r, es) // Pass Elasticsearch client to handler
    }).Methods("POST")

    // Start the server
    srv := &http.Server{
        Handler:      r,
        Addr:         ":8080",
        WriteTimeout: 15 * time.Second,
        ReadTimeout:  15 * time.Second,
    }

    fmt.Println("Server is listening on :8080")
    log.Fatal(srv.ListenAndServe())
}

