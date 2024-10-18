package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
	"bytes"
	"os"
	"es"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
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
    var report v1alpha1.VulnerabilityReport

    // Read and validate the request body
    body, err := io.ReadAll(r.Body)
    if err != nil || len(body) == 0 {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Decode JSON
    err = json.Unmarshal(body, &report)
    if err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
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

