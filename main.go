package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "bytes"
    "time"

    "github.com/gorilla/mux"
    "github.com/elastic/go-elasticsearch/v8"
    "github.com/elastic/go-elasticsearch/v8/esapi"
)

// Function to create Elasticsearch client and log success/failure
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
        log.Printf("Error creating Elasticsearch client: %v", err)
        return nil, err
    }

    // Ping Elasticsearch to verify connection
    res, err := es.Ping()
    if err != nil || res.StatusCode != 200 {
        log.Printf("Failed to connect to Elasticsearch: %v", err)
        return nil, fmt.Errorf("failed to connect to Elasticsearch: %v", err)
    }

    // Log successful connection
    log.Println("Successfully connected to Elasticsearch")
    return es, nil
}

// Function to handle incoming vulnerability reports and log ingestion process
func handleTrivyReport(w http.ResponseWriter, r *http.Request, es *elasticsearch.Client) {
    log.Println("Received a request at /webhook")

    var report map[string]interface{}

    // Read and validate the request body
    body, err := io.ReadAll(r.Body)
    if err != nil || len(body) == 0 {
        log.Printf("Invalid request body or empty: %v", err)
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    log.Println("Request body received successfully")

    // Decode JSON
    err = json.Unmarshal(body, &report)
    if err != nil {
        log.Printf("Error decoding JSON: %v", err)
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }

    log.Printf("Ingesting vulnerability report: %v", report)

    // Convert the report to JSON for Elasticsearch
    reportData, err := json.Marshal(report)
    if err != nil {
        log.Printf("Failed to serialize report: %v", err)
        http.Error(w, "Failed to serialize report", http.StatusInternalServerError)
        return
    }

    log.Printf("Serialized report data: %s", string(reportData))

    // Index the report in Elasticsearch
    req := esapi.IndexRequest{
        Index:      "trivy-vulnerabilities",
        DocumentID: fmt.Sprintf("%v", report["metadata"].(map[string]interface{})["name"]),
        Body:       bytes.NewReader(reportData),
        Refresh:    "true",
    }

    log.Println("Attempting to index the report into Elasticsearch")

    res, err := req.Do(context.Background(), es)
    if err != nil || res.IsError() {
        log.Printf("Failed to index document in Elasticsearch. Status Code: %d, Response: %s", res.StatusCode, res.String())
        http.Error(w, "Failed to index document", http.StatusInternalServerError)
        return
    }

    log.Println("Successfully pushed the vulnerability report to Elasticsearch")

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

    // Pass Elasticsearch client to the webhook handler
    r.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
        handleTrivyReport(w, r, es) // Pass the 'es' client here
    }).Methods("POST")

    // Health check endpoint
    r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    })

    // Start the server
    srv := &http.Server{
        Handler:      r,
        Addr:         ":8080",
        WriteTimeout: 15 * time.Second,
        ReadTimeout:  15 * time.Second,
    }

    log.Println("Server is listening on :8080")
    log.Fatal(srv.ListenAndServe())
}
