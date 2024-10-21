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

// Remove invalid fields with only dots (".") from the report recursively
func removeInvalidFields(data interface{}) {
    switch v := data.(type) {
    case map[string]interface{}:
        keysToDelete := []string{} // List of keys to delete
        // Traverse through the map and identify keys with only dots
        for key, value := range v {
            if key == "." {
                keysToDelete = append(keysToDelete, key)
            } else {
                // Recursively process nested maps or arrays
                removeInvalidFields(value)
            }
        }
        // Delete the invalid keys after traversal
        for _, key := range keysToDelete {
            delete(v, key)
        }
    case []interface{}:
        // Handle arrays of values (which could contain nested maps)
        for _, item := range v {
            removeInvalidFields(item)
        }
    }
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

    // Defensive type assertion for operatorObject and metadata
    operatorObject, ok := report["operatorObject"].(map[string]interface{})
    if !ok {
        log.Println("Error: operatorObject field is missing or not a map")
        http.Error(w, "Invalid report format: missing operatorObject", http.StatusBadRequest)
        return
    }

    metadata, ok := operatorObject["metadata"].(map[string]interface{})
    if !ok {
        log.Println("Error: metadata field is missing or not a map inside operatorObject")
        http.Error(w, "Invalid report format: missing metadata", http.StatusBadRequest)
        return
    }

    name, ok := metadata["name"].(string)
    if !ok {
        log.Println("Error: name field is missing or not a string")
        http.Error(w, "Invalid report format: missing name", http.StatusBadRequest)
        return
    }

    // Check if the summary is present and contains the counts
    reportData, ok := operatorObject["report"].(map[string]interface{})
    if !ok {
        log.Println("Error: report field is missing or not a map")
        http.Error(w, "Invalid report format: missing report data", http.StatusBadRequest)
        return
    }

    summary, ok := reportData["summary"].(map[string]interface{})
    if !ok {
        log.Println("Error: summary field is missing or not a map")
        http.Error(w, "Invalid report format: missing summary data", http.StatusBadRequest)
        return
    }

    // Helper function to safely get counts from summary
    getCount := func(field string) float64 {
        if count, exists := summary[field]; exists {
            if floatVal, ok := count.(float64); ok {
                return floatVal
            }
        }
        return 0.0 // Default to 0 if the field doesn't exist or is not a float64
    }

    // Extract vulnerability counts safely
    criticalCount := getCount("criticalCount")
    highCount := getCount("highCount")
    mediumCount := getCount("mediumCount")
    lowCount := getCount("lowCount")

    // If all counts are zero, skip uploading to Elasticsearch
    if criticalCount == 0 && highCount == 0 && mediumCount == 0 && lowCount == 0 {
        log.Println("All counts are zero; skipping Elasticsearch upload")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("Report contains no findings, skipping index"))
        return
    }

    // Clean up invalid fields
    removeInvalidFields(report)

    // Convert the report to JSON for Elasticsearch
    reportDataBytes, err := json.Marshal(report)
    if err != nil {
        log.Printf("Failed to serialize report: %v", err)
        http.Error(w, "Failed to serialize report", http.StatusInternalServerError)
        return
    }

    log.Printf("Serialized report data: %s", string(reportDataBytes))

    // Index the report in Elasticsearch
    req := esapi.IndexRequest{
        Index:      "trivy-vulnerabilities",
        DocumentID: name, // Safe to use now
        Body:       bytes.NewReader(reportDataBytes),
        Refresh:    "true",
    }

    log.Println("Attempting to index the report into Elasticsearch")

    res, err := req.Do(context.Background(), es)
    if err != nil || res.IsError() {
        if res != nil {
            log.Printf("Failed to index document in Elasticsearch. Status Code: %d, Response: %s", res.StatusCode, res.String())
        } else {
            log.Printf("Failed to index document in Elasticsearch: %v", err)
        }
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
