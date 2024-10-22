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

    // Clean up invalid fields
    removeInvalidFields(report)

    // In the createElasticsearchClient or other appropriate function:
    fieldsToPushJson := os.Getenv("ELASTIC_FIELDS_TO_PUSH")

    // Declare a map to hold field-value pairs
    fieldsToPush := make(map[string]interface{})

    // Parse the JSON string into a map
    if err := json.Unmarshal([]byte(fieldsToPushJson), &fieldsToPush); err != nil {
        log.Fatalf("Error parsing ELASTIC_FIELDS_TO_PUSH: %v", err)
    }

    // Identify the report type by its 'kind'
    operatorObject, ok := report["operatorObject"].(map[string]interface{})
    if !ok {
        log.Println("Error: operatorObject field is missing or not a map")
        http.Error(w, "Invalid report format: missing operatorObject", http.StatusBadRequest)
        return
    }

    // Example of using the fields in handleVulnerabilityReport
    for field, value := range fieldsToPush {
        log.Printf("Processing field: %s with value: %v", field, value)

        // Add the field and value to the report data for Elasticsearch
        operatorObject[field] = value
    }

    kind, ok := operatorObject["kind"].(string)
    if !ok {
        log.Println("Error: kind field is missing or not a string")
        http.Error(w, "Invalid report format: missing kind", http.StatusBadRequest)
        return
    }

    log.Println("Ingesting report of kind:", kind)

    // Extract verb from report (ensure it's declared)
    verb, ok := report["verb"].(string)
    if !ok {
        log.Println("Verb field is missing, setting to default 'create'")
        verb = "create"  // Default to "create" if "verb" is missing
    }
    log.Println("Report verb:", verb)

    // Special handling for VulnerabilityReport
    if kind == "VulnerabilityReport" {
        log.Println("Processing vulnerability report.")
        handleVulnerabilityReport(w, operatorObject, es, verb)
        return
    }

    // Handle other report types (unchanged behavior)
    handleOtherReportTypes(w, operatorObject, es, verb)
}

func handleVulnerabilityReport(w http.ResponseWriter, report map[string]interface{}, es *elasticsearch.Client, verb string) {


    // Extract metadata
    metadata, ok := report["metadata"].(map[string]interface{})
    if !ok {
        log.Println("Error: metadata field is missing or not a map inside operatorObject")
        http.Error(w, "Invalid report format: missing metadata", http.StatusBadRequest)
        return
    }

    log.Println("Resource name is:", metadata["name"])

    // Extract report data
    reportData, ok := report["report"].(map[string]interface{})
    if !ok {
        log.Println("Error: report field is missing or not a map")
        http.Error(w, "Invalid report format: missing report data", http.StatusBadRequest)
        return
    }

    // Extract artifact, os, scanner, and summary fields
    artifact := reportData["artifact"].(map[string]interface{})
    os := reportData["os"].(map[string]interface{})
    scanner := reportData["scanner"].(map[string]interface{})
    summary := reportData["summary"].(map[string]interface{})

    // Extract vulnerabilities
    vulnerabilities, ok := reportData["vulnerabilities"].([]interface{})
    if !ok {
        log.Println("Error: vulnerabilities field is missing or not a list")
        http.Error(w, "Invalid report format: missing vulnerabilities", http.StatusBadRequest)
        return
    }

    // Check if the vulnerabilities list is empty
    if len(vulnerabilities) == 0 {
        log.Printf("No vulnerability found for %s", metadata["name"])
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(fmt.Sprintf("No vulnerability found for %s", metadata["name"])))
        return
    }

    // Ingest each critical vulnerability as a separate document
    for _, vuln := range vulnerabilities {
        vulnMap := vuln.(map[string]interface{})
        
        // Check if the vulnerability has a "CRITICAL" severity
        if severity, ok := vulnMap["severity"].(string); ok && severity == "CRITICAL" {
            // Add the deleted flag
            reportDeleted := false
            if verb == "delete" {
                reportDeleted = true
            }

            // Build the formatted report for this vulnerability
            formattedVulnReport := map[string]interface{}{
                "kind":             "VulnerabilityReport",
                "metadata":         metadata, // Include full metadata
                "artifact":         artifact,
                "os":               os,
                "scanner":          scanner,
                "summary":          summary, // Optional, keep summary if needed
                "vulnerability":    formatVulnerability(vulnMap), // Only this specific vulnerability
                "report": map[string]interface{}{
                    "deleted": reportDeleted, // Add the deleted flag
                },
            }

            // Convert the formatted report to JSON for Elasticsearch
            reportDataBytes, err := json.Marshal(formattedVulnReport)
            if err != nil {
                log.Printf("Failed to serialize formatted report: %v", err)
                http.Error(w, "Failed to serialize report", http.StatusInternalServerError)
                return
            }

            // Use a unique DocumentID for each vulnerability (combining report name and vulnerability ID)
            documentID := fmt.Sprintf("%s-%s", metadata["name"], vulnMap["vulnerabilityID"])

            // Index the report in Elasticsearch
            var req esapi.Request
            if verb == "delete" {
                // Update document if it's a delete request
                req = esapi.UpdateRequest{
                    Index:      "trivy-vulnerabilities",
                    DocumentID: documentID, // Unique ID for each vulnerability
                    Body:       bytes.NewReader([]byte(fmt.Sprintf(`{"doc":%s}`, reportDataBytes))),
                    Refresh:    "true",
                }
                log.Printf("Flagging document as deleted")
            } else {
                req = esapi.IndexRequest{
                    Index:      "trivy-vulnerabilities",
                    DocumentID: documentID, // Unique ID for each vulnerability
                    Body:       bytes.NewReader(reportDataBytes),
                    Refresh:    "true",
                }
                log.Printf("Indexing critical vulnerability: %s", vulnMap["vulnerabilityID"])
            }

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

            log.Printf("Successfully processed critical vulnerability %s", vulnMap["vulnerabilityID"])
        }
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Vulnerability report processed successfully"))
}




// Helper function to format a single vulnerability
func formatVulnerability(vuln map[string]interface{}) map[string]interface{} {
    return map[string]interface{}{
        "vulnerabilityID":   vuln["vulnerabilityID"],
        "resource":          vuln["resource"],
        "installedVersion":  vuln["installedVersion"],
        "fixedVersion":      vuln["fixedVersion"],
        "severity":          vuln["severity"],
        "score":             vuln["score"],
        "title":             vuln["title"],
        "publishedDate":     vuln["publishedDate"],
        "lastModifiedDate":  vuln["lastModifiedDate"],
    }
}

func handleOtherReportTypes(w http.ResponseWriter, report map[string]interface{}, es *elasticsearch.Client, verb string) {
    // Add "report.deleted" based on the verb
    reportDeleted := false
    if verb == "delete" {
        reportDeleted = true
    }
    
    // Add or modify the "report" field to include "deleted"
    report["report"] = map[string]interface{}{
        "deleted": reportDeleted,
    }

    // Serialize the modified report
    reportDataBytes, err := json.Marshal(report)
    if err != nil {
        log.Printf("Failed to serialize report: %v", err)
        http.Error(w, "Failed to serialize report", http.StatusInternalServerError)
        return
    }

    // Get the report name
    name, _ := report["metadata"].(map[string]interface{})["name"].(string)
    log.Println("Resource name is:", name)

    var req esapi.Request

    // Handle "delete" or "index" requests
    if verb == "delete" {
        req = esapi.UpdateRequest{
            Index:      "trivy-reports",
            DocumentID: name,
            Body:       bytes.NewReader([]byte(fmt.Sprintf(`{"doc":%s}`, reportDataBytes))),
            Refresh:    "true",
        }
        log.Printf("Flagging document as deleted for report: %s", name)
    } else {
        req = esapi.IndexRequest{
            Index:      "trivy-reports",
            DocumentID: name,
            Body:       bytes.NewReader(reportDataBytes),
            Refresh:    "true",
        }
        log.Printf("Indexing non-vulnerability report: %s", name)
    }

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

    log.Println("Successfully pushed the report to Elasticsearch")
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
