package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

func runVeracodeDynamicAnalysisReview(ctx context.Context, args Args) error {
	logrus.Infof("\n🟢 Starting Veracode Dynamic Analysis Review...")

	// Step 0: Get analysis name from env if not provided
	if args.AnalysisName == "" {
		analysisNameFromFile := getAnalysisNameFromFile()
		if analysisNameFromFile != "" {
			logrus.Infof("\n🔄 Using fallback analysis name from file: %s", analysisNameFromFile)
			args.AnalysisName = analysisNameFromFile
		}
	}

	// Step 1: Validate required inputs
	if args.AnalysisName == "" || args.VID == "" || args.VKey == "" {
		return fmt.Errorf("\n❌ Missing required env: PLUGIN_ANALYSIS_NAME, PLUGIN_VID, or PLUGIN_VKEY")
	}

	// Step 2: Resolve analysis ID
	logrus.Infof("\n🔍 Resolving analysis ID for analysis name: %s", args.AnalysisName)
	analysisID, err := fetchAnalysisID(args)
	if err != nil {
		return fmt.Errorf("\n❌ Failed to resolve analysis ID from name: %w", err)
	}
	logrus.Infof("\n✅ Fetched Analysis ID: %s", analysisID)

	// Step 3: Poll until status is COMPLETED or FAILED
	logrus.Infof("\n⏳ Polling dynamic analysis status...")
	status, err := pollAnalysisStatus(analysisID, args)
	if err != nil {
		return fmt.Errorf("\n❌ Error while polling analysis status for ID '%s': %w", analysisID, err)
	}
	logrus.Infof("\n📘 Final Dynamic Analysis Status: %s", status)

	if status != "COMPLETED" {
		return fmt.Errorf("\n❌ Dynamic analysis did not complete successfully. Final status: %s", status)
	}

	// Step 4: Fetch and log detailed findings
	logrus.Infof("\n🐞 Fetching vulnerability findings for analysis ID: %s", analysisID)
	if err := fetchAndLogDetailedFindings(analysisID, args); err != nil {
		return fmt.Errorf("\n❌ Failed to fetch vulnerability findings: %w", err)
	}

	logrus.Infof("\n✅ Dynamic Analysis Review completed successfully.")
	return nil
}

// extractEnvVarFromFile reads a file and extracts the value for a specific key
func extractEnvVarFromFile(path, key string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimPrefix(line, key+"="), nil
		}
	}
	return "", nil
}

// getAllCandidatePaths returns possible file paths to search for the env var
func getAllCandidatePaths() []string {
	paths := []string{}
	droneOutput := os.Getenv("DRONE_OUTPUT")
	if droneOutput != "" {
		paths = append(paths, droneOutput)
	}
	paths = append(paths, "/tmp/engine")
	return paths
}

func getAnalysisNameFromFile() string {
	const key = "VERACODE_ANALYSIS_NAME"

	for _, path := range getAllCandidatePaths() {
		if isFile(path) {
			if value := getKeyFromFile(path, key); value != "" {
				return value
			}
		} else if isDir(path) {
			if value := getKeyFromDirectory(path, key); value != "" {
				return value
			}
		}
	}
	return ""
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func getKeyFromFile(path, key string) string {
	value, err := extractEnvVarFromFile(path, key)
	if err == nil && value != "" {
		return value
	}
	return ""
}

func getKeyFromDirectory(dirPath, key string) string {
	files, err := filepath.Glob(filepath.Join(dirPath, "*-output.env"))
	if err != nil {
		return ""
	}
	for _, file := range files {
		if value := getKeyFromFile(file, key); value != "" {
			return value
		}
	}
	return ""
}

// Poll analysis until "COMPLETED" or timeout
func pollAnalysisStatus(analysisID string, args Args) (string, error) {
	timeout := time.Duration(args.WaitForResultsDuration) * time.Hour
	interval := 30 * time.Second
	elapsed := time.Duration(0)

	logrus.Infof("\n⏳ Polling analysis status for up to %v...", timeout)

	for elapsed < timeout {
		status, err := getAnalysisStatus(analysisID, args)
		if err != nil {
			logrus.Errorf("\n❌ Error checking analysis status: %v", err)
			return "", err
		}

		logrus.Infof("\n🔁 Status: %s (elapsed: %v)", status, elapsed)

		if status == "COMPLETED" || status == "FAILED" {
			return status, nil
		}

		time.Sleep(interval)
		elapsed += interval
	}

	return "", fmt.Errorf("\npolling timeout reached (%v) for analysis ID: %s", timeout, analysisID)
}

// --- STEP 4: Fetch Full Vulnerability Report ---
func fetchAndLogDetailedFindings(analysisID string, args Args) error {
	logrus.Infof("\n📦 Fetching full analysis metadata for ID: %s", analysisID)

	// Step 1: Fetch the full analysis JSON to get the latest_occurrence link
	analysisURL := fmt.Sprintf("https://api.veracode.com/was/configservice/v1/analyses/%s", analysisID)
	body, status, err := makeHMACRequestFunc(args.VID, args.VKey, analysisURL, http.MethodGet, nil, args)
	if err != nil {
		return fmt.Errorf("\nfailed to fetch analysis metadata: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("\nnon-200 status fetching analysis metadata: %d. Body: %s", status, body)
	}

	// Step 2: Parse the latest_occurrence URL
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return fmt.Errorf("\nfailed to parse analysis metadata JSON: %w", err)
	}

	links, ok := parsed["_links"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("\nmissing _links in analysis metadata")
	}
	latestOccurrence, ok := links["latest_occurrence"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("\nmissing latest_occurrence in _links")
	}
	occurrenceHref, ok := latestOccurrence["href"].(string)
	if !ok {
		return fmt.Errorf("\nmissing href for latest_occurrence")
	}

	// Step 3: Fetch the full occurrence data
	occurrenceURL := occurrenceHref
	logrus.Infof("\n🔍 Fetching detailed analysis occurrence from: %s", occurrenceURL)

	occurrenceBody, status, err := makeHMACRequestFunc(args.VID, args.VKey, occurrenceURL, http.MethodGet, nil, args)
	if err != nil {
		return fmt.Errorf("\nfailed to fetch occurrence data: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("\nnon-200 status fetching occurrence: %d. Body: %s", status, occurrenceBody)
	}

	// Step 4: Pretty print the results
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, []byte(occurrenceBody), "", "  "); err != nil {
		return fmt.Errorf("\nfailed to format occurrence JSON: %w", err)
	}

	logrus.Infof("\n🧪 Detailed Dynamic Analysis Findings:\n%s", prettyJSON.String())

	if err := logStructuredStats(occurrenceBody); err != nil {
		logrus.Warnf("\n⚠️ Failed to log structured stats: %v", err)
	}
	return nil
}

// Call GET /analyses/{id} to fetch current status
func getAnalysisStatus(analysisID string, args Args) (string, error) {
	apiURL := fmt.Sprintf("https://api.veracode.com/was/configservice/v1/analyses/%s", analysisID)
	respBody, status, err := makeHMACRequestFunc(args.VID, args.VKey, apiURL, http.MethodGet, nil, args)
	if err != nil {
		return "", fmt.Errorf("\nfailed to fetch status: %w", err)
	}
	if status != 200 {
		return "", fmt.Errorf("\nnon-200 response (%d): %s", status, respBody)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(respBody), &parsed); err != nil {
		return "", fmt.Errorf("\nfailed to parse analysis status JSON: %w", err)
	}

	occurrence, ok := parsed["latest_occurrence_status"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("\nmissing 'latest_occurrence_status' in response")
	}

	statusType, ok := occurrence["status_type"].(string)
	if !ok {
		return "", fmt.Errorf("\ninvalid or missing 'status_type' in response")
	}

	switch statusType {
	case "FINISHED_RESULTS_AVAILABLE":
		return "COMPLETED", nil
	case "FAILED":
		return "FAILED", nil
	default:
		return statusType, nil
	}
}

func logStructuredStats(occurrenceBody string) error {
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(occurrenceBody), &parsed); err != nil {
		return fmt.Errorf("\n❌ Failed to parse occurrence JSON: %w", err)
	}

	// Define helper
	get := func(key string) string {
		if val, ok := parsed[key]; ok {
			return fmt.Sprintf("%v", val)
		}
		return "N/A"
	}
	status := "N/A"
	if s, ok := parsed["status"].(map[string]interface{}); ok {
		status = fmt.Sprintf("%v", s["status_type"])
	}

	logrus.Info("\n📊 ====== Dynamic Analysis Summary ======")
	logrus.Infof("\n📌 Analysis ID         : %s", get("analysis_id"))
	logrus.Infof("\n📝 Name                : %s", get("name"))
	logrus.Infof("\n📅 Start Date          : %s", get("start_date"))
	logrus.Infof("\n📅 End Date            : %s", get("end_date"))
	logrus.Infof("\n🕒 Actual Start        : %s", get("actual_start_date"))
	logrus.Infof("\n🕒 Actual End          : %s", get("actual_end_date"))
	logrus.Infof("\n⏱️ Duration            : %s", get("duration"))
	logrus.Infof("\n📊 Status              : %s", status)
	logrus.Infof("\n📈 Percent Scanned     : %v%%", get("percent_scanned"))
	logrus.Infof("\n🔒 Verification Only   : %s", get("verification_only"))
	logrus.Infof("\n✅ All Scans Verified  : %s", get("all_scans_passed_verification"))
	logrus.Infof("\n❌ Failed Verifications: %s", get("count_of_failed_verifications"))
	logrus.Infof("\n🏷️  Scan Type          : %s", get("scan_type"))
	logrus.Infof("\n🏢 Org                 : %s", get("org"))
	logrus.Infof("\n🏢 Enterprise Mode     : %s", get("enterprise_mode"))
	logrus.Infof("\n🔁 Schedule Frequency  : %s", get("schedule_frequency"))
	logrus.Info("\n📊 =====================================")
	return nil
}
