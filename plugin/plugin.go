package plugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/antfie/veracode-go-hmac-authentication/hmac"
	"github.com/georgeJobs/go-antpathmatcher"
	"github.com/sirupsen/logrus"
)

var makeHMACRequestFunc = makeHMACRequest

const (
	PolicyDidNotPass      = "Did Not Pass"
	PolicyConditionalPass = "Conditional Pass"

	FeatureVeracode         = "veracode"
	FeatureVeracodeResubmit = "veracode_resubmit"
	FeatureVeracodeReview   = "veracode_dynamic_analysis_review"
)

type AnalysesResponse struct {
	Embedded struct {
		Analyses []struct {
			AnalysisID string `json:"analysis_id"`
		} `json:"analyses"`
	} `json:"_embedded"`
}

type ResubmitPayload struct {
	Schedule struct {
		Duration struct {
			Length int    `json:"length"`
			Unit   string `json:"unit"`
		} `json:"duration"`
		Now            bool   `json:"now"`
		ScheduleStatus string `json:"schedule_status"`
		StartDate      string `json:"start_date"`
	} `json:"schedule"`
}

type BuildInfo struct {
	XMLName xml.Name `xml:"buildinfo"`
	Build   struct {
		PolicyComplianceStatus string `xml:"policy_compliance_status,attr"`
	} `xml:"build"`
}

type Args struct {
	FeatureType             string `envconfig:"PLUGIN_FEATURE_TYPE" default:"veracode"`
	AppName                 string `envconfig:"PLUGIN_APPLICATION_NAME"`
	Criticality             string `envconfig:"PLUGIN_CRITICALITY"`
	SandboxName             string `envconfig:"PLUGIN_SANDBOX_NAME"`
	Timeout                 int    `envconfig:"PLUGIN_TIMEOUT"`
	CreateProfile           bool   `envconfig:"PLUGIN_CREATE_PROFILE"`
	Teams                   string `envconfig:"PLUGIN_TEAMS"`
	CreateSandbox           bool   `envconfig:"PLUGIN_CREATE_SANDBOX"`
	Debug                   bool   `envconfig:"PLUGIN_DEBUG"`
	UploadIncludesPattern   string `envconfig:"PLUGIN_UPLOAD_INCLUDES_PATTERN"`
	UploadExcludesPattern   string `envconfig:"PLUGIN_UPLOAD_EXCLUDES_PATTERN"`
	ScanIncludesPattern     string `envconfig:"PLUGIN_SCAN_INCLUDES_PATTERN"`
	ScanExcludesPattern     string `envconfig:"PLUGIN_SCAN_EXCLUDES_PATTERN"`
	FileNamePattern         string `envconfig:"PLUGIN_FILE_NAME_PATTERN"`
	ReplacementPattern      string `envconfig:"PLUGIN_REPLACEMENT_PATTERN"`
	ScanAllNonFatalTopLevel bool   `envconfig:"PLUGIN_SCAN_ALL_NON_FATAL_TOP_LEVEL_MODULES"`
	IncludeNewModules       bool   `envconfig:"PLUGIN_INCLUDE_NEW_MODULES"`
	PHost                   string `envconfig:"PLUGIN_P_HOST"`
	PPort                   string `envconfig:"PLUGIN_P_PORT"`
	PUser                   string `envconfig:"PLUGIN_P_USER"`
	PPassword               string `envconfig:"PLUGIN_P_PASSWORD"`
	VID                     string `envconfig:"PLUGIN_VID"`
	VKey                    string `envconfig:"PLUGIN_VKEY"`
	DeleteIncompleteScan    bool   `envconfig:"PLUGIN_DELETE_INCOMPLETE_SCAN"`
	WaitForScan             bool   `envconfig:"PLUGIN_WAIT_FOR_SCAN"`
	TimeoutFailsJob         bool   `envconfig:"PLUGIN_TIMEOUT_FAILS_JOB"`
	CanFailJob              bool   `envconfig:"PLUGIN_CAN_FAIL_JOB"`
	UseProxy                bool   `envconfig:"PLUGIN_USE_PROXY"`
	Version                 string `envconfig:"PLUGIN_VERSION"`
	Level                   string `envconfig:"PLUGIN_LEVEL"`

	// Resubmit-specific
	AnalysisName          string `envconfig:"PLUGIN_ANALYSIS_NAME"`
	MaximumDuration       int    `envconfig:"PLUGIN_MAXIMUM_DURATION" default:"3"`
	FailBuildAsScanFailed bool   `envconfig:"PLUGIN_FAIL_BUILD_AS_SCAN_FAILED" default:"false"`

	//Analysis Review
	WaitForResultsDuration      int  `envconfig:"PLUGIN_WAIT_FOR_RESULTS_DURATION" default:"60"`
	FailBuildForPolicyViolation bool `envconfig:"PLUGIN_FAIL_BUILD_FOR_POLICY_VIOLATION" default:"false"`
}

func ValidateInputs(args Args) error {
	if args.AppName == "" {
		return fmt.Errorf("PLUGIN_APPLICATION_NAME is required")
	}
	if args.VID == "" || args.VKey == "" {
		return fmt.Errorf("PLUGIN_VID and PLUGIN_VKEY must be provided")
	}
	if args.UploadIncludesPattern == "" && args.UploadExcludesPattern == "" {
		args.UploadIncludesPattern = "**/*"
	}
	return nil
}

func Exec(ctx context.Context, args Args) error {
	switch args.FeatureType {
	case FeatureVeracode:
		return runVeracodePlugin(ctx, args)
	case FeatureVeracodeResubmit:
		return runVeracodeResubmit(args)
	case FeatureVeracodeReview:
		return runVeracodeDynamicAnalysisReview(ctx, args)
	default:
		return fmt.Errorf("\n❌ Unknown PLUGIN_FEATURE_TYPE: %s (expected: '%s' or '%s')", args.FeatureType, FeatureVeracode, FeatureVeracodeResubmit)
	}
}

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

func getAnalysisNameFromFile() string {
	paths := []string{
		os.Getenv("DRONE_OUTPUT"), // default location
		"/tmp/engine",             // fallback folder
	}

	for _, path := range paths {
		// If it's a file
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			content, _ := os.ReadFile(path)
			for _, line := range strings.Split(string(content), "\n") {
				if strings.HasPrefix(line, "VERACODE_ANALYSIS_NAME=") {
					return strings.TrimPrefix(line, "VERACODE_ANALYSIS_NAME=")
				}
			}
		}

		// If it's a directory like /tmp/engine, check for *-output.env
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			files, _ := filepath.Glob(filepath.Join(path, "*-output.env"))
			for _, file := range files {
				content, _ := os.ReadFile(file)
				for _, line := range strings.Split(string(content), "\n") {
					if strings.HasPrefix(line, "VERACODE_ANALYSIS_NAME=") {
						return strings.TrimPrefix(line, "VERACODE_ANALYSIS_NAME=")
					}
				}
			}
		}
	}

	return ""
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

// Poll analysis until "COMPLETED" or timeout
func pollAnalysisStatus(analysisID string, args Args) (string, error) {
	timeout := time.Duration(args.WaitForResultsDuration) * time.Hour
	interval := 30 * time.Second
	elapsed := time.Duration(0)

	logrus.Infof("⏳ Polling analysis status for up to %v...", timeout)

	for elapsed < timeout {
		status, err := getAnalysisStatus(analysisID, args)
		if err != nil {
			logrus.Errorf("❌ Error checking analysis status: %v", err)
			return "", err
		}

		logrus.Infof("🔁 Status: %s (elapsed: %v)", status, elapsed)

		if status == "COMPLETED" || status == "FAILED" {
			return status, nil
		}

		time.Sleep(interval)
		elapsed += interval
	}

	return "", fmt.Errorf("polling timeout reached (%v) for analysis ID: %s", timeout, analysisID)
}

// Call GET /analyses/{id} to fetch current status

func getAnalysisStatus(analysisID string, args Args) (string, error) {
	apiURL := fmt.Sprintf("https://api.veracode.com/was/configservice/v1/analyses/%s", analysisID)
	respBody, status, err := makeHMACRequestFunc(args.VID, args.VKey, apiURL, http.MethodGet, nil, args)
	if err != nil {
		return "", fmt.Errorf("failed to fetch status: %w", err)
	}
	if status != 200 {
		return "", fmt.Errorf("non-200 response (%d): %s", status, respBody)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(respBody), &parsed); err != nil {
		return "", fmt.Errorf("failed to parse analysis status JSON: %w", err)
	}

	occurrence, ok := parsed["latest_occurrence_status"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("missing 'latest_occurrence_status' in response")
	}

	statusType, ok := occurrence["status_type"].(string)
	if !ok {
		return "", fmt.Errorf("invalid or missing 'status_type' in response")
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

func runVeracodePlugin(ctx context.Context, args Args) error {
	logrus.Infof("🟢 Starting Veracode UploadAndScan")

	if err := ValidateInputs(args); err != nil {
		return fmt.Errorf("input validation failed: %v", err)
	}

	finalFileList, err := resolveUploadFileList(args.UploadIncludesPattern, args.UploadExcludesPattern)
	if err != nil {
		return fmt.Errorf("failed to resolve upload file list: %w", err)
	}

	cmdArgs := buildVeracodeCommandArgs(args, finalFileList)
	maskedArgs := maskSensitiveArgs(cmdArgs)
	logrus.Infof("➡️  Executing: java %s", strings.Join(maskedArgs, " "))

	cmd := exec.CommandContext(ctx, "java", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	err = runJavaCommandWithTimeout(cmd, args)
	if err != nil {
		return err
	}

	if args.WaitForScan {
		return waitForScanCompletion(ctx, args)
	}

	return nil
}

func maskSensitiveArgs(args []string) []string {
	masked := make([]string, len(args))
	copy(masked, args)
	for i := 0; i < len(masked)-1; i++ {
		if masked[i] == "-vkey" || masked[i] == "-vid" || masked[i] == "-ppassword" {
			masked[i+1] = "****"
		}
	}
	return masked
}

func buildVeracodeCommandArgs(args Args, fileList string) []string {
	cmdArgs := []string{
		"-jar", "/opt/veracode/api-wrapper.jar",
		"-action", "UploadAndScan",
		"-appname", args.AppName,
		"-filepath", fileList,
		"-version", args.Version,
		"-vid", args.VID,
		"-vkey", args.VKey,
	}

	optional := []struct {
		flag  string
		value string
	}{
		{"-criticality", args.Criticality},
		{"-sandboxname", args.SandboxName},
		{"-teams", args.Teams},
		{"-pattern", args.FileNamePattern},
		{"-replacement", args.ReplacementPattern},
		{"-exclude", args.ScanExcludesPattern},
		{"-include", args.ScanIncludesPattern},
		{"-phost", args.PHost},
		{"-pport", args.PPort},
		{"-puser", args.PUser},
		{"-ppassword", args.PPassword},
	}

	for _, opt := range optional {
		if opt.value != "" {
			cmdArgs = append(cmdArgs, opt.flag, opt.value)
		}
	}

	flags := []struct {
		flag string
		cond bool
	}{
		{"-createprofile", args.CreateProfile},
		{"-createsandbox", args.CreateSandbox},
		{"-debug", args.Debug},
		{"-scanallnonfataltoplevelmodules", args.ScanAllNonFatalTopLevel},
		{"-includenewmodules", args.IncludeNewModules},
		{"-deleteincompletescan", args.DeleteIncompleteScan},
	}

	for _, f := range flags {
		if f.cond {
			cmdArgs = append(cmdArgs, f.flag, "true")
		}
	}

	return cmdArgs
}

func runJavaCommandWithTimeout(cmd *exec.Cmd, args Args) error {
	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	if args.Timeout > 0 {
		select {
		case err := <-done:
			return handleResult(err, args)
		case <-time.After(time.Duration(args.Timeout) * time.Minute):
			if args.TimeoutFailsJob {
				return fmt.Errorf("❌ UploadAndScan timed out after %d minutes", args.Timeout)
			}
			logrus.Warnf("⚠️ UploadAndScan timed out after %d minutes, job not marked as failed", args.Timeout)
			return nil
		}
	} else {
		return handleResult(<-done, args)
	}
}

func resolveUploadFileList(includes, excludes string) (string, error) {
	workspace := os.Getenv("DRONE_WORKSPACE")
	if workspace == "" {
		var err error
		workspace, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("could not determine workspace: %w", err)
		}
	}

	matches, err := getAntMatchedFiles(workspace, includes, excludes)
	if err != nil {
		return "", fmt.Errorf("failed to match files: %w", err)
	}

	if len(matches) == 0 {
		return "", fmt.Errorf("no files matched for upload")
	}

	return strings.Join(matches, ","), nil
}

func getAntMatchedFiles(root, includePatterns, excludePatterns string) ([]string, error) {
	var results []string
	includes := splitPatterns(includePatterns)
	excludes := splitPatterns(excludePatterns)

	matcher := antpathmatcher.NewAntPathMatcher()

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		// Get path relative to root for matching
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(relPath) // normalize for matcher

		// Check inclusion
		included := false
		for _, pat := range includes {
			if matcher.Match(pat, relPath) {
				included = true
				break
			}
		}
		if !included {
			return nil
		}

		// Check exclusion
		for _, pat := range excludes {
			if matcher.Match(pat, relPath) {
				return nil
			}
		}

		results = append(results, filepath.Join(root, relPath))
		return nil
	})

	return results, err
}

func splitPatterns(patterns string) []string {
	var result []string
	for _, p := range strings.Split(patterns, ",") {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func handleResult(err error, args Args) error {
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			output := string(exitError.Stderr)

			// Check if version already exists
			if strings.Contains(output, "already exists") {
				logrus.Warnf("⚠️ The version '%s' already exists on Veracode. Please delete the existing version or use a new version string.", args.Version)
			} else {
				logrus.Errorf("❌ UploadAndScan failed with error: %s", output)
			}
		} else {
			logrus.Errorf("❌ UploadAndScan failed: %v (job not marked as failed)", err)
		}

		if args.CanFailJob {
			return fmt.Errorf("❌ UploadAndScan failed: %w", err)
		}
	} else {
		logrus.Info("✅ UploadAndScan completed successfully")
	}
	return nil
}

func waitForScanCompletion(ctx context.Context, args Args) error {
	logrus.Info("⏳ Waiting for scan to complete...")

	timeout := time.After(time.Duration(args.Timeout) * time.Minute)
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			if args.TimeoutFailsJob {
				return fmt.Errorf("❌ Scan polling timed out after %d minutes", args.Timeout)
			}
			logrus.Warn("⚠️ Scan polling timed out, but job not marked as failed")
			return nil

		case <-ticker.C:
			logrus.Info("🔁 Checking scan status...")

			published, policyStatus, err := isScanPublished(ctx, args)
			if err != nil {
				logrus.Warnf("⚠️ Failed to check scan status: %v", err)
				continue
			}
			if !published {
				continue
			}

			logrus.Infof("✅ Scan completed and published! Policy compliance status: %s", policyStatus)

			if args.CanFailJob {
				if policyStatus == "Did Not Pass" || policyStatus == "Conditional Pass" {
					return fmt.Errorf("❌ Policy evaluation returned %s. Marking build as Failed", policyStatus)
				}
			}

			return nil
		}
	}
}

func isScanPublished(ctx context.Context, args Args) (bool, string, error) {
	appID, err := getAppID(ctx, args)
	if err != nil {
		return false, "", err
	}

	statusArgs := []string{
		"-jar", "/opt/veracode/api-wrapper.jar",
		"-action", "GetBuildInfo",
		"-appid", appID,
		"-vid", args.VID,
		"-vkey", args.VKey,
	}
	if args.SandboxName != "" {
		statusArgs = append(statusArgs, "-sandboxname", args.SandboxName)
	}

	masked := maskSensitiveArgs(statusArgs)
	logrus.Infof("➡️  Checking build info with: java %s", strings.Join(masked, " "))

	cmd := exec.CommandContext(ctx, "java", statusArgs...)
	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	logrus.Infof("🔍 CLI raw output:\n%s", outputStr)

	if err != nil {
		return false, "", fmt.Errorf("failed to check build info: %w", err)
	}

	isPublished := strings.Contains(outputStr, "published") || strings.Contains(outputStr, "Results Ready")
	policyStatus := extractPolicyComplianceStatus(outputStr)

	return isPublished, policyStatus, nil
}

func getAppID(ctx context.Context, args Args) (string, error) {
	appListArgs := []string{
		"-jar", "/opt/veracode/api-wrapper.jar",
		"-action", "GetAppList",
		"-vid", args.VID,
		"-vkey", args.VKey,
	}

	masked := maskSensitiveArgs(appListArgs)
	logrus.Infof("➡️  Fetching App ID with: java %s", strings.Join(masked, " "))

	cmd := exec.CommandContext(ctx, "java", appListArgs...)
	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	logrus.Infof("🔍 AppList raw output:\n%s", outputStr)

	if err != nil {
		return "", fmt.Errorf("failed to get app list: %w", err)
	}

	appID := extractAppID(outputStr, args.AppName)
	if appID == "" {
		return "", fmt.Errorf("app name '%s' not found in app list", args.AppName)
	}

	logrus.Infof("✅ Found App ID for '%s': %s", args.AppName, appID)
	return appID, nil
}

func extractAppID(xmlStr, appName string) string {
	// Look for <app app_id="xxx" app_name="yyy" />
	appTag := `<app `
	idKey := `app_id="`

	entries := strings.Split(xmlStr, appTag)
	for _, entry := range entries {
		if strings.Contains(entry, `app_name="`+appName+`"`) {
			// Find app_id
			idStart := strings.Index(entry, idKey)
			if idStart == -1 {
				continue
			}
			idStart += len(idKey)
			idEnd := strings.Index(entry[idStart:], `"`)
			if idEnd == -1 {
				continue
			}
			return entry[idStart : idStart+idEnd]
		}
	}
	return ""
}

func extractPolicyComplianceStatus(xmlStr string) string {
	start := strings.Index(xmlStr, `policy_compliance_status="`)
	if start == -1 {
		return ""
	}
	start += len(`policy_compliance_status="`)
	end := strings.Index(xmlStr[start:], `"`)
	if end == -1 {
		return ""
	}
	return xmlStr[start : start+end]
}

func runVeracodeResubmit(args Args) error {
	logrus.Infof("🟢 Starting Veracode Resubmit")
	if args.AnalysisName == "" || args.VID == "" || args.VKey == "" {
		return fmt.Errorf("missing required env: PLUGIN_ANALYSIS_NAME, PLUGIN_VID, PLUGIN_VKEY")
	}

	// Defer writing Veracode_Analysis_Name at the very end
	defer func() {
		if args.AnalysisName != "" {
			err := WriteEnvToFile("VERACODE_ANALYSIS_NAME", args.AnalysisName, false)
			if err != nil {
				logrus.Warnf("⚠️ Failed to write VERACODE_ANALYSIS_NAME to env: %v", err)
			} else {
				logrus.Infof("✅ Set VERACODE_ANALYSIS_NAME: %s", args.AnalysisName)
			}
		}
	}()

	analysisID, err := fetchAnalysisID(args)
	if err != nil {
		return fmt.Errorf("error fetching analysis ID: %v", err)
	}
	log.Printf("✅ Fetched Analysis ID: %s", analysisID)

	payload := buildResubmitPayload(args.MaximumDuration)

	if err := resubmitAnalysis(args, analysisID, payload); err != nil {
		if args.FailBuildAsScanFailed {
			return fmt.Errorf("❌ Resubmit failed and failBuildAsScanFailed is enabled: %v", err)
		}
		log.Printf("❌ Resubmit failed: %v", err)
	} else {
		log.Println("✅ Resubmit Successful!")
	}
	return nil
}

func WriteEnvToFile(key string, value interface{}, isBase64Encoded bool) error {

	outputFile, err := os.OpenFile(os.Getenv("DRONE_OUTPUT"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file: %w", err)
	}
	defer outputFile.Close()

	valueStr := fmt.Sprintf("%v", value)

	if isBase64Encoded {
		valueStr = ConvertToBase64(valueStr)
	}

	_, err = fmt.Fprintf(outputFile, "%s=%s\n", key, valueStr)
	if err != nil {
		return fmt.Errorf("failed to write to env: %w", err)
	}

	return nil
}

func ConvertToBase64(input string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(input))
	return encoded
}

func fetchAnalysisID(args Args) (string, error) {
	apiURL := fmt.Sprintf("https://api.veracode.com/was/configservice/v1/analyses?name=%s", url.QueryEscape(args.AnalysisName))
	respBody, status, err := makeHMACRequestFunc(args.VID, args.VKey, apiURL, http.MethodGet, nil, args)
	if err != nil {
		return "", fmt.Errorf("API request failed: %v", err)
	}
	if status != 200 {
		return "", fmt.Errorf("failed to fetch analysis (status %d): %s", status, respBody)
	}

	var resp AnalysesResponse
	if err := json.Unmarshal([]byte(respBody), &resp); err != nil {
		return "", fmt.Errorf("failed to parse analysis response: %v", err)
	}
	if len(resp.Embedded.Analyses) == 0 {
		return "", fmt.Errorf("no analysis found with name: %s", args.AnalysisName)
	}
	return resp.Embedded.Analyses[0].AnalysisID, nil
}

func buildResubmitPayload(maxDuration int) []byte {
	startTime := time.Now().Format(time.RFC3339)
	payload := ResubmitPayload{}
	payload.Schedule.Duration.Length = maxDuration
	payload.Schedule.Duration.Unit = "DAY"
	payload.Schedule.Now = false
	payload.Schedule.ScheduleStatus = "ACTIVE"
	payload.Schedule.StartDate = startTime

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Fatalf("❌ Failed to marshal payload: %v", err)
	}
	return jsonData
}

func resubmitAnalysis(args Args, analysisID string, payload []byte) error {
	apiURL := fmt.Sprintf("https://api.veracode.com/was/configservice/v1/analyses/%s?method=PATCH", analysisID)
	respBody, status, err := makeHMACRequestFunc(args.VID, args.VKey, apiURL, http.MethodPut, bytes.NewBuffer(payload), args)
	if err != nil {
		return fmt.Errorf("API request failed: %v", err)
	}
	log.Printf("Status: %d", status)

	if status == 204 {
		log.Println("✅ Resubmit successful (204 No Content)")
		return nil
	}

	log.Printf("❌ Response Body (error case): %s", respBody)
	return fmt.Errorf("resubmit failed (status %d): %s", status, respBody)
}

func makeHMACRequest(apiID, apiKey, apiURL, method string, bodyBuffer *bytes.Buffer, args Args) (string, int, error) {
	parsedURL, err := url.Parse(apiURL)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse URL: %v", err)
	}

	var body io.Reader
	if bodyBuffer != nil {
		body = bodyBuffer
	} else {
		body = http.NoBody
	}

	req, err := http.NewRequest(method, parsedURL.String(), body)
	if err != nil {
		return "", 0, fmt.Errorf("failed to create request: %v", err)
	}

	authHeader, err := hmac.CalculateAuthorizationHeader(parsedURL, method, apiID, apiKey)
	if err != nil {
		return "", 0, fmt.Errorf("failed to calculate HMAC header: %v", err)
	}
	req.Header.Add("Authorization", authHeader)
	if method == http.MethodPut {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{}

	if args.UseProxy {
		proxyURL := fmt.Sprintf("http://%s:%s", args.PHost, args.PPort)
		parsedProxyURL, err := url.Parse(proxyURL)
		if err != nil {
			return "", 0, fmt.Errorf("failed to parse proxy URL: %v", err)
		}

		transport := &http.Transport{
			Proxy: http.ProxyURL(parsedProxyURL),
		}

		// Add proxy authentication if provided
		if args.PUser != "" && args.PPassword != "" {
			transport.ProxyConnectHeader = http.Header{}
			transport.ProxyConnectHeader.Set("Proxy-Authorization",
				"Basic "+basicAuth(args.PUser, args.PPassword))
		}

		client.Transport = transport
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("failed to read response body: %v", err)
	}
	return string(respBytes), resp.StatusCode, nil
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
