package plugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
	default:
		return fmt.Errorf("❌ Unknown PLUGIN_FEATURE_TYPE: %s (expected: '%s' or '%s')", args.FeatureType, FeatureVeracode, FeatureVeracodeResubmit)
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
	tick := time.Tick(1 * time.Minute)

	for {
		select {
		case <-timeout:
			if args.TimeoutFailsJob {
				return fmt.Errorf("❌ Scan polling timed out after %d minutes", args.Timeout)
			}
			logrus.Warn("⚠️ Scan polling timed out, but job not marked as failed")
			return nil

		case <-tick:
			logrus.Info("🔁 Checking scan status...")

			published, err := isScanPublished(ctx, args)
			if err != nil {
				logrus.Warnf("⚠️ Failed to check scan status: %v", err)
				continue
			}
			if !published {
				continue
			}

			logrus.Info("✅ Scan completed and published!")

			if args.CanFailJob {
				if err := handlePolicyEvaluation(ctx, args); err != nil {
					return err
				}
			}

			return nil
		}
	}
}

func isScanPublished(ctx context.Context, args Args) (bool, error) {
	statusArgs := []string{
		"-jar", "/opt/veracode/api-wrapper.jar",
		"-action", "GetBuildInfo",
		"-appname", args.AppName,
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
	if err != nil {
		return false, err
	}

	return strings.Contains(string(output), "Published"), nil
}

func handlePolicyEvaluation(ctx context.Context, args Args) error {
	logrus.Info("🔍 Evaluating policy compliance for Failed job...")

	policyArgs := []string{
		"-jar", "/opt/veracode/api-wrapper.jar",
		"-action", "PassFail",
		"-appname", args.AppName,
		"-vid", args.VID,
		"-vkey", args.VKey,
	}
	if args.SandboxName != "" {
		policyArgs = append(policyArgs, "-sandboxname", args.SandboxName)
	}

	masked := maskSensitiveArgs(policyArgs)
	logrus.Infof("➡️  Checking build info with: java %s", strings.Join(masked, " "))

	cmd := exec.CommandContext(ctx, "java", policyArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("❌ Failed to check policy status: %v", err)
	}

	if strings.Contains(string(output), PolicyDidNotPass) || strings.Contains(string(output), PolicyConditionalPass) {
		return fmt.Errorf("❌ Policy evaluation returned Did Not Pass / Conditional Pass. Marking build as Failed: %w", err)
	}

	logrus.Info("✅ Policy evaluation passed")
	return nil
}

func runVeracodeResubmit(args Args) error {
	logrus.Infof("🟢 Starting Veracode Resubmit")
	if args.AnalysisName == "" || args.VID == "" || args.VKey == "" {
		return fmt.Errorf("missing required env: PLUGIN_ANALYSIS_NAME, PLUGIN_VID, PLUGIN_VKEY")
	}

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
