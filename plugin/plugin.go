package plugin

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/georgeJobs/go-antpathmatcher"
	"github.com/sirupsen/logrus"
)

const (
	PolicyDidNotPass      = "Did Not Pass"
	PolicyConditionalPass = "Conditional Pass"
)

type Args struct {
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
	logrus.Infof("🟢 Starting Veracode UploadAndScan")

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
