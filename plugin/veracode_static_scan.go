package plugin

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

func runVeracodeStaticScanPlugin(ctx context.Context, args Args) error {
	logrus.Infof("🟢 Starting Veracode UploadAndScan")

	if err := ValidateInputs(args); err != nil {
		return fmt.Errorf("input validation failed: %v", err)
	}

	finalFileList, err := resolveUploadFileList(args.Workspace, args.UploadIncludesPattern, args.UploadExcludesPattern)
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

func getVeracodeJarPath() string {
	// 1. Allow external override
	if path := os.Getenv("VERACODE_JAR_PATH"); path != "" {
		return path
	}

	// 2. OS-aware fallback
	if runtime.GOOS == "windows" {
		return "C:/opt/veracode/api-wrapper.jar"
	}

	// 3. Default Linux path
	return "/opt/veracode/api-wrapper.jar"
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
		"-jar", getVeracodeJarPath(),
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
	ctx := context.Background()
	var cancel context.CancelFunc

	if args.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(args.Timeout)*time.Minute)
		defer cancel()
	}

	// Attach context to command
	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	// Optional: capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	errChan := make(chan error, 1)
	go func() {
		errChan <- cmd.Run()
	}()

	select {
	case err := <-errChan:
		logrus.Infof("📤 Stdout: %s", stdout.String())
		logrus.Infof("📥 Stderr: %s", stderr.String())
		// Command finished in time
		return handleResult(err, args)

	case <-ctx.Done():
		// Timeout occurred
		if ctx.Err() == context.DeadlineExceeded {
			logrus.Warnf("⚠️ UploadAndScan timed out after %d minutes", args.Timeout)

			// Ensure process is killed
			if cmd.Process != nil {
				_ = cmd.Process.Kill() // Optional: handle kill error if needed
				logrus.Warn("💀 Process killed due to timeout")
			}

			if args.TimeoutFailsJob {
				return fmt.Errorf("❌ UploadAndScan timed out after %d minutes", args.Timeout)
			}
			return nil
		}
		// Other context error
		return ctx.Err()
	}
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
		"-jar", getVeracodeJarPath(),
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
	logrus.Debugf("🔍 CLI raw output:\n%s", outputStr)

	if err != nil {
		return false, "", fmt.Errorf("failed to check build info: %w", err)
	}

	isPublished := strings.Contains(outputStr, "published") || strings.Contains(outputStr, "Results Ready")
	policyStatus := extractPolicyComplianceStatus(outputStr)

	return isPublished, policyStatus, nil
}

func getAppID(ctx context.Context, args Args) (string, error) {
	appListArgs := []string{
		"-jar", getVeracodeJarPath(),
		"-action", "GetAppList",
		"-vid", args.VID,
		"-vkey", args.VKey,
	}

	masked := maskSensitiveArgs(appListArgs)
	logrus.Infof("➡️  Fetching App ID with: java %s", strings.Join(masked, " "))

	cmd := exec.CommandContext(ctx, "java", appListArgs...)
	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	logrus.Debugf("🔍 AppList raw output:\n%s", outputStr)

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
	var list AppList
	err := xml.Unmarshal([]byte(xmlStr), &list)
	if err != nil {
		fmt.Printf("❌ Failed to parse XML: %v\n", err)
		return ""
	}

	for _, app := range list.Apps {
		if app.AppName == appName {
			return app.AppID
		}
	}
	return ""
}

func extractPolicyComplianceStatus(xmlStr string) string {
	var buildInfo BuildInfo
	err := xml.Unmarshal([]byte(xmlStr), &buildInfo)
	if err != nil {
		fmt.Printf("❌ Failed to parse build info XML: %v\n", err)
		return ""
	}
	return buildInfo.Build.PolicyComplianceStatus
}
