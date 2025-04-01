package plugin

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
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
	UnstableBuild           bool   `envconfig:"PLUGIN_UNSTABLE_BUILD"`
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
	logrus.Infof("➡️  Executing: java %s", strings.Join(cmdArgs, " "))

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

	fsys := os.DirFS(workspace)

	excludeSet, err := buildFullPathSet(fsys, workspace, excludes)
	if err != nil {
		return "", fmt.Errorf("resolving excludes: %w", err)
	}

	includeMatches, err := getMatchedFilesFromPatterns(fsys, includes)
	if err != nil {
		return "", fmt.Errorf("resolving includes: %w", err)
	}

	var finalFiles []string
	for _, f := range includeMatches {
		full := filepath.Join(workspace, f)
		if _, excluded := excludeSet[full]; !excluded {
			finalFiles = append(finalFiles, full)
		}
	}

	if len(finalFiles) == 0 {
		return "", fmt.Errorf("no files matched for upload after includes/excludes filtering")
	}

	return strings.Join(finalFiles, ","), nil
}

func getMatchedFilesFromPatterns(fsys fs.FS, patterns string) ([]string, error) {
	var allMatches []string
	for _, pat := range strings.Split(patterns, ",") {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		matches, err := doublestar.Glob(fsys, pat)
		if err != nil {
			return nil, fmt.Errorf("pattern %q error: %w", pat, err)
		}
		allMatches = append(allMatches, matches...)
	}
	return allMatches, nil
}

func buildFullPathSet(fsys fs.FS, root, patterns string) (map[string]struct{}, error) {
	set := make(map[string]struct{})
	matches, err := getMatchedFilesFromPatterns(fsys, patterns)
	if err != nil {
		return nil, err
	}
	for _, f := range matches {
		set[filepath.Join(root, f)] = struct{}{}
	}
	return set, nil
}

func handleResult(err error, args Args) error {
	if err != nil {
		if args.CanFailJob {
			return fmt.Errorf("❌ UploadAndScan failed: %w", err)
		}
		logrus.Warnf("⚠️ UploadAndScan failed: %v (job not marked as failed)", err)
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

			if args.UnstableBuild {
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

	cmd := exec.CommandContext(ctx, "java", statusArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}

	return strings.Contains(string(output), "Published"), nil
}

func handlePolicyEvaluation(ctx context.Context, args Args) error {
	logrus.Info("🔍 Evaluating policy compliance for unstableBuild...")

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

	cmd := exec.CommandContext(ctx, "java", policyArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logrus.Warnf("⚠️ Failed to check policy status: %v", err)
		return nil // do not fail job on policy check failure
	}

	if strings.Contains(string(output), PolicyDidNotPass) || strings.Contains(string(output), PolicyConditionalPass) {
		logrus.Warn("⚠️ Policy evaluation returned Did Not Pass / Conditional Pass. Marking build as UNSTABLE.")
		os.Exit(2)
	}

	logrus.Info("✅ Policy evaluation passed")
	return nil
}
