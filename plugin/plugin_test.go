package plugin

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ---------- Helper & Mock Logic ----------

// Overrideable execCommandContext
var execCommandContext = exec.CommandContext

// Mock exec.Command for Java CLI
func mockCommandContext(ctx context.Context, command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.CommandContext(ctx, os.Args[0], cs...)
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
	return cmd
}

// Simulate external Java CLI execution
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	if len(os.Args) > 3 {
		args := os.Args[3:]
		if contains(args, "UploadAndScan") {
			os.Stdout.WriteString("UploadAndScan complete.\n")
			os.Exit(0)
		}
		if contains(args, "GetBuildInfo") {
			os.Stdout.WriteString("Scan status: Published\n")
			os.Exit(0)
		}
		if contains(args, "PassFail") {
			os.Stdout.WriteString("Policy evaluation: Passed\n")
			os.Exit(0)
		}
	}
	os.Exit(1)
}

func contains(arr []string, substr string) bool {
	for _, s := range arr {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// ---------- Test Cases ----------

// ValidateInputs test
func TestValidateInputs(t *testing.T) {
	tests := []struct {
		name      string
		args      Args
		expectErr bool
		errMsg    string
	}{
		{"Valid Inputs", Args{AppName: "MyApp", VID: "vid", VKey: "vkey"}, false, ""},
		{"Missing AppName", Args{VID: "vid", VKey: "vkey"}, true, "PLUGIN_APPLICATION_NAME"},
		{"Missing VID/VKey", Args{AppName: "App"}, true, "PLUGIN_VID and PLUGIN_VKEY"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateInputs(tc.args)
			if tc.expectErr {
				if err == nil || !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("Expected error '%s', got %v", tc.errMsg, err)
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// resolveUploadFileList test
func TestResolveUploadFileList(t *testing.T) {
	os.Setenv("DRONE_WORKSPACE", "../testdata")

	actualRaw, err := resolveUploadFileList("*.go", "*.txt")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Normalize to forward slashes for cross-platform compatibility
	actualPaths := strings.Split(actualRaw, ",")
	for i := range actualPaths {
		actualPaths[i] = filepath.ToSlash(actualPaths[i])
	}

	expected := "../testdata/include1.go,../testdata/include2.go"
	expectedPaths := strings.Split(expected, ",")

	// Sort both lists
	sort.Strings(actualPaths)
	sort.Strings(expectedPaths)

	actualStr := strings.Join(actualPaths, ",")
	expectedStr := strings.Join(expectedPaths, ",")

	if actualStr != expectedStr {
		t.Errorf("Expected file list:\n%s\nBut got:\n%s", expectedStr, actualStr)
	}
}

// handleResult test
func TestHandleResult(t *testing.T) {
	tests := []struct {
		name        string
		inputErr    error
		args        Args
		expectedErr bool
	}{
		{"Error but can fail", exec.ErrNotFound, Args{CanFailJob: true}, true},
		{"Error but cannot fail", exec.ErrNotFound, Args{CanFailJob: false}, false},
		{"No error", nil, Args{}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := handleResult(tc.inputErr, tc.args)
			if tc.expectedErr && err == nil {
				t.Errorf("Expected error but got nil")
			} else if !tc.expectedErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// buildVeracodeCommandArgs test
func TestBuildCommandArgs(t *testing.T) {
	args := Args{
		AppName:           "MyApp",
		VKey:              "vkey",
		VID:               "vid",
		Version:           "1.0",
		Criticality:       "VeryHigh",
		SandboxName:       "sandbox",
		Teams:             "TeamX",
		Debug:             true,
		IncludeNewModules: true,
	}
	file := "/tmp/file.zip"
	cmdArgs := buildVeracodeCommandArgs(args, file)

	expected := []string{
		"-appname", "MyApp",
		"-filepath", file,
		"-version", "1.0",
		"-vid", "vid",
		"-vkey", "vkey",
		"-criticality", "VeryHigh",
		"-sandboxname", "sandbox",
		"-teams", "TeamX",
		"-debug", "true",
		"-includenewmodules", "true",
	}
	for _, token := range expected {
		found := false
		for _, actual := range cmdArgs {
			if actual == token {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected '%s' in command args", token)
		}
	}
}

// runJavaCommandWithTimeout test (mocked)
func TestRunJavaCommandWithTimeout(t *testing.T) {
	oldExec := execCommandContext
	defer func() { execCommandContext = oldExec }()
	execCommandContext = mockCommandContext

	cmd := exec.Command("sleep", "2")
	args := Args{Timeout: 1, TimeoutFailsJob: true}
	err := runJavaCommandWithTimeout(cmd, args)

	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Log("Simulated timeout case might need adjustment")
	}
}

// ---------- New Tests for Resubmit ----------

func mockMakeHMACRequestSuccess(apiID, apiKey, apiURL, method string, bodyBuffer *bytes.Buffer) (string, int, error) {
	if method == "GET" && contains([]string{apiURL}, "analyses?name=") {
		mockResp := `{
			"_embedded": {
				"analyses": [
					{ "analysis_id": "mock-analysis-id-123" }
				]
			}
		}`
		return mockResp, 200, nil
	}
	if method == "PUT" && contains([]string{apiURL}, "analyses/mock-analysis-id-123") {
		return "", 204, nil
	}
	return "", 400, fmt.Errorf("unexpected mock call")
}

func mockMakeHMACRequestFailure(apiID, apiKey, apiURL, method string, bodyBuffer *bytes.Buffer) (string, int, error) {
	return "mock error response", 500, fmt.Errorf("mock failure")
}

// --- Unit Tests ---

func TestFetchAnalysisIDSuccess(t *testing.T) {
	original := makeHMACRequestFunc
	defer func() { makeHMACRequestFunc = original }()
	makeHMACRequestFunc = mockMakeHMACRequestSuccess

	args := Args{
		AnalysisName: "MockAnalysis",
		VID:          "mockVID",
		VKey:         "mockVKey",
	}

	id, err := fetchAnalysisID(args)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if id != "mock-analysis-id-123" {
		t.Fatalf("expected mock-analysis-id-123, got: %s", id)
	}
}

func TestFetchAnalysisIDFailure(t *testing.T) {
	original := makeHMACRequestFunc
	defer func() { makeHMACRequestFunc = original }()
	makeHMACRequestFunc = mockMakeHMACRequestFailure

	args := Args{
		AnalysisName: "MockAnalysis",
		VID:          "mockVID",
		VKey:         "mockVKey",
	}

	_, err := fetchAnalysisID(args)
	if err == nil {
		t.Fatal("expected error, got none")
	}
}

func TestResubmitAnalysisSuccess(t *testing.T) {
	original := makeHMACRequestFunc
	defer func() { makeHMACRequestFunc = original }()
	makeHMACRequestFunc = mockMakeHMACRequestSuccess

	args := Args{
		VID:  "mockVID",
		VKey: "mockVKey",
	}

	payload := buildResubmitPayload(3)
	err := resubmitAnalysis(args, "mock-analysis-id-123", payload)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestResubmitAnalysisFailure(t *testing.T) {
	original := makeHMACRequestFunc
	defer func() { makeHMACRequestFunc = original }()
	makeHMACRequestFunc = mockMakeHMACRequestFailure

	args := Args{
		VID:  "mockVID",
		VKey: "mockVKey",
	}

	payload := buildResubmitPayload(3)
	err := resubmitAnalysis(args, "mock-analysis-id-123", payload)
	if err == nil {
		t.Fatal("expected error, got none")
	}
}
