package plugin

import (
	"context"
	"fmt"
)

const (
	PolicyDidNotPass      = "Did Not Pass"
	PolicyConditionalPass = "Conditional Pass"

	VeracodeStaticScan = "veracode"
	VeracodeResubmit   = "veracode_resubmit"
	VeracodeReview     = "veracode_dynamic_analysis_review"
)

type Args struct {
	OperationMode           string `envconfig:"PLUGIN_OPERATION_MODE" default:"veracode"`
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
	Workspace               string `envconfig:"PLUGIN_WORKSPACE"`

	// Resubmit-specific
	AnalysisName          string `envconfig:"PLUGIN_ANALYSIS_NAME"`
	MaximumDuration       int    `envconfig:"PLUGIN_MAXIMUM_DURATION" default:"3"` //In days
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
	switch args.OperationMode {
	case VeracodeStaticScan:
		return runVeracodeStaticScanPlugin(ctx, args)
	case VeracodeResubmit:
		return runVeracodeResubmit(args)
	default:
		return fmt.Errorf("\n❌ Unknown PLUGIN_OPERATION_MODE: %s (expected: '%s' or '%s')", args.OperationMode, VeracodeStaticScan, VeracodeResubmit)
	}
}
