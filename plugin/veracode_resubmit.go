package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

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
