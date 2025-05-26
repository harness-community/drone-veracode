package plugin

import "encoding/xml"

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
			Length int    `json:"length"` //In days
			Unit   string `json:"unit"`   //Units are days
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
