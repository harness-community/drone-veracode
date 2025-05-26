package plugin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/antfie/veracode-go-hmac-authentication/hmac"
	"github.com/georgeJobs/go-antpathmatcher"
)

var makeHMACRequestFunc = makeHMACRequest

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
