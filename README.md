# drone-Veracode

# Overview
This plugin performs a Veracode Upload and Scan operation using the official Veracode Java API Wrapper. It supports file filtering, scanning options, policy evaluations, proxy support, and job failure handling logic.

## Building

Build the plugin binary:

```text
scripts/build.sh
```

Build the plugin image:

```text
docker build -t plugins/veracode -f docker/Dockerfile .
```

🚀 Testing
You can run the plugin locally using:

```
docker run --rm \
  -e PLUGIN_APPLICATION_NAME="My App" \
  -e PLUGIN_CRITICALITY="VeryHigh" \
  -e PLUGIN_SANDBOX_NAME="Integration" \
  -e PLUGIN_TIMEOUT=10 \
  -e PLUGIN_CREATE_PROFILE=true \
  -e PLUGIN_TEAMS="SecurityTeam" \
  -e PLUGIN_CREATE_SANDBOX=true \
  -e PLUGIN_DEBUG=true \
  -e PLUGIN_UPLOAD_INCLUDES_PATTERN="**/*.jar" \
  -e PLUGIN_UPLOAD_EXCLUDES_PATTERN="**/test/**" \
  -e PLUGIN_SCAN_INCLUDES_PATTERN="**/*.jar" \
  -e PLUGIN_SCAN_EXCLUDES_PATTERN="**/test/**" \
  -e PLUGIN_FILE_NAME_PATTERN="*.jar" \
  -e PLUGIN_REPLACEMENT_PATTERN="*.zip" \
  -e PLUGIN_SCAN_ALL_NON_FATAL_TOP_LEVEL_MODULES=true \
  -e PLUGIN_INCLUDE_NEW_MODULES=true \
  -e PLUGIN_P_HOST="proxy.example.com" \
  -e PLUGIN_P_PORT="8080" \
  -e PLUGIN_P_USER="proxyuser" \
  -e PLUGIN_P_PASSWORD="proxypass" \
  -e PLUGIN_VID="veracode_api_id" \
  -e PLUGIN_VKEY="veracode_api_key" \
  -e PLUGIN_DELETE_INCOMPLETE_SCAN=true \
  -e PLUGIN_WAIT_FOR_SCAN=true \
  -e PLUGIN_TIMEOUT_FAILS_JOB=true \
  -e PLUGIN_UNSTABLE_BUILD=true \
  -e PLUGIN_CAN_FAIL_JOB=true \
  -e PLUGIN_USE_PROXY=true \
  -e PLUGIN_VERSION="build-123" \
  -e PLUGIN_LEVEL="info" \
  -v $(pwd):/drone/src \
  plugins/veracode
```

📦 Example Harness Step

```
- step:
    identifier: veracode-scan
    name: Veracode Static Scan
    spec:
      image: plugins/veracode
      settings:
        application_name: "My App"
        criticality: "VeryHigh"
        sandbox_name: "Integration"
        timeout: 15
        create_profile: true
        create_sandbox: true
        teams: "SecurityTeam"
        debug: true
        upload_includes_pattern: "**/*.jar"
        upload_excludes_pattern: "**/test/**"
        scan_includes_pattern: "**/*.jar"
        scan_excludes_pattern: "**/test/**"
        file_name_pattern: "*.jar"
        replacement_pattern: "*.zip"
        scan_all_non_fatal_top_level_modules: true
        include_new_modules: true
        p_host: "proxy.example.com"
        p_port: "8080"
        p_user: "proxyuser"
        p_password: "proxypass"
        vid: "veracode_api_id"
        vkey: "veracode_api_key"
        delete_incomplete_scan: true
        wait_for_scan: true
        timeout_fails_job: true
        unstable_build: true
        can_fail_job: true
        use_proxy: true
        version: "build-123"
        level: "info"
    timeout: '20m'
    type: Plugin
```

# Plugin Settings

- `PLUGIN_OPERATION_MODE`
Description: Defines the mode of operation for the plugin (veracode, resubmit, review, etc.).
Example: veracode

- `PLUGIN_APPLICATION_NAME`
Description: Name of the Veracode application to scan.
Example: My Application

- `PLUGIN_CRITICALITY`
Description: Criticality of the application (VeryHigh, High, Medium, Low, etc.).
Example: High

- `PLUGIN_SANDBOX_NAME`
Description: Optional sandbox name to use during the scan.
Example: Integration Sandbox

- `PLUGIN_TIMEOUT`
Description: Maximum timeout in minutes for the scan to complete.
Example: 15

- `PLUGIN_CREATE_PROFILE`
Description: If true, creates the application profile if it doesn't exist.
Example: true

- `PLUGIN_TEAMS`
Description: Comma-separated list of teams to associate with the scan.
Example: DevSecOps,QA

- `PLUGIN_CREATE_SANDBOX`
Description: If true, creates a sandbox if it does not exist.
Example: true

- `PLUGIN_DEBUG`
Description: Enable debug-level logs.
Example: true

- `PLUGIN_UPLOAD_INCLUDES_PATTERN`
Description: Comma-separated Ant-style file patterns to include for upload.
Example: /*.jar,/*.war

- `PLUGIN_UPLOAD_EXCLUDES_PATTERN`
Description: Comma-separated Ant-style file patterns to exclude from upload.
Example: /test/,/docs/

- `PLUGIN_SCAN_INCLUDES_PATTERN`
Description: Pattern to include specific modules during scan.
Example: *.jar

- `PLUGIN_SCAN_EXCLUDES_PATTERN`
Description: Pattern to exclude specific modules from scan.
Example: *-test.jar

- `PLUGIN_FILE_NAME_PATTERN`
Description: Pattern used for renaming files during upload.
Example: *.jar

- `PLUGIN_REPLACEMENT_PATTERN`
Description: Pattern to replace file name strings (used with PLUGIN_FILE_NAME_PATTERN).
Example: *.zip

- `PLUGIN_SCAN_ALL_NON_FATAL_TOP_LEVEL_MODULES`
Description: If true, scan all non-fatal top-level modules.
Example: true

- `PLUGIN_INCLUDE_NEW_MODULES`
Description: If true, includes new modules found during the scan.
Example: true

- `PLUGIN_P_HOST`
Description: Proxy host to use for outbound Veracode traffic.
Example: proxy.example.com

- `PLUGIN_P_PORT`
Description: Proxy port to use.
Example: 8080

- `PLUGIN_P_USER`
Description: Username for authenticating with the proxy.
Example: proxyuser

- `PLUGIN_P_PASSWORD`
Description: Password for the proxy user.
Example: proxypassword

- `PLUGIN_VID`
Description: Veracode API ID used for authentication.
Example: abc123xyz

- `PLUGIN_VKEY`
Description: Veracode API Key used for authentication.
Example: secret-api-key

- `PLUGIN_DELETE_INCOMPLETE_SCAN`
Description: If true, deletes any existing incomplete scan before starting a new one.
Example: true

- `PLUGIN_WAIT_FOR_SCAN`
Description: If true, the plugin will wait until the scan finishes and retrieves the result.
Example: true

- `PLUGIN_TIMEOUT_FAILS_JOB`
Description: If true, the job will fail if the scan times out.
Example: true

- `PLUGIN_CAN_FAIL_JOB`
Description: If true, scan failure will fail the job; if false, it only logs warnings.
Example: true

- `PLUGIN_USE_PROXY`
Description: If true, enables proxy settings for the scan.
Example: true

- `PLUGIN_VERSION`
Description: Version name to associate with the scan.
Example: v1.0.0-build123

- `PLUGIN_LEVEL`
Description: Defines the plugin log level (debug, info, warn, etc.).
Example: info

- `PLUGIN_WORKSPACE`
Description: Workspace path where the plugin operates (generally set by CI/CD pipeline).
Example: /drone/src

- `PLUGIN_ANALYSIS_NAME`
Description: The name of the Dynamic Analysis to be reviewed or resubmitted.
Example: my-analysis-01

- `PLUGIN_MAXIMUM_DURATION`
Description: Maximum duration (in days) to wait before timing out resubmitted scans.
Example: 3

- `PLUGIN_FAIL_BUILD_AS_SCAN_FAILED`
Description: If true, fails the build if the scan itself fails.
Example: false

- `PLUGIN_WAIT_FOR_RESULTS_DURATION`
Description: Duration in minutes to wait for results of a Dynamic Analysis review.
Example: 60

- `PLUGIN_FAIL_BUILD_FOR_POLICY_VIOLATION`
Description: If true, policy violations during review fail the build.
Example: false