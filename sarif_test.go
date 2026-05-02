package sarif_test

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/sarif"
)

func TestUnmarshalReport(t *testing.T) {
	sarifFiles := []string{}

	if err := filepath.WalkDir("static", func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			if strings.HasSuffix(d.Name(), ".sarif") || strings.HasSuffix(d.Name(), ".sarif.json") {
				sarifFiles = append(sarifFiles, path)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for _, v := range sarifFiles {
		_, er := sarif.OpenReport(v)
		if er != nil {
			t.Logf("failed to read %v sarif report", v)
			t.Error(er)
		} else {
			t.Logf("Unmarshall test successful: %v\n", v)
		}
	}
}

func TestReport(t *testing.T) {
	report := sarif.NewReport()

	metadata := map[string]string{
		"payload":         "'sleep(10)--",
		"Severity Rating": "10",
	}

	// rule or template
	rule1 := sarif.ReportingDescriptor{
		Id:   "template1",
		Name: "SQL Injection CVE-2022-xx",
		ShortDescription: &sarif.MultiformatMessageString{
			Text: "SQL Injection Vulnerability due to Dependency",
		},
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Full Description of Vulnerability with references",
		},
		Help: &sarif.MultiformatMessageString{
			Text:     "SQL injections",
			Markdown: "# SQL injections\nInjections are _often_ caused by...",
		},
		HelpUri:    "https://www.cve.org/CVERecord?id=CVE-2020-xx",
		Properties: metadata,
	}

	report.RegisterTool(sarif.ToolComponent{
		Name:         "vulnscanner",
		Organization: "ProjectDiscovery",
		Product:      "Scanners",
		ShortDescription: &sarif.MultiformatMessageString{
			Text: "Vulnerability Scanner",
		},
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Template Based Vulnerability Scanner",
		},
		FullName:        "vulnscanner v2.1.1",
		SemanticVersion: "v2.1.1",
		InformationUri:  "https://github.com/projectdiscovery/nuclei",
		DownloadUri:     "https://github.com/projectdiscovery/xxx",
		Rules:           []sarif.ReportingDescriptor{rule1},
	})

	outfiles := sarif.ArtifactLocation{
		Uri: "file:///etc/passwd",
		Description: &sarif.Message{
			Text: "Generated using vulnscanner",
		},
	}

	report.RegisterToolInvocation(sarif.Invocation{
		CommandLine:         "vulnscanner",
		Arguments:           []string{"-sC", "-sV"},
		ResponseFiles:       []sarif.ArtifactLocation{outfiles},
		ExecutionSuccessful: true,
		WorkingDirectory: sarif.ArtifactLocation{
			Uri: "file:///opt",
		},
		EnvironmentVariables: map[string]string{
			"GOPROXY": "direct",
		},
	})

	loc := sarif.Location{
		Message: &sarif.Message{
			Text: "status.projectdiscovery.io",
		},
		PhysicalLocation: sarif.PhysicalLocation{
			Address: sarif.Address{
				Name:               "Address of Location",
				FullyQualifiedName: "Name of Address",
				Kind:               "parameter",
			},
			ArtifactLocation: sarif.ArtifactLocation{
				Uri: "https://projectdiscovery.com/api/user=admin'",
				Description: &sarif.Message{
					Text: "https://projectdiscovery.com/api/user=admin'",
				},
			},
		},
	}

	report.RegisterResult(sarif.Result{
		RuleId:    "template1",
		RuleIndex: 0,
		Level:     sarif.Error,
		Kind:      sarif.Review,
		AnalysisTarget: sarif.ArtifactLocation{
			Uri: "https://projectdiscovery.io",
		},
		Message: &sarif.Message{
			Text: "SQL Injection",
		},
		Rule: sarif.ReportingDescriptorReference{
			Id: "template1",
			ToolComponent: sarif.ToolComponent{
				Name:             "SQL Injection in xxx",
				ShortDescription: rule1.MessageStrings,
			},
		},
		Locations: []sarif.Location{loc},
	})

	if _, err := report.Export(); err != nil {
		t.Fatalf("failed to export report")
	}
}

func TestEmptyResultsReport(t *testing.T) {
	report := sarif.NewReport()

	metadata := map[string]string{
		"payload":         "'sleep(10)--",
		"Severity Rating": "10",
	}

	// rule or template
	rule1 := sarif.ReportingDescriptor{
		Id:   "template1",
		Name: "SQL Injection CVE-2022-xx",
		ShortDescription: &sarif.MultiformatMessageString{
			Text: "SQL Injection Vulnerability due to Dependency",
		},
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Full Description of Vulnerability with references",
		},
		HelpUri:    "https://www.cve.org/CVERecord?id=CVE-2020-xx",
		Properties: metadata,
	}

	report.RegisterTool(sarif.ToolComponent{
		Name:         "vulnscanner",
		Organization: "ProjectDiscovery",
		Product:      "Scanners",
		ShortDescription: &sarif.MultiformatMessageString{
			Text: "Vulnerability Scanner",
		},
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Template Based Vulnerability Scanner",
		},
		FullName:        "vulnscanner v2.1.1",
		SemanticVersion: "v2.1.1",
		InformationUri:  "https://github.com/projectdiscovery/nuclei",
		DownloadUri:     "https://github.com/projectdiscovery/xxx",
		Rules:           []sarif.ReportingDescriptor{rule1},
	})

	outfiles := sarif.ArtifactLocation{
		Uri: "file:///etc/passwd",
		Description: &sarif.Message{
			Text: "Generated using vulnscanner",
		},
	}

	report.RegisterToolInvocation(sarif.Invocation{
		CommandLine:         "vulnscanner",
		Arguments:           []string{"-sC", "-sV"},
		ResponseFiles:       []sarif.ArtifactLocation{outfiles},
		ExecutionSuccessful: true,
		WorkingDirectory: sarif.ArtifactLocation{
			Uri: "file:///opt",
		},
		EnvironmentVariables: map[string]string{
			"GOPROXY": "direct",
		},
	})

	if _, err := report.Export(); err != nil {
		t.Fatalf("failed to export report")
	}
}

func TestExportNormalizesValidatorCriticalFields(t *testing.T) {
	report := sarif.NewReport()

	report.RegisterTool(sarif.ToolComponent{
		Name:        "Nuclei",
		DownloadUri: "https://github.com/projectdiscovery/nuclei/releases",
		Rules: []sarif.ReportingDescriptor{
			{
				Id:   "ssh-sha1-hmac-algo",
				Name: "SSH SHA-1 HMAC Algorithms Enabled",
			},
		},
	})

	report.RegisterResult(sarif.Result{
		RuleId: "ssh-sha1-hmac-algo",
		Rule: sarif.ReportingDescriptorReference{
			Id: "ssh-sha1-hmac-algo",
		},
		Message: &sarif.Message{Text: "example result"},
		Locations: []sarif.Location{
			{
				PhysicalLocation: sarif.PhysicalLocation{
					ArtifactLocation: sarif.ArtifactLocation{Uri: "/"},
				},
			},
		},
	})

	out, err := report.Export()
	if err != nil {
		t.Fatalf("failed to export normalized report: %v", err)
	}

	var data map[string]any
	if err := json.Unmarshal(out, &data); err != nil {
		t.Fatalf("failed to decode exported report: %v", err)
	}

	runs := data["runs"].([]any)
	run := runs[0].(map[string]any)

	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	if driver["informationUri"] == "" {
		t.Fatalf("expected driver informationUri to be populated")
	}

	rules := driver["rules"].([]any)
	rule := rules[0].(map[string]any)
	help := rule["help"].(map[string]any)
	if strings.TrimSpace(help["text"].(string)) == "" {
		t.Fatalf("expected rule help text to be populated")
	}
	if strings.TrimSpace(rule["helpUri"].(string)) == "" {
		t.Fatalf("expected rule helpUri to be populated")
	}
	if rule["id"].(string) != "ssh-sha1-hmac-algo" {
		t.Fatalf("expected rule id to be preserved")
	}
	if rule["name"].(string) != "SSH SHA-1 HMAC Algorithms Enabled" {
		t.Fatalf("expected rule name to be preserved")
	}

	if _, ok := run["versionControlProvenance"]; !ok {
		t.Fatalf("expected versionControlProvenance to be populated")
	}
	versionControlProvenance := run["versionControlProvenance"].([]any)
	if len(versionControlProvenance) == 0 {
		t.Fatalf("expected at least one versionControlProvenance entry")
	}
	firstVersionControl := versionControlProvenance[0].(map[string]any)
	mappedTo := firstVersionControl["mappedTo"].(map[string]any)
	if strings.TrimSpace(mappedTo["uriBaseId"].(string)) == "" {
		t.Fatalf("expected versionControlProvenance.mappedTo.uriBaseId to be populated")
	}

	results := run["results"].([]any)
	result := results[0].(map[string]any)
	if _, ok := result["rule"]; ok {
		t.Fatalf("expected redundant result.rule property to be omitted")
	}
	message := result["message"].(map[string]any)
	if strings.TrimSpace(message["text"].(string)) == "" {
		t.Fatalf("expected result message text to be populated")
	}

	partialFingerprints := result["partialFingerprints"].(map[string]any)
	if len(partialFingerprints) == 0 {
		t.Fatalf("expected partialFingerprints to be populated")
	}

	locations := result["locations"].([]any)
	location := locations[0].(map[string]any)
	physicalLocation := location["physicalLocation"].(map[string]any)
	artifactLocation := physicalLocation["artifactLocation"].(map[string]any)
	if artifactLocation["uri"].(string) == "/" {
		t.Fatalf("expected leading slash URI to be normalized")
	}
	if strings.TrimSpace(artifactLocation["uriBaseId"].(string)) == "" {
		t.Fatalf("expected artifact location uriBaseId to be populated")
	}

	region := physicalLocation["region"].(map[string]any)
	if int(region["startLine"].(float64)) < 1 {
		t.Fatalf("expected region.startLine to be >= 1")
	}
	if _, ok := region["snippet"]; !ok {
		t.Fatalf("expected region snippet to be populated")
	}
	if _, ok := physicalLocation["contextRegion"]; !ok {
		t.Fatalf("expected contextRegion to be populated")
	}
}

func TestExportWithOptionsDefaultMatchesExport(t *testing.T) {
	report := sarif.NewReport()
	report.RegisterTool(sarif.ToolComponent{
		Name: "Nuclei",
		Rules: []sarif.ReportingDescriptor{
			{Id: "sample-rule", Name: "Sample Rule"},
		},
	})
	report.RegisterResult(sarif.Result{
		RuleId:  "sample-rule",
		Message: &sarif.Message{Text: "sample"},
		Locations: []sarif.Location{
			{PhysicalLocation: sarif.PhysicalLocation{ArtifactLocation: sarif.ArtifactLocation{Uri: "/"}}},
		},
	})

	defaultExport, err := report.Export()
	if err != nil {
		t.Fatalf("failed default export: %v", err)
	}

	optionExport, err := report.ExportWithOptions()
	if err != nil {
		t.Fatalf("failed option export: %v", err)
	}

	if string(defaultExport) != string(optionExport) {
		t.Fatalf("expected Export and ExportWithOptions defaults to be identical")
	}
}

func TestExportWithOptionsCanDisableNormalization(t *testing.T) {
	report := sarif.NewReport()
	report.RegisterTool(sarif.ToolComponent{
		Name: "Nuclei",
		Rules: []sarif.ReportingDescriptor{
			{Id: "custom-rule-id", Name: "Custom Rule Name"},
		},
	})
	report.RegisterResult(sarif.Result{
		RuleId:  "custom-rule-id",
		Message: &sarif.Message{Text: "example"},
		Locations: []sarif.Location{
			{PhysicalLocation: sarif.PhysicalLocation{ArtifactLocation: sarif.ArtifactLocation{Uri: "/"}}},
		},
	})

	normalizedOut, err := report.ExportWithOptions()
	if err != nil {
		t.Fatalf("failed normalized export: %v", err)
	}

	unnormalizedOut, err := report.ExportWithOptions(sarif.WithNormalization(false))
	if err != nil {
		t.Fatalf("failed unnormalized export: %v", err)
	}

	var normalizedData map[string]any
	if err := json.Unmarshal(normalizedOut, &normalizedData); err != nil {
		t.Fatalf("failed to decode normalized export: %v", err)
	}

	var unnormalizedData map[string]any
	if err := json.Unmarshal(unnormalizedOut, &unnormalizedData); err != nil {
		t.Fatalf("failed to decode unnormalized export: %v", err)
	}

	normalizedRun := normalizedData["runs"].([]any)[0].(map[string]any)
	unnormalizedRun := unnormalizedData["runs"].([]any)[0].(map[string]any)

	normalizedRule := normalizedRun["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	unnormalizedRule := unnormalizedRun["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)[0].(map[string]any)

	if normalizedRule["id"].(string) != "custom-rule-id" {
		t.Fatalf("expected normalized export to preserve original rule id")
	}
	if unnormalizedRule["id"].(string) != "custom-rule-id" {
		t.Fatalf("expected unnormalized export to keep original rule id")
	}

	normalizedResult := normalizedRun["results"].([]any)[0].(map[string]any)
	unnormalizedResult := unnormalizedRun["results"].([]any)[0].(map[string]any)

	if _, ok := normalizedResult["partialFingerprints"]; !ok {
		t.Fatalf("expected normalized export to add partialFingerprints")
	}
	if _, ok := unnormalizedResult["partialFingerprints"]; ok {
		t.Fatalf("expected unnormalized export to skip partialFingerprints synthesis")
	}

	normalizedURI := normalizedResult["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"].(string)
	unnormalizedURI := unnormalizedResult["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"].(string)

	if normalizedURI == "/" {
		t.Fatalf("expected normalized export to normalize leading slash URI")
	}
	if unnormalizedURI != "/" {
		t.Fatalf("expected unnormalized export to preserve original URI")
	}
}
