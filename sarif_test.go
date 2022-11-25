package sarif_test

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/sarif"
)

func Test_UnmarshalReport(t *testing.T) {
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

func Test_Report(t *testing.T) {
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
		DownloadURI:     "https://github.com/projectdiscovery/xxx",
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
