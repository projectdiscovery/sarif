package main

import (
	"log"
	"os"

	"github.com/projectdiscovery/sarif"
)

func main() {
	// create new sarif report
	report := sarif.NewReport()
	// Extra metadata can be added to any type of sarif
	extrametadata := map[string]string{
		"payload":         "'sleep(10)--",
		"Severity Rating": "10",
	}

	// to create new tool/template/plugin
	rule1 := sarif.ReportingDescriptor{
		Id:   "template1",
		Name: "SQL Injection CVE-2022-xx",
		ShortDescription: &sarif.MultiformatMessageString{
			Text: "SQL Injection Vulnerability due to Dependency",
		},
		FullDescription: &sarif.MultiformatMessageString{
			Text: "Full Description of Vulnerability with references",
		},
		Properties: extrametadata,
	}

	// register details of the static analysis tool
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
		// The order of rules/templates/plugins is important here
		// this index is referenced when a result/vulnerability is found
	})

	// Output of static analysis tool
	outfiles := sarif.ArtifactLocation{
		Uri: "file:///var/log/xxx.log",
		Description: &sarif.Message{
			Text: "Generated using vulnscanner",
		},
	}

	// to register tool invocation and env
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

	// locations of a particular target can be linked to result
	// using sarif.Location
	location := sarif.Location{
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

	// Register results with severity etc
	report.RegisterResult(sarif.Result{
		RuleId:    "template1",
		RuleIndex: 0,
		Level:     sarif.Error,
		Kind:      sarif.Open,
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
		Locations: []sarif.Location{location},
	})

	bin, err := report.Export()
	if err != nil {
		log.Fatalf("failed to export report")
	}

	if err = os.WriteFile("sql_report.sarif", bin, 0644); err != nil {
		log.Fatalf("failed to write file generated.sarif %v", err)
	}

	log.Printf("Report sql_report.sarif created")
}
