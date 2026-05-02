package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

const (
	defaultSchemaURI      = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json"
	defaultToolInfoURI    = "https://github.com/projectdiscovery/sarif"
	defaultRevisionID     = "unknown"
	defaultRuleIDPrefix   = "PD"
	defaultRepoRootBaseID = "%SRCROOT%"
	lineFingerprintName   = "primaryLocationLineHash"
)

var (
	ruleWordPattern = regexp.MustCompile(`[A-Za-z0-9]+`)
)

// Report encapsulates SarifLog Object and generates .sarif Report
type Report struct {
	Sarif *SarifLog // SarifLog Object
	run   Run       // Describes a single run of an analysis tool
}

type exportOptions struct {
	normalize        bool
	pruneEmptyObject bool
}

// ExportOption customizes ExportWithOptions behavior.
type ExportOption func(*exportOptions)

func defaultExportOptions() exportOptions {
	return exportOptions{
		normalize:        true,
		pruneEmptyObject: true,
	}
}

func resolveExportOptions(opts ...ExportOption) exportOptions {
	resolved := defaultExportOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&resolved)
		}
	}
	return resolved
}

// WithNormalization enables or disables SARIF normalization.
func WithNormalization(enabled bool) ExportOption {
	return func(options *exportOptions) {
		options.normalize = enabled
	}
}

// WithEmptyObjectPruning enables or disables post-export empty object pruning.
func WithEmptyObjectPruning(enabled bool) ExportOption {
	return func(options *exportOptions) {
		options.pruneEmptyObject = enabled
	}
}

// RegisterTool registers tool details
func (r *Report) RegisterTool(driver ToolComponent) {
	r.run.Tool.Driver = driver
}

// RegisterToolExtension registers tool plugins/extensions/templates
func (r *Report) RegisterToolExtension(extensions []ToolComponent) {
	r.run.Tool.Extensions = extensions
}

// RegisterToolInvocation registers runtime environment when tool was run
func (r *Report) RegisterToolInvocation(invocation Invocation) {
	r.run.Invocations = append(r.run.Invocations, invocation)
}

// RegisterResult registers result
func (r *Report) RegisterResult(result Result) {
	r.run.Result = append(r.run.Result, result)
}

// Export
func (r *Report) Export() ([]byte, error) {
	return r.ExportWithOptions()
}

// ExportWithOptions exports a SARIF report with optional normalization controls.
func (r *Report) ExportWithOptions(opts ...ExportOption) ([]byte, error) {
	options := resolveExportOptions(opts...)

	log := SarifLog{
		Version: r.Sarif.Version,
		Schema:  r.Sarif.Schema,
		Runs:    append([]Run{}, r.Sarif.Runs...),
	}

	if !isRunZeroValue(r.run) {
		log.Runs = append(log.Runs, r.run)
	}

	if options.normalize {
		clonedLog, err := cloneSarifLog(log)
		if err != nil {
			return nil, err
		}
		log = clonedLog
		normalizeLog(&log)
	}

	if options.pruneEmptyObject {
		return marshalNormalizedLog(log)
	}

	return json.MarshalIndent(log, "", "\t")
}

func cloneSarifLog(source SarifLog) (SarifLog, error) {
	raw, err := json.Marshal(source)
	if err != nil {
		return SarifLog{}, err
	}

	var cloned SarifLog
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return SarifLog{}, err
	}

	return cloned, nil
}

// NewReport Creates New Report Instance
func NewReport() *Report {
	sf := SarifLog{
		Version: "2.1.0",
		Schema:  defaultSchemaURI,
		Runs:    []Run{},
	}

	sarifExporter := Report{
		Sarif: &sf,
	}
	run := Run{
		Invocations: []Invocation{},
		Result:      []Result{},
	}
	sarifExporter.run = run

	return &sarifExporter
}

func OpenReport(filename string) (*Report, error) {
	var sarifObject SarifLog

	bin, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(bin, &sarifObject); err != nil {
		return nil, err
	}
	report := Report{
		Sarif: &sarifObject,
	}
	return &report, nil
}

func normalizeLog(log *SarifLog) {
	log.Schema = defaultSchemaURI

	for i := range log.Runs {
		normalizeRun(&log.Runs[i])
	}
}

func normalizeRun(run *Run) {
	normalizeToolComponent(&run.Tool.Driver)
	for i := range run.Tool.Extensions {
		normalizeToolComponent(&run.Tool.Extensions[i])
	}

	versionControlProvenanceCheck(run)

	for i := range run.Result {
		normalizeResult(&run.Result[i])
	}
}

func normalizeToolComponent(component *ToolComponent) {
	ruleIDPrefix := ruleIDPrefixFromToolName(component.Name)

	defaultRuleHelpURI := component.InformationUri
	if strings.TrimSpace(defaultRuleHelpURI) == "" {
		defaultRuleHelpURI = defaultToolInfoURI
	}

	for i := range component.Rules {
		rule := &component.Rules[i]
		originalRuleID := strings.TrimSpace(rule.Id)
		if originalRuleID == "" {
			originalRuleID = fmt.Sprintf("%s%d", ruleIDPrefix, i+1)
		}
		rule.Id = originalRuleID

		normalizeReportingDescriptor(rule, defaultRuleHelpURI)
	}
}

func versionControlProvenanceCheck(run *Run) {
	repositoryURI := strings.TrimSpace(run.Tool.Driver.InformationUri)
	if repositoryURI == "" {
		repositoryURI = strings.TrimSpace(run.Tool.Driver.DownloadUri)
	}
	if repositoryURI == "" {
		repositoryURI = defaultToolInfoURI
	}

	if len(run.VersionControlProvenance) == 0 {
		detail := VersionControlDetail{RepositoryURI: repositoryURI}
		normalizeVersionControlDetail(&detail, repositoryURI)
		run.VersionControlProvenance = []VersionControlDetail{detail}
		return
	}

	for i := range run.VersionControlProvenance {
		normalizeVersionControlDetail(&run.VersionControlProvenance[i], repositoryURI)
	}
}

func normalizeVersionControlDetail(detail *VersionControlDetail, defaultRepositoryURI string) {
	if strings.TrimSpace(detail.RepositoryURI) == "" {
		detail.RepositoryURI = defaultRepositoryURI
	}
	if strings.TrimSpace(detail.RevisionID) == "" {
		detail.RevisionID = defaultRevisionID
	}
	if strings.TrimSpace(detail.MappedTo.Uri) == "" {
		detail.MappedTo.Uri = "."
	}
	if strings.TrimSpace(detail.MappedTo.UriBaseId) == "" {
		detail.MappedTo.UriBaseId = defaultRepoRootBaseID
	}
}

func ruleIDPrefixFromToolName(toolName string) string {
	words := ruleWordPattern.FindAllString(toolName, -1)
	if len(words) == 0 {
		return defaultRuleIDPrefix
	}

	if len(words) == 1 {
		runes := []rune(strings.ToUpper(words[0]))
		letters := make([]rune, 0, len(runes))
		for _, r := range runes {
			if unicode.IsLetter(r) {
				letters = append(letters, r)
			}
		}

		switch {
		case len(letters) >= 3:
			return string(letters[:3])
		case len(letters) == 2:
			return string(letters)
		case len(letters) == 1:
			return string([]rune{letters[0], 'R'})
		}
	}

	builder := strings.Builder{}
	for _, word := range words {
		if word == "" {
			continue
		}
		runeWord := []rune(word)
		if len(runeWord) == 0 {
			continue
		}
		if unicode.IsLetter(runeWord[0]) {
			builder.WriteRune(unicode.ToUpper(runeWord[0]))
		}
		if builder.Len() >= 3 {
			break
		}
	}

	prefix := builder.String()
	if prefix == "" {
		return defaultRuleIDPrefix
	}

	if len(prefix) < 2 {
		prefix += "R"
	}

	return prefix
}

func normalizeReportingDescriptor(rule *ReportingDescriptor, defaultHelpURI string) {
	if rule.ShortDescription == nil {
		shortText := strings.TrimSpace(rule.Name)
		if shortText == "" {
			shortText = strings.TrimSpace(rule.Id)
		}
		if shortText != "" {
			rule.ShortDescription = &MultiformatMessageString{Text: shortText}
		}
	}

	if rule.FullDescription == nil {
		fullText := ""
		if rule.ShortDescription != nil {
			fullText = strings.TrimSpace(rule.ShortDescription.Text)
		}
		if fullText == "" {
			fullText = strings.TrimSpace(rule.Name)
		}
		if fullText == "" {
			fullText = strings.TrimSpace(rule.Id)
		}
		if fullText != "" {
			rule.FullDescription = &MultiformatMessageString{Text: fullText}
		}
	}

	if rule.Help == nil {
		rule.Help = &MultiformatMessageString{}
	}

	if strings.TrimSpace(rule.Help.Text) == "" {
		helpText := ""
		if rule.FullDescription != nil {
			helpText = strings.TrimSpace(rule.FullDescription.Text)
		}
		if helpText == "" && rule.ShortDescription != nil {
			helpText = strings.TrimSpace(rule.ShortDescription.Text)
		}
		if helpText == "" {
			helpText = strings.TrimSpace(rule.Name)
		}
		if helpText == "" {
			helpText = strings.TrimSpace(rule.Id)
		}
		rule.Help.Text = helpText
	}

	if strings.TrimSpace(rule.HelpUri) == "" {
		rule.HelpUri = defaultHelpURI
	}
}

func normalizeResult(result *Result) {
	if strings.TrimSpace(result.RuleId) == "" && strings.TrimSpace(result.Rule.Id) != "" {
		result.RuleId = result.Rule.Id
	}

	normalizeResultMessage(result)

	if shouldDropRuleReference(*result) {
		result.Rule = ReportingDescriptorReference{}
	}

	for i := range result.Locations {
		normalizeLocation(&result.Locations[i])
	}

	partialFingerprintsCheck(result)
}

func shouldDropRuleReference(result Result) bool {
	if strings.TrimSpace(result.RuleId) == "" {
		return false
	}

	if !isToolComponentZeroValue(result.Rule.ToolComponent) {
		return false
	}

	if result.Rule.GUID != "" || result.Rule.Index != 0 || result.Rule.Properties != nil {
		return false
	}

	ruleRefID := strings.TrimSpace(result.Rule.Id)
	return ruleRefID == "" || ruleRefID == strings.TrimSpace(result.RuleId)
}

func normalizeLocation(location *Location) {
	uri := normalizeArtifactURI(location.PhysicalLocation.ArtifactLocation.Uri)
	location.PhysicalLocation.ArtifactLocation.Uri = uri
	if strings.TrimSpace(location.PhysicalLocation.ArtifactLocation.UriBaseId) == "" && isRelativeURI(uri) {
		location.PhysicalLocation.ArtifactLocation.UriBaseId = defaultRepoRootBaseID
	}

	if location.PhysicalLocation.Region == nil {
		location.PhysicalLocation.Region = &Region{StartLine: 1}
	}

	if location.PhysicalLocation.Region.StartLine < 1 {
		location.PhysicalLocation.Region.StartLine = 1
	}

	if location.PhysicalLocation.Region.EndLine > 0 && location.PhysicalLocation.Region.EndLine < location.PhysicalLocation.Region.StartLine {
		location.PhysicalLocation.Region.EndLine = location.PhysicalLocation.Region.StartLine
	}

	if location.PhysicalLocation.Region.Snippet == nil {
		snippetText := deriveLocationSnippet(location)
		location.PhysicalLocation.Region.Snippet = &ArtifactContent{Text: snippetText}
	}

	if location.PhysicalLocation.ContextRegion == nil {
		contextRegion := *location.PhysicalLocation.Region
		if contextRegion.StartLine < 1 {
			contextRegion.StartLine = 1
		}
		if contextRegion.EndLine < contextRegion.StartLine {
			contextRegion.EndLine = contextRegion.StartLine + 2
		}
		location.PhysicalLocation.ContextRegion = &contextRegion
	}
}

func normalizeResultMessage(result *Result) {
	if result.Message == nil {
		return
	}

	messageText := strings.TrimSpace(result.Message.Text)
	if messageText != "" {
		result.Message.Text = messageText
		return
	}

	if markdown := strings.TrimSpace(result.Message.Markdown); markdown != "" {
		result.Message.Text = markdown
		return
	}

	for _, argument := range result.Message.Arguments {
		if strings.TrimSpace(argument) != "" {
			result.Message.Text = strings.TrimSpace(argument)
			return
		}
	}

	if strings.TrimSpace(result.Message.Id) != "" {
		result.Message.Text = strings.TrimSpace(result.Message.Id)
		return
	}

	result.Message.Text = "result"
}

func deriveLocationSnippet(location *Location) string {
	if location.Message != nil {
		locationText := strings.TrimSpace(location.Message.Text)
		if locationText != "" {
			return locationText
		}
	}

	artifactDescription := location.PhysicalLocation.ArtifactLocation.Description
	if artifactDescription != nil {
		descriptionText := strings.TrimSpace(artifactDescription.Text)
		if descriptionText != "" {
			return descriptionText
		}
	}

	artifactURI := strings.TrimSpace(location.PhysicalLocation.ArtifactLocation.Uri)
	if artifactURI != "" {
		return artifactURI
	}

	return "source unavailable"
}

func normalizeArtifactURI(uri string) string {
	uri = strings.TrimSpace(strings.ReplaceAll(uri, "\\", "/"))
	if uri == "" {
		return "."
	}

	if strings.HasPrefix(uri, "/") {
		trimmed := strings.TrimLeft(uri, "/")
		if trimmed == "" {
			return "."
		}
		return trimmed
	}

	return uri
}

func isRelativeURI(uri string) bool {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return true
	}

	if strings.Contains(uri, "://") || strings.HasPrefix(uri, "file:") || strings.HasPrefix(uri, "urn:") {
		return false
	}

	if len(uri) > 1 && uri[1] == ':' {
		return false
	}

	return true
}

func partialFingerprintsCheck(result *Result) {
	if len(result.PartialFingerprints) > 0 {
		return
	}

	seed := []string{
		strings.TrimSpace(result.RuleId),
	}

	if result.Message != nil {
		seed = append(seed,
			strings.TrimSpace(result.Message.Id),
			strings.TrimSpace(result.Message.Text),
			strings.TrimSpace(result.Message.Markdown),
			strings.Join(result.Message.Arguments, "|"),
		)
	}

	if len(result.Locations) > 0 {
		location := result.Locations[0]
		seed = append(seed, strings.TrimSpace(location.PhysicalLocation.ArtifactLocation.Uri))
		if location.PhysicalLocation.Region != nil {
			seed = append(seed, strconv.Itoa(location.PhysicalLocation.Region.StartLine), strconv.Itoa(location.PhysicalLocation.Region.StartColumn))
		}
	}

	digest := sha256.Sum256([]byte(strings.Join(seed, "|")))
	result.PartialFingerprints = map[string]string{
		lineFingerprintName: hex.EncodeToString(digest[:16]),
	}
}

func marshalNormalizedLog(log SarifLog) ([]byte, error) {
	raw, err := json.Marshal(log)
	if err != nil {
		return nil, err
	}

	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}

	cleaned, ok := pruneEmptyJSONObjects(payload)
	if !ok {
		return json.MarshalIndent(log, "", "\t")
	}

	return json.MarshalIndent(cleaned, "", "\t")
}

func pruneEmptyJSONObjects(value any) (any, bool) {
	switch v := value.(type) {
	case map[string]any:
		cleaned := make(map[string]any, len(v))
		for key, item := range v {
			normalized, keep := pruneEmptyJSONObjects(item)
			if keep {
				cleaned[key] = normalized
			}
		}
		if len(cleaned) == 0 {
			return nil, false
		}
		return cleaned, true
	case []any:
		cleaned := make([]any, 0, len(v))
		for _, item := range v {
			normalized, keep := pruneEmptyJSONObjects(item)
			if keep {
				cleaned = append(cleaned, normalized)
			}
		}
		return cleaned, true
	case nil:
		return nil, false
	default:
		return value, true
	}
}

func isRunZeroValue(run Run) bool {
	return isToolZeroValue(run.Tool) && len(run.Result) == 0 && len(run.Invocations) == 0
}

func isToolZeroValue(tool Tool) bool {
	return isToolComponentZeroValue(tool.Driver) && len(tool.Extensions) == 0 && tool.Properties == nil
}

func isToolComponentZeroValue(component ToolComponent) bool {
	return component.GUID == "" &&
		component.Name == "" &&
		component.Organization == "" &&
		component.Product == "" &&
		component.ShortDescription == nil &&
		component.FullDescription == nil &&
		component.FullName == "" &&
		component.SemanticVersion == "" &&
		component.ReleaseDateUTC == "" &&
		component.DownloadUri == "" &&
		component.InformationUri == "" &&
		len(component.Notifications) == 0 &&
		len(component.Rules) == 0 &&
		len(component.Locations) == 0 &&
		component.Properties == nil
}
