package reporter

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/RowanDark/0xgen/internal/findings"
)

// XMLReport represents the root XML structure for a security report.
type XMLReport struct {
	XMLName  xml.Name    `xml:"SecurityReport"`
	Version  string      `xml:"version,attr"`
	Summary  XMLSummary  `xml:"Summary"`
	Findings []XMLFinding `xml:"Findings>Finding"`
}

// XMLSummary contains aggregate statistics.
type XMLSummary struct {
	Total         int                   `xml:"TotalFindings"`
	GeneratedAt   string                `xml:"GeneratedAt"`
	WindowStart   string                `xml:"WindowStart,omitempty"`
	WindowEnd     string                `xml:"WindowEnd"`
	SeverityBreakdown XMLSeverityBreakdown `xml:"SeverityBreakdown"`
}

// XMLSeverityBreakdown contains counts by severity.
type XMLSeverityBreakdown struct {
	Critical int `xml:"Critical"`
	High     int `xml:"High"`
	Medium   int `xml:"Medium"`
	Low      int `xml:"Low"`
	Info     int `xml:"Info"`
}

// XMLFinding represents a single security finding.
type XMLFinding struct {
	ID         string         `xml:"ID,attr"`
	Severity   string         `xml:"Severity"`
	Type       string         `xml:"Type"`
	Message    string         `xml:"Message"`
	Target     string         `xml:"Target,omitempty"`
	Evidence   string         `xml:"Evidence,omitempty"`
	Plugin     string         `xml:"Plugin"`
	DetectedAt string         `xml:"DetectedAt"`
	Metadata   []XMLMetadata  `xml:"Metadata>Entry,omitempty"`
}

// XMLMetadata represents a key-value metadata pair.
type XMLMetadata struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// RenderXML generates an XML export of findings.
func RenderXML(list []findings.Finding, opts ReportOptions) ([]byte, error) {
	summary, filteredList, _, windowStart := buildSummary(list, opts)

	// Build XML report structure
	xmlReport := XMLReport{
		Version: "1.0",
		Summary: XMLSummary{
			Total:       summary.Total,
			GeneratedAt: summary.GeneratedAt.Format("2006-01-02T15:04:05Z"),
			WindowEnd:   summary.WindowEnd.Format("2006-01-02T15:04:05Z"),
			SeverityBreakdown: XMLSeverityBreakdown{
				Critical: summary.SeverityCount[findings.SeverityCritical],
				High:     summary.SeverityCount[findings.SeverityHigh],
				Medium:   summary.SeverityCount[findings.SeverityMedium],
				Low:      summary.SeverityCount[findings.SeverityLow],
				Info:     summary.SeverityCount[findings.SeverityInfo],
			},
		},
		Findings: make([]XMLFinding, 0, len(filteredList)),
	}

	if windowStart != nil {
		xmlReport.Summary.WindowStart = windowStart.Format("2006-01-02T15:04:05Z")
	}

	// Convert findings to XML format
	for _, f := range filteredList {
		xmlFinding := XMLFinding{
			ID:         f.ID,
			Severity:   string(f.Severity),
			Type:       f.Type,
			Message:    f.Message,
			Target:     f.Target,
			Evidence:   f.Evidence,
			Plugin:     f.Plugin,
			DetectedAt: f.DetectedAt.Time().Format("2006-01-02T15:04:05Z"),
		}

		// Add metadata if present
		if len(f.Metadata) > 0 {
			xmlFinding.Metadata = make([]XMLMetadata, 0, len(f.Metadata))
			for k, v := range f.Metadata {
				xmlFinding.Metadata = append(xmlFinding.Metadata, XMLMetadata{
					Key:   k,
					Value: v,
				})
			}
		}

		xmlReport.Findings = append(xmlReport.Findings, xmlFinding)
	}

	// Marshal to XML with indentation
	data, err := xml.MarshalIndent(xmlReport, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal XML: %w", err)
	}

	// Add XML header
	header := []byte(xml.Header)
	result := append(header, data...)
	result = append(result, '\n')

	return result, nil
}

// WriteXML writes XML output to a writer.
func WriteXML(w io.Writer, list []findings.Finding, opts ReportOptions) error {
	data, err := RenderXML(list, opts)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
