// Package models defines the shared data types used across all CMMC audit agents.
package models

import "time"

// Domain represents a CMMC Level 2 domain abbreviation.
type Domain string

const (
	DomainAC Domain = "AC" // Access Control
	DomainAT Domain = "AT" // Awareness and Training
	DomainAU Domain = "AU" // Audit and Accountability
	DomainCM Domain = "CM" // Configuration Management
	DomainIA Domain = "IA" // Identification and Authentication
	DomainIR Domain = "IR" // Incident Response
	DomainMA Domain = "MA" // Maintenance
	DomainMP Domain = "MP" // Media Protection
	DomainPE Domain = "PE" // Physical Protection
	DomainPS Domain = "PS" // Personnel Security
	DomainRA Domain = "RA" // Risk Assessment
	DomainCA Domain = "CA" // Security Assessment
	DomainSC Domain = "SC" // System and Communications Protection
	DomainSI Domain = "SI" // System and Information Integrity
)

// Severity represents the risk level of a compliance finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Status represents whether a control check passed, failed, or was skipped.
type Status string

const (
	StatusCompliant    Status = "COMPLIANT"
	StatusNonCompliant Status = "NON_COMPLIANT"
	StatusNotChecked   Status = "NOT_CHECKED"
)

// Control represents a single CMMC Level 2 practice.
type Control struct {
	ID          string // e.g. "AC.L2-3.1.1"
	Domain      Domain
	Title       string
	Description string
	NISTRef     string // NIST SP 800-171 Rev 2 reference
}

// Finding represents a single compliance finding produced by the scanner.
type Finding struct {
	Control     Control
	Status      Status
	Severity    Severity
	Details     string
	Remediation string
	CheckedAt   time.Time
	Host        string
}

// RemediationTask represents a hardening action generated for a non-compliant finding.
type RemediationTask struct {
	Finding   Finding
	Action    string // human-readable description of what will be done
	Command   string // shell command (or script) that performs the fix
	Applied   bool
	AppliedAt time.Time
	Error     string // non-empty when apply failed
}

// TestResult represents the outcome of a post-hardening verification test.
type TestResult struct {
	Control  Control
	Passed   bool
	Status   Status // original compliance status from the re-scan
	Details  string
	TestedAt time.Time
}

// ComplianceScore summarises aggregate compliance metrics for a report.
type ComplianceScore struct {
	Total        int
	Compliant    int
	NonCompliant int
	NotChecked   int
	Percentage   float64
}

// Report represents a complete, point-in-time CMMC L2 audit report.
type Report struct {
	Title       string
	GeneratedAt time.Time
	Host        string
	Findings    []Finding
	Score       ComplianceScore
	Summary     string
}
