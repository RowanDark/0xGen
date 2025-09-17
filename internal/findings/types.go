package findings

import "time"

// Finding represents a single issue reported by a plugin.
type Finding struct {
	ID       string
	Plugin   string
	Target   string
	Evidence string
	Severity string    // info|low|med|high|crit
	TS       time.Time // timestamp of when the finding was recorded
}
