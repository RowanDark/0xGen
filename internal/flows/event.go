package flows

import (
	"time"

	pb "github.com/RowanDark/0xgen/proto/gen/go/proto/glyph"
)

// Event encapsulates an intercepted HTTP flow destined for plugin consumers.
// Sanitized contains a redacted representation suitable for plugins with the
// CAP_FLOW_INSPECT capability, while Raw retains the original bytes for plugins
// granted CAP_FLOW_INSPECT_RAW. Metadata fields capture ordering and
// truncation information to support replay.
type Event struct {
	ID                string
	Sequence          uint64
	Timestamp         time.Time
	Type              pb.FlowEvent_Type
	Sanitized         []byte
	Raw               []byte
	RawBodySize       int
	RawBodyCaptured   int
	SanitizedRedacted bool
}

// Clone returns a deep copy of the event payload to ensure downstream
// consumers cannot mutate the shared buffers.
func (e Event) Clone() Event {
	clone := Event{
		ID:                e.ID,
		Sequence:          e.Sequence,
		Timestamp:         e.Timestamp,
		Type:              e.Type,
		RawBodySize:       e.RawBodySize,
		RawBodyCaptured:   e.RawBodyCaptured,
		SanitizedRedacted: e.SanitizedRedacted,
	}
	if len(e.Sanitized) > 0 {
		clone.Sanitized = append([]byte(nil), e.Sanitized...)
	}
	if len(e.Raw) > 0 {
		clone.Raw = append([]byte(nil), e.Raw...)
	}
	return clone
}
