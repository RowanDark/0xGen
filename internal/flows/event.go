package flows

import (
	pb "github.com/RowanDark/Glyph/proto/gen/go/proto/glyph"
)

// Event encapsulates an intercepted HTTP flow destined for plugin consumers.
// Sanitized contains a redacted representation suitable for plugins with the
// CAP_FLOW_INSPECT capability, while Raw retains the original bytes for plugins
// granted CAP_FLOW_INSPECT_RAW.
type Event struct {
	Type      pb.FlowEvent_Type
	Sanitized []byte
	Raw       []byte
}

// Clone returns a deep copy of the event payload to ensure downstream
// consumers cannot mutate the shared buffers.
func (e Event) Clone() Event {
	clone := Event{Type: e.Type}
	if len(e.Sanitized) > 0 {
		clone.Sanitized = append([]byte(nil), e.Sanitized...)
	}
	if len(e.Raw) > 0 {
		clone.Raw = append([]byte(nil), e.Raw...)
	}
	return clone
}
