package pluginsdk

// CapabilitySet centralises capability declarations for plugin scaffolds.
type CapabilitySet struct {
	EmitFindings   bool
	HTTPPassive    bool
	AIAnalysis     bool
	FlowInspect    bool
	FlowInspectRaw bool
	WorkspaceRead  bool
	WorkspaceWrite bool
	NetOutbound    bool
	SecretsRead    bool
}

// List returns the enabled capabilities as a slice suitable for manifests or configs.
func (s CapabilitySet) List() []Capability {
	caps := make([]Capability, 0, 8)
	if s.EmitFindings {
		caps = append(caps, CapabilityEmitFindings)
	}
	if s.HTTPPassive {
		caps = append(caps, CapabilityHTTPPassive)
	}
	if s.AIAnalysis {
		caps = append(caps, CapabilityAIAnalysis)
	}
	if s.FlowInspect {
		caps = append(caps, CapabilityFlowInspect)
	}
	if s.FlowInspectRaw {
		caps = append(caps, CapabilityFlowInspectRaw)
	}
	if s.WorkspaceRead {
		caps = append(caps, CapabilityWorkspaceRead)
	}
	if s.WorkspaceWrite {
		caps = append(caps, CapabilityWorkspaceWrite)
	}
	if s.NetOutbound {
		caps = append(caps, CapabilityNetOutbound)
	}
	if s.SecretsRead {
		caps = append(caps, CapabilitySecretsRead)
	}
	return caps
}

// Enabled reports whether the provided capability is present in the set.
func (s CapabilitySet) Enabled(cap Capability) bool {
	switch cap {
	case CapabilityEmitFindings:
		return s.EmitFindings
	case CapabilityHTTPPassive:
		return s.HTTPPassive
	case CapabilityAIAnalysis:
		return s.AIAnalysis
	case CapabilityFlowInspect:
		return s.FlowInspect
	case CapabilityFlowInspectRaw:
		return s.FlowInspectRaw
	case CapabilityWorkspaceRead:
		return s.WorkspaceRead
	case CapabilityWorkspaceWrite:
		return s.WorkspaceWrite
	case CapabilityNetOutbound:
		return s.NetOutbound
	case CapabilitySecretsRead:
		return s.SecretsRead
	default:
		return false
	}
}
