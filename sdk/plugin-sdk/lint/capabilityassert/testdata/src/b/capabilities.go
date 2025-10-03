package b

import pluginsdk "github.com/RowanDark/Glyph/sdk/plugin-sdk"

var CapabilityMacros = pluginsdk.CapabilitySet{
	EmitFindings:  true,
	HTTPPassive:   true,
	WorkspaceRead: false,
	NetOutbound:   false,
}
