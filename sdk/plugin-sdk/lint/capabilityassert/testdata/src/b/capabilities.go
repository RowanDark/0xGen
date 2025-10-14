package b

import pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"

var CapabilityMacros = pluginsdk.CapabilitySet{
	EmitFindings:  true,
	HTTPPassive:   true,
	WorkspaceRead: false,
	NetOutbound:   false,
}
