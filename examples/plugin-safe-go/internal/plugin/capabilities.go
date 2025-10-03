package plugin

import pluginsdk "github.com/RowanDark/Glyph/sdk/plugin-sdk"

// CapabilityMacros toggles the manifest capabilities requested by the plugin.
// Adjust the booleans to match the broker clients you actually need.
var CapabilityMacros = pluginsdk.CapabilitySet{
    EmitFindings:   true,
    HTTPPassive:    true,
    WorkspaceRead:  true,
    WorkspaceWrite: false,
    NetOutbound:    false,
    SecretsRead:    false,
}
