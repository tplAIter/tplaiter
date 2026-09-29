package mcpsrv

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// serverEntry describes one stdio MCP server in a client configuration.
type serverEntry struct {
	Type    string   `json:"type,omitempty"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// PrintConfig returns a ready JSON configuration snippet for connecting an MCP
// client to this server (the goca `--print-config` pattern). Supported clients
// are claude, cursor, and vscode. exe is the absolute path to the tplater binary.
//
// Configuration shapes differ by client:
//   - claude / cursor: {"mcpServers": {"tplaiter": {command, args}}};
//   - vscode: {"servers": {"tplaiter": {"type":"stdio", command, args}}}
//     (the .vscode/mcp.json format).
func PrintConfig(client, exe string) (string, error) {
	entry := serverEntry{Command: exe, Args: []string{"mcp-server"}}

	var root map[string]any
	switch strings.ToLower(client) {
	case "claude", "cursor":
		root = map[string]any{
			"mcpServers": map[string]any{"tplaiter": entry},
		}
	case "vscode":
		entry.Type = "stdio"
		root = map[string]any{
			"servers": map[string]any{"tplaiter": entry},
		}
	default:
		return "", fmt.Errorf("mcpsrv: unknown client %q (expected claude|cursor|vscode)", client)
	}

	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", fmt.Errorf("mcpsrv: config serialization: %w", err)
	}
	return string(data), nil
}

// SupportedPrintConfigClients returns the sorted list of supported clients for
// command help and error messages.
func SupportedPrintConfigClients() []string {
	clients := []string{"claude", "cursor", "vscode"}
	sort.Strings(clients)
	return clients
}
