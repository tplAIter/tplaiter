package mcpsrv

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPrintConfig(t *testing.T) {
	const exe = "/usr/local/bin/tplater"

	for _, client := range []string{"claude", "cursor", "vscode"} {
		t.Run(client, func(t *testing.T) {
			snippet, err := PrintConfig(client, exe)
			if err != nil {
				t.Fatalf("PrintConfig(%q): %v", client, err)
			}
			if !json.Valid([]byte(snippet)) {
				t.Fatalf("PrintConfig(%q): invalid JSON:\n%s", client, snippet)
			}

			var root map[string]json.RawMessage
			if err := json.Unmarshal([]byte(snippet), &root); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			key := "mcpServers"
			if client == "vscode" {
				key = "servers"
			}
			raw, ok := root[key]
			if !ok {
				t.Fatalf("key %q missing in config %q:\n%s", key, client, snippet)
			}

			var servers map[string]serverEntry
			if err := json.Unmarshal(raw, &servers); err != nil {
				t.Fatalf("unmarshal servers: %v", err)
			}
			entry, ok := servers["tplaiter"]
			if !ok {
				t.Fatalf("tplater server missing in config %q", client)
			}
			if entry.Command != exe {
				t.Errorf("command = %q, want %q", entry.Command, exe)
			}
			if len(entry.Args) != 1 || entry.Args[0] != "mcp-server" {
				t.Errorf("args = %v, want [mcp-server]", entry.Args)
			}
			if client == "vscode" && entry.Type != "stdio" {
				t.Errorf("vscode type = %q, want stdio", entry.Type)
			}
		})
	}
}

func TestPrintConfigUnknownClient(t *testing.T) {
	_, err := PrintConfig("emacs", "/bin/tplater")
	if err == nil {
		t.Fatal("expected an error for an unknown client")
	}
	if !strings.Contains(err.Error(), "emacs") {
		t.Errorf("error does not mention the client: %v", err)
	}
}
