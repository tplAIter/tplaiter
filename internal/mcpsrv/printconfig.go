package mcpsrv

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// serverEntry — описание одного stdio MCP-сервера в конфиге клиента.
type serverEntry struct {
	Type    string   `json:"type,omitempty"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// PrintConfig возвращает готовый JSON-сниппет конфигурации MCP-клиента для
// подключения этого сервера (goca-паттерн `--print-config`). Поддерживаемые
// клиенты: claude, cursor, vscode. exe — абсолютный путь к бинарнику tplater.
//
// Формы конфигов различаются по клиентам:
//   - claude / cursor: {"mcpServers": {"tplaiter": {command, args}}};
//   - vscode: {"servers": {"tplaiter": {"type":"stdio", command, args}}}
//     (формат .vscode/mcp.json).
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
		return "", fmt.Errorf("mcpsrv: неизвестный клиент %q (ожидается claude|cursor|vscode)", client)
	}

	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", fmt.Errorf("mcpsrv: сериализация конфига: %w", err)
	}
	return string(data), nil
}

// SupportedPrintConfigClients возвращает отсортированный список поддерживаемых
// клиентов — для сообщений об ошибке/справки команды.
func SupportedPrintConfigClients() []string {
	clients := []string{"claude", "cursor", "vscode"}
	sort.Strings(clients)
	return clients
}
