// Package mcpsrv реализует MCP-сервер tplater: команды CLI выставлены наружу
// как MCP-tools для AI-агентов (заимствование 6 из docs/research/clean-codegen.md
// §1 — «MCP-сервер поверх CLI»). Архитектура — subprocess-паттерн goca: каждый
// tool исполняет тот же бинарник tplater отдельным процессом с раздельными
// аргументами (без shell-интерполяции), а НЕ вызывает cobra-команды in-process.
// In-process вызов опасен: глобальное состояние флагов cobra протекает между
// вызовами tool'ов; отдельный процесс на вызов даёт полную изоляцию.
//
// Транспорт — stdio JSON-RPC (server.ServeStdio). Логи сервера идут в stderr:
// stdout занят протоколом.
package mcpsrv

import (
	"log"
	"os"

	"github.com/mark3labs/mcp-go/server"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// Server оборачивает *server.MCPServer вместе с путём к бинарнику tplater и
// раннером подпроцессов (мокабельным в тестах через execx.RecordingRunner).
type Server struct {
	exe    string
	runner execx.Runner
	mcp    *server.MCPServer
}

// New собирает MCP-сервер tplater: регистрирует все tools и resources.
//
//	exe     — абсолютный путь к бинарнику tplater (обычно os.Executable());
//	          каждый tool исполняет именно его как подпроцесс;
//	version — версия tplater (для Implementation в initialize);
//	runner  — исполнитель подпроцессов (в проде execx.Exec{}, в тестах
//	          execx.RecordingRunner).
func New(exe, version string, runner execx.Runner) *Server {
	m := server.NewMCPServer(
		"tplaiter",
		version,
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(false, false),
		server.WithRecovery(),
	)
	s := &Server{exe: exe, runner: runner, mcp: m}
	s.registerTools()
	s.registerResources()
	return s
}

// MCP возвращает нижележащий *server.MCPServer — нужен тестам для подключения
// in-process клиента (client.NewInProcessClient).
func (s *Server) MCP() *server.MCPServer { return s.mcp }

// ServeStdio запускает сервер на stdio JSON-RPC. Ошибки протокола логируются в
// stderr (stdout занят протоколом). Блокирует до завершения (EOF на stdin или
// SIGINT/SIGTERM — обрабатывается внутри ServeStdio).
func (s *Server) ServeStdio() error {
	errLog := log.New(os.Stderr, "tplaiter-mcp ", log.LstdFlags)
	return server.ServeStdio(s.mcp, server.WithErrorLogger(errLog))
}
