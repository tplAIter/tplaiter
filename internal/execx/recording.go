package execx

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// Call — одна записанная инвокация [RecordingRunner.Run].
type Call struct {
	Name string
	Args []string
	Opts Options
}

// Response — заскриптованный ответ на вызов Run.
type Response struct {
	Result Result
	Err    error
}

// RecordingRunner — тестовый дублёр [Runner]: отвечает по заранее заданному
// скрипту и запоминает все вызовы для последующих проверок в тестах.
//
// Ответы на Run ищутся в таком порядке:
//  1. точное совпадение "name arg1 arg2 ..." (см. [RecordingRunner.On]);
//  2. совпадение только по name (см. [RecordingRunner.OnCommand]);
//  3. Default, если задан;
//  4. иначе — ошибка "нет заскриптованного ответа".
//
// Каждый ключ хранит очередь ответов (FIFO): повторные вызовы с тем же
// ключом последовательно потребляют её, последний ответ переиспользуется
// после исчерпания очереди.
type RecordingRunner struct {
	mu sync.Mutex

	Calls []Call

	byExact map[string][]Response
	byName  map[string][]Response

	// Default — ответ, когда для вызова не нашлось скрипта. Если HasDefault
	// не выставлен через SetDefault, отсутствие скрипта — это ошибка теста.
	Default    Response
	hasDefault bool

	lookups map[string]string
}

// NewRecordingRunner создаёт пустой RecordingRunner.
func NewRecordingRunner() *RecordingRunner {
	return &RecordingRunner{
		byExact: make(map[string][]Response),
		byName:  make(map[string][]Response),
		lookups: make(map[string]string),
	}
}

// On заскриптовывает ответ на вызов с точным совпадением name и args.
func (r *RecordingRunner) On(name string, args []string, resp Response) *RecordingRunner {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := commandKey(name, args)
	r.byExact[key] = append(r.byExact[key], resp)
	return r
}

// OnCommand заскриптовывает ответ на вызов name с любыми аргументами
// (используется, если точное совпадение по [RecordingRunner.On] не найдено).
func (r *RecordingRunner) OnCommand(name string, resp Response) *RecordingRunner {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byName[name] = append(r.byName[name], resp)
	return r
}

// SetDefault задаёт ответ-фоллбек для вызовов без скрипта.
func (r *RecordingRunner) SetDefault(resp Response) *RecordingRunner {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Default = resp
	r.hasDefault = true
	return r
}

// SetLookPath заскриптовывает результат LookPath(name) = path, ok=true.
func (r *RecordingRunner) SetLookPath(name, path string) *RecordingRunner {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups[name] = path
	return r
}

// Run реализует [Runner]. Записывает вызов и возвращает заскриптованный ответ.
func (r *RecordingRunner) Run(_ context.Context, name string, args []string, opts Options) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.Calls = append(r.Calls, Call{Name: name, Args: append([]string(nil), args...), Opts: opts})

	resp, ok := popResponse(r.byExact, commandKey(name, args))
	if !ok {
		resp, ok = popResponse(r.byName, name)
	}
	if !ok {
		if r.hasDefault {
			resp = r.Default
		} else {
			return Result{}, fmt.Errorf("execx: recording runner: no scripted response for %q", commandKey(name, args))
		}
	}

	if opts.Stdout != nil && resp.Result.Stdout != "" {
		_, _ = opts.Stdout.Write([]byte(resp.Result.Stdout))
	}
	if opts.Stderr != nil && resp.Result.Stderr != "" {
		_, _ = opts.Stderr.Write([]byte(resp.Result.Stderr))
	}
	return resp.Result, resp.Err
}

// LookPath реализует [Runner]. Возвращает заскриптованный путь либо
// exec.ErrNotFound, если SetLookPath для name не вызывался.
func (r *RecordingRunner) LookPath(name string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if path, ok := r.lookups[name]; ok {
		return path, nil
	}
	return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
}

// popResponse достаёт первый ответ из очереди по ключу key. Последний
// оставшийся элемент переиспользуется повторно (очередь не опустошается
// ниже одного элемента), чтобы длинные тестовые сценарии не требовали
// заранее знать точное число вызовов.
func popResponse(m map[string][]Response, key string) (Response, bool) {
	queue, ok := m[key]
	if !ok || len(queue) == 0 {
		return Response{}, false
	}
	resp := queue[0]
	if len(queue) > 1 {
		m[key] = queue[1:]
	}
	return resp, true
}

// commandKey строит ключ скрипта из имени команды и аргументов.
func commandKey(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}
