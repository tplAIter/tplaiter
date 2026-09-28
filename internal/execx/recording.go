package execx

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// Call — one recorded invocation of [RecordingRunner.Run].
type Call struct {
	Name string
	Args []string
	Opts Options
}

// Response — scripted response to a Run call.
type Response struct {
	Result Result
	Err    error
}

// RecordingRunner — [Runner] test double: responds according to a predefined
// script and records all calls for later test assertions.
//
// Run responses are looked up in this order:
//  1. exact match "name arg1 arg2 ..." (see [RecordingRunner.On]);
//  2. name-only match (see [RecordingRunner.OnCommand]);
//  3. Default, if set;
//  4. otherwise, error "no scripted response".
//
// Each key stores a FIFO response queue: repeated calls with the same key
// consume it in order, and the last response is reused after the queue is exhausted.
type RecordingRunner struct {
	mu sync.Mutex

	Calls []Call

	byExact map[string][]Response
	byName  map[string][]Response

	// Default — response when no script matches a call. If HasDefault was not set
	// through SetDefault, a missing script is a test error.
	Default    Response
	hasDefault bool

	lookups map[string]string
}

// NewRecordingRunner creates an empty RecordingRunner.
func NewRecordingRunner() *RecordingRunner {
	return &RecordingRunner{
		byExact: make(map[string][]Response),
		byName:  make(map[string][]Response),
		lookups: make(map[string]string),
	}
}

// On scripts a response for a call with an exact name and args match.
func (r *RecordingRunner) On(name string, args []string, resp Response) *RecordingRunner {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := commandKey(name, args)
	r.byExact[key] = append(r.byExact[key], resp)
	return r
}

// OnCommand scripts a response for name with any arguments (used when no exact
// match from [RecordingRunner.On] is found).
func (r *RecordingRunner) OnCommand(name string, resp Response) *RecordingRunner {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byName[name] = append(r.byName[name], resp)
	return r
}

// SetDefault sets a fallback response for calls without a script.
func (r *RecordingRunner) SetDefault(resp Response) *RecordingRunner {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Default = resp
	r.hasDefault = true
	return r
}

// SetLookPath scripts the result LookPath(name) = path, ok=true.
func (r *RecordingRunner) SetLookPath(name, path string) *RecordingRunner {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups[name] = path
	return r
}

// Run implements [Runner]. It records the call and returns the scripted response.
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

// LookPath implements [Runner]. It returns the scripted path or exec.ErrNotFound
// if SetLookPath was not called for name.
func (r *RecordingRunner) LookPath(name string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if path, ok := r.lookups[name]; ok {
		return path, nil
	}
	return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
}

// popResponse takes the first response from the queue for key. The last
// remaining element is reused (the queue never shrinks below one element), so
// long test scenarios need not know the exact call count in advance.
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

// commandKey builds a script key from a command name and arguments.
func commandKey(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}
