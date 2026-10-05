package cmd

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextcmd"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

const rootDeliveryVersion = "tplaiter.dev/root-delivery/v1"

// These control messages correlate delivery of bytes, never source authority.
// The installed runtime and the retained RootSelection authenticate the source.
type rootDeliveryMessage struct {
	APIVersion string `json:"apiVersion"`
	Token      string `json:"token"`
	Sequence   int    `json:"sequence"`
	Action     string `json:"action"`
	Digest     string `json:"digest"`
}

func newContextRootSelectCmd() *cobra.Command {
	var key, dir, raw, token string
	c := &cobra.Command{Use: "select", Short: "Select complete authenticated ROOT task context", Args: cobra.NoArgs, Annotations: prerunAnnotations(prerunReadonly)}
	c.Flags().StringVar(&key, "project-context", "", "exact installed project-context key")
	c.Flags().StringVar(&dir, "dir", "", "locator matching the installed root")
	c.Flags().StringVar(&raw, "request", "", "closed ROOT selectors, bindings path, expected snapshot and byte bounds")
	c.Flags().StringVar(&token, "root-delivery-token", "", "private pipe delivery correlation; does not grant authority")
	_ = c.Flags().MarkHidden("root-delivery-token")
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		cmd.SetContext(ctx)
		req, err := decodeRootRequest(raw)
		if err != nil {
			return resultdto.NewError(contextcmd.Invalid, resultdto.ExitUsage, err)
		}
		if token != "" && !validRootDeliveryToken(token) {
			return resultdto.NewError(contextcmd.Invalid, resultdto.ExitUsage, nil)
		}
		var control, replies *os.File
		if token != "" {
			control = os.NewFile(3, "root-delivery-control")
			replies = os.NewFile(4, "root-delivery-replies")
			if control == nil || replies == nil {
				return resultdto.NewError(contextcmd.Invalid, resultdto.ExitUsage, nil)
			}
			defer control.Close()
			defer replies.Close()
			for _, pipe := range []*os.File{control, replies} {
				info, e := pipe.Stat()
				if e != nil || info.Mode()&os.ModeNamedPipe == 0 {
					return resultdto.NewError(contextcmd.Invalid, resultdto.ExitUsage, nil)
				}
			}
		}
		runtime, err := nativeGenRuntime(cmd, nativeGenControls{key: key, dir: dir})
		if err != nil {
			return err
		}
		defer runtime.Close()
		selected, err := contextcmd.BeginRootSelection(cmd.Context(), runtime, req)
		if err != nil {
			return rootSelectionError(err)
		}
		defer selected.Close()
		env := newResult(resultdto.OperationContextQuery)
		env.Project = trustProject(runtime.ProjectContext())
		data, err := rootFrontendData(selected.Result(), req.MaxBytes)
		if err != nil {
			return err
		}
		if err = env.SetData(data); err != nil {
			return err
		}
		frame, err := rootResultFrame(env, req.MaxBytes)
		if err != nil {
			return err
		}
		if token == "" {
			if err = selected.Recheck(cmd.Context()); err != nil {
				return rootSelectionError(err)
			}
			// Mark the output attempt before writing: a broken pipe must never append a
			// second result/v1 frame after an incomplete first frame.
			emittedResult = true
			return writeRootFrameContext(cmd.Context(), cmd.OutOrStdout(), frame)
		}
		if err = selected.Recheck(cmd.Context()); err != nil {
			return rootSelectionError(err)
		}
		emittedResult = true
		if err = writeRootFrame(cmd.OutOrStdout(), frame); err != nil {
			return err
		}
		return serveRootDelivery(cmd.Context(), selected, control, replies, token, evidencecas.Digest(frame))
	}
	return withResult(c, resultdto.OperationContextQuery)
}

func decodeRootRequest(raw string) (contextcmd.RootSelectionRequest, error) {
	var req contextcmd.RootSelectionRequest
	if len(raw) == 0 || len(raw) > 16384 || canonicaljson.DecodeStrict([]byte(raw), &req) != nil {
		return req, errors.New(contextcmd.Invalid)
	}
	if req.MaxBytes == 0 {
		req.MaxBytes = 32768
	}
	if req.MaxRecords == 0 {
		req.MaxRecords = 256
	}
	if req.MaxBytes < 1 || req.MaxBytes > 32768 || req.MaxRecords < 1 || req.MaxRecords > 256 || len(req.Selections) < 1 || len(req.Selections) > 16 {
		return req, errors.New(contextcmd.Invalid)
	}
	return req, nil
}

func validRootDeliveryToken(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func rootResultFrame(env resultdto.Result, ceiling int) ([]byte, error) {
	if err := env.ValidateExit(resultdto.ExitSuccess); err != nil {
		return nil, err
	}
	raw, err := resultdto.MarshalCanonical(env)
	if err != nil {
		return nil, err
	}
	if len(raw)+1 > ceiling {
		return nil, resultdto.NewError(contextcmd.Budget, resultdto.ExitUnavailable, nil)
	}
	return append(raw, '\n'), nil
}

func writeRootFrame(w io.Writer, frame []byte) error {
	n, err := w.Write(frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
}

// Ordinary ROOT stdout uses a pollable duplicate so cancellation can interrupt
// a blocked complete-frame write while the real selection remains retained.
func writeRootFrameContext(ctx context.Context, w io.Writer, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, ok := w.(*os.File)
	if !ok {
		return writeRootFrame(w, frame)
	}
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		return err
	}
	syscall.CloseOnExec(fd)
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		syscall.Close(fd)
		return err
	}
	if err = syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return err
	}
	output := os.NewFile(uintptr(fd), "root-stdout")
	defer func() { _ = syscall.SetNonblock(fd, flags&syscall.O_NONBLOCK != 0); _ = output.Close() }()
	deadline, _ := ctx.Deadline()
	if err = output.SetWriteDeadline(deadline); err != nil {
		// Regular files cannot block on pipe capacity and do not support deadlines.
		info, statErr := output.Stat()
		if statErr == nil && info.Mode().IsRegular() {
			return writeRootFrame(output, frame)
		}
		return err
	}
	finished := make(chan struct{})
	cancel := context.AfterFunc(ctx, func() { defer close(finished); _ = output.SetWriteDeadline(time.Now()) })
	defer func() {
		if !cancel() {
			<-finished
		}
		_ = output.SetWriteDeadline(time.Time{})
	}()
	return writeRootFrame(output, frame)
}

func rootSelectionError(err error) error {
	exit := resultdto.ExitTrust
	var ce *contextcmd.Error
	if errors.As(err, &ce) && ce.Code == contextcmd.Invalid {
		exit = resultdto.ExitUsage
	}
	if contextcmd.Code(err) == contextcmd.Budget {
		exit = resultdto.ExitUnavailable
	}
	return resultdto.NewError(contextcmd.Code(err), exit, err)
}

func serveRootDelivery(ctx context.Context, selected *contextcmd.RootSelection, control io.ReadCloser, replies io.Writer, token, digest string) error {
	// Closing the real pipe unblocks a pending read when the invocation ends.
	stop := context.AfterFunc(ctx, func() { _ = control.Close() })
	defer stop()
	reader := bufio.NewReaderSize(control, 1025)
	for sequence, action := range []string{"recheck", "complete"} {
		line, err := reader.ReadSlice('\n')
		if err != nil || len(line) > 1024 {
			return errors.New(contextcmd.Stale)
		}
		var message rootDeliveryMessage
		if canonicaljson.DecodeStrict(line, &message) != nil || message.APIVersion != rootDeliveryVersion || message.Token != token || message.Digest != digest || message.Sequence != sequence+1 || message.Action != action {
			return errors.New(contextcmd.Stale)
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		replyAction := "closed"
		if action == "recheck" {
			if err = selected.Recheck(ctx); err != nil {
				return err
			}
			replyAction = "ready"
		} else {
			selected.Close()
		}
		reply, err := json.Marshal(rootDeliveryMessage{rootDeliveryVersion, token, sequence + 1, replyAction, digest})
		if err != nil {
			return err
		}
		if err = writeRootFrame(replies, append(reply, '\n')); err != nil {
			return err
		}
	}
	return nil
}

func rootFrontendData(root resultdto.ContextRootSelectionData, ceiling int) (resultdto.ContextData, error) {
	data := resultdto.ContextData{Action: "select", Snapshot: root.Body.Snapshot, CatalogOrigin: "authenticated-installed-native-root", Entries: []resultdto.ContextEntry{}, WindowState: "unknown", WindowReason: contextcmd.WindowUnknown, NativeRootSelection: &root}
	for range 32 {
		raw, err := json.Marshal(data)
		if err != nil {
			return resultdto.ContextData{}, err
		}
		if len(raw) > ceiling {
			return resultdto.ContextData{}, resultdto.NewError(contextcmd.Budget, resultdto.ExitUnavailable, nil)
		}
		if data.Bytes == len(raw) {
			return data, nil
		}
		data.Bytes = len(raw)
	}
	return resultdto.ContextData{}, resultdto.NewError(contextcmd.Budget, resultdto.ExitUnavailable, nil)
}
