package sourcepackage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // Git SHA-1 object format.
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const maxRawBytes = 64 << 20

type batchReader struct {
	child   *execx.CapturedGitBatch
	input   io.Writer
	output  *bufio.Reader
	origin  string
	objects map[string][]byte
	total   int
}

// No inherited Git/config/object/proxy/credential environment is passed. The
// original repository path is never supplied to Git. Missing objects fail.
func newBatchReader(ctx context.Context, scratch, origin string) (*batchReader, error) {
	child, err := execx.StartCapturedGitBatch(ctx, scratch)
	if err != nil {
		return nil, err
	}
	return &batchReader{child: child, input: child, output: bufio.NewReaderSize(child, 4096), origin: origin, objects: map[string][]byte{}}, nil
}
func (r *batchReader) close() { _ = r.child.Close() }

func batchHeader(r *bufio.Reader, oid string, remaining int) (string, int, error) {
	bad := errors.New("sourcepackage: invalid or oversized Git batch frame")
	var header [128]byte
	n := 0
	for ; n < len(header); n++ {
		b, err := r.ReadByte()
		if err != nil {
			return "", 0, bad
		}
		if b == '\n' {
			break
		}
		header[n] = b
	}
	if n == len(header) {
		return "", 0, bad
	}
	fields := strings.Split(string(header[:n]), " ")
	if len(fields) != 3 || fields[0] != oid {
		return "", 0, bad
	}
	size, err := strconv.ParseInt(fields[2], 10, 32)
	if err != nil || strconv.FormatInt(size, 10) != fields[2] {
		return "", 0, bad
	}
	limit := int64(1 << 20)
	switch fields[1] {
	case "commit", "tree":
	case "blob":
		limit = 16 << 20
	default:
		return "", 0, bad
	}
	// Include the reconstructed frame header in the aggregate allocation budget.
	overhead := len(fields[1]) + 1 + len(fields[2]) + 1
	if size < 0 || size > limit || remaining < overhead || size > int64(remaining-overhead) {
		return "", 0, bad
	}
	return fields[1], int(size), nil
}

func (r *batchReader) ReadObject(ctx context.Context, origin trustverify.SourceOrigin, oid trustverify.ObjectID) (trustverify.GitObject, error) {
	return r.ReadObjectWithLimit(ctx, origin, oid, 16<<20)
}

func (r *batchReader) ReadObjectWithLimit(ctx context.Context, origin trustverify.SourceOrigin, oid trustverify.ObjectID, limit int) (trustverify.GitObject, error) {
	if err := ctx.Err(); err != nil {
		return trustverify.GitObject{}, err
	}
	id := string(oid)
	if string(origin) != r.origin || len(id) != 40 || strings.ToLower(id) != id {
		return trustverify.GitObject{}, errors.New("sourcepackage: invalid object request")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return trustverify.GitObject{}, errors.New("sourcepackage: invalid object request")
	}
	if raw, ok := r.objects[id]; ok {
		z := bytes.IndexByte(raw, 0)
		if len(raw)-z-1 > limit {
			return trustverify.GitObject{}, errors.New("sourcepackage: object limit exceeded")
		}
		return trustverify.GitObject{Kind: string(raw[:bytes.IndexByte(raw[:z], ' ')]), Data: raw[z+1:]}, nil
	}
	if len(r.objects) >= 8192 {
		return trustverify.GitObject{}, errors.New("sourcepackage: object count limit")
	}
	if _, err := io.WriteString(r.input, id+"\n"); err != nil {
		return trustverify.GitObject{}, errors.New("sourcepackage: Git request failed")
	}
	kind, size, err := batchHeader(r.output, id, maxRawBytes-r.total)
	if err != nil {
		return trustverify.GitObject{}, err
	}
	if size > limit {
		return trustverify.GitObject{}, errors.New("sourcepackage: object limit exceeded")
	}
	prefix := kind + " " + strconv.Itoa(size) + "\x00"
	raw := make([]byte, len(prefix)+size)
	copy(raw, prefix)
	if _, err := io.ReadFull(r.output, raw[len(prefix):]); err != nil {
		return trustverify.GitObject{}, errors.New("sourcepackage: truncated object")
	}
	delimiter, err := r.output.ReadByte()
	if err != nil || delimiter != '\n' {
		return trustverify.GitObject{}, errors.New("sourcepackage: invalid object delimiter")
	}
	hash := sha1.Sum(raw) //nolint:gosec // Rehash exact Git frame.
	if hex.EncodeToString(hash[:]) != id {
		return trustverify.GitObject{}, errors.New("sourcepackage: object identity mismatch")
	}
	if err := ctx.Err(); err != nil {
		return trustverify.GitObject{}, err
	}
	r.total += len(raw)
	r.objects[id] = raw
	return trustverify.GitObject{Kind: kind, Data: raw[len(prefix):]}, nil
}
