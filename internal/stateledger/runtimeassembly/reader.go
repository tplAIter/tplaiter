package runtimeassembly

import (
	"context"
	"reflect"

	"github.com/tplAIter/tplaiter/internal/projecttransaction/inventory"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// ReadSession retains real writer coordination across authentication and public
// projection. It never creates a lock inode or exports a mutation capability.
type ReadSession struct {
	runtime  *trustload.Runtime
	options  Options
	held     *readCoordination
	observed *Observation
}

// OpenReadOnly locks existing native writer inodes in shared, nonblocking mode.
// A missing advisory inode is tolerated only when no native receipt exists;
// its continued absence is checked before success. No home is discovered.
func OpenReadOnly(ctx context.Context, r *trustload.Runtime, opts Options) (*ReadSession, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil {
		return nil, stateledger.ErrProjectIdentity
	}
	held, err := holdReaders(ctx, r.ProjectContext().RootPath, opts.Home)
	if err != nil {
		return nil, err
	}
	session := &ReadSession{runtime: r, options: opts, held: held}
	observed, err := session.observe(ctx)
	if err != nil {
		session.Close()
		return nil, err
	}
	session.observed = observed
	return session, nil
}

func (s *ReadSession) Close() {
	if s != nil && s.held != nil {
		s.held.close()
		s.held = nil
	}
}

// Observation is authenticated metadata, not a write grant.
func (s *ReadSession) Observation() *Observation { return s.observed }

// Recheck holds the same writer inodes and reauthenticates the current runtime,
// marker, receipts and CAS before a caller publishes its read-only projection.
func (s *ReadSession) Recheck(ctx context.Context) error {
	if s == nil || s.held == nil {
		return stateledger.ErrUnsafe
	}
	current, err := s.observe(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(s.observed, current) {
		return stateledger.ErrUnsafe
	}
	return nil
}

func (s *ReadSession) observe(ctx context.Context) (*Observation, error) {
	if err := s.held.check(ctx); err != nil {
		return nil, err
	}
	if s.runtime.TrustRuntime() == nil {
		return nil, stateledger.ErrProjectIdentity
	}
	if err := stateledger.CheckCurrentProjectIdentity(ctx, s.runtime.ProjectContext().RootPath, s.runtime.TrustRuntime()); err != nil {
		return nil, err
	}
	candidates, err := inventory.Discover(ctx, s.runtime.ProjectContext().RootPath, s.options.Home)
	if err != nil {
		return nil, err
	}
	if len(candidates) > 0 && (s.options.Home == "" || !s.held.complete()) {
		return nil, &JournalError{Status: inventory.StatusUnresolved}
	}
	var observed *Observation
	if s.options.Home == "" {
		// Existing absent-home verification remains read-only. Any project native
		// image namespace above fails unresolved rather than guessing its authority.
		snapshot, err := stateledger.VerifyStable(ctx, s.runtime.ProjectContext().RootPath, s.runtime.TrustRuntime(), stateledger.StableVerifyOptions{CAS: s.runtime})
		if err != nil {
			return nil, err
		}
		observed = &Observation{Snapshot: snapshot, Journals: []inventory.Record{}}
	} else {
		observed, err = verifyUnderCoordination(ctx, s.runtime, s.options)
		if err != nil {
			return nil, err
		}
	}
	if err := s.held.check(ctx); err != nil {
		return nil, err
	}
	return observed, nil
}
