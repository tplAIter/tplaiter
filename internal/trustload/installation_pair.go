package trustload

// SharesInstallation compares the immutable, authenticated launcher pins of
// two live runtimes. Effective profile bindings remain project-specific and
// must not be equated or weakened to admit a secondary project context.
func (r *Runtime) SharesInstallation(other *Runtime) bool {
	if r == nil || other == nil {
		return false
	}
	r.mu.Lock()
	selection, live := r.installation, !r.closed && r.runtime != nil
	r.mu.Unlock()
	other.mu.Lock()
	peer, peerLive := other.installation, !other.closed && other.runtime != nil
	other.mu.Unlock()
	return live && peerLive && selection == peer
}
