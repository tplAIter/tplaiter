package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// These are installation-time linker pins. Empty values deliberately leave
// stock trust-dependent commands unavailable; flags and environment never
// participate in selecting them.
var installedRegistrationPath string
var installedRegistrationSHA256 string

type installedRegistration struct {
	APIVersion     string              `json:"apiVersion"`
	Profile        bootstrap.ProfileID `json:"profile"`
	RuntimeConfig  trustload.FilePin   `json:"runtimeConfig"`
	OperatorRecord trustload.FilePin   `json:"operatorRecord"`
	InstallationID string              `json:"installationID"`
	ProjectKey     string              `json:"projectKey"`
}

func installedInvocation(ctx context.Context) (invocation, error) {
	if installedRegistrationPath == "" || installedRegistrationSHA256 == "" {
		return invocation{}, trustload.ErrAnchorMissing
	}
	raw, err := readFixedTrustDocument(ctx, installedRegistrationPath)
	if err != nil {
		return invocation{}, trustload.ErrAnchorMissing
	}
	if !rawDigestMatches(raw, installedRegistrationSHA256) {
		return invocation{}, trustload.ErrPinMismatch
	}
	var r installedRegistration
	if err := canonicaljson.DecodeStrict(raw, &r); err != nil || r.APIVersion != "tplaiter.dev/installed-launch-registration/v1" || r.Profile == bootstrap.ProfileDevelopment {
		return invocation{}, trustload.ErrConfigInvalid
	}
	in := invocation{Selection: trustload.LaunchSelection{Profile: r.Profile, RuntimeConfig: r.RuntimeConfig, OperatorRecord: r.OperatorRecord, InstallationID: r.InstallationID}, ProjectKey: r.ProjectKey, Clock: bootstrap.ClockFunc(time.Now)}
	if err := in.Selection.Validate(); err != nil || in.ProjectKey == "" {
		return invocation{}, trustload.ErrConfigInvalid
	}
	return in, nil
}

func rawDigestMatches(raw []byte, want string) bool {
	if !strings.HasPrefix(want, "sha256:") || len(want) != len("sha256:")+64 {
		return false
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(want, "sha256:")); err != nil {
		return false
	}
	h := sha256.Sum256(raw)
	return want == "sha256:"+hex.EncodeToString(h[:])
}
