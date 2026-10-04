package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

const trustCommandDocumentLimit = 1 << 20

// newTrustCmd exposes the only updater entrypoints. They compose a fixed
// launcher selection per invocation and never borrow new/update's runtime.
func newTrustCmd() *cobra.Command {
	root := &cobra.Command{Use: "trust", Annotations: prerunAnnotations(prerunTrustOwned), Short: "Inspect and maintain the trust profile"}
	root.AddCommand(newTrustInspectCmd(), newTrustProvisionCmd(), newTrustRefreshCmd(), newTrustRecoverCmd(), newTrustContextsCmd())
	return root
}

// trustInspection is the `trust inspect --json` document: the stable
// trust-profile binding fields at the top level (unchanged for existing
// consumers) plus the installation the binding was loaded from.
type trustInspection struct {
	bootstrap.ProfileBinding
	Installation trustInstallation `json:"installation"`
}

type trustInstallation struct {
	InstallationID string `json:"installationID"`
	// RegistrationSHA256 is the linker-pinned registration digest; it is
	// empty for an in-process invocation that was not launched from an
	// installed registration.
	RegistrationSHA256  string `json:"registrationSHA256,omitempty"`
	RuntimeConfigSHA256 string `json:"runtimeConfigSHA256"`
	Store               string `json:"store"`
}

func newTrustInspectCmd() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use: "inspect", Args: cobra.NoArgs,
		Short: "Verify the installed trust profile and print its binding",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireProvisioned(cmd.Context()); err != nil {
				return err
			}
			runtime, err := composeRuntime(cmd.Context())
			if err != nil {
				return err
			}
			defer runtime.Close()
			binding := runtime.TrustRuntime().Binding()
			if asJSON {
				in, err := commandInvocation(cmd.Context())
				if err != nil {
					return err
				}
				report := trustInspection{ProfileBinding: binding, Installation: trustInstallation{
					InstallationID:      in.Selection.InstallationID,
					RuntimeConfigSHA256: in.Selection.RuntimeConfig.SHA256,
					Store:               "provisioned",
				}}
				if _, injected := cmd.Context().Value(invocationKey{}).(invocation); !injected {
					report.Installation.RegistrationSHA256 = installedRegistrationSHA256
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				return enc.Encode(report)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "trust authority verified")
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "print the stable trust-profile binding and installation")
	return c
}

func newTrustProvisionCmd() *cobra.Command {
	return &cobra.Command{
		Use: "provision", Args: cobra.NoArgs,
		Short: "Enroll the trust store from the installation's pinned initial state (idempotent)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			in, err := commandInvocation(cmd.Context())
			if err != nil {
				return err
			}
			if storeProvisioned(cmd.Context(), in) == nil {
				// An existing store is only accepted when it opens as the
				// verified runtime of this installation; anything else keeps
				// the typed failure (use `trust recover-state`).
				if runtime, openErr := composeRuntime(cmd.Context()); openErr == nil {
					_ = runtime.Close()
					_, _ = fmt.Fprintln(cmd.OutOrStdout(), "trust store already provisioned")
					return nil
				}
			}
			loaded, err := trustload.Load(cmd.Context(), in.Selection)
			if err != nil || loaded.Install.OSS == nil {
				return maintenanceError(err)
			}
			state, err := readFixedTrustDocument(cmd.Context(), loaded.Install.OSS.InitialStatePath)
			if err != nil {
				return trustload.ErrProvenanceUnavailable
			}
			bundle, err := readFixedTrustDocument(cmd.Context(), loaded.Install.OSS.InitialBundlePath)
			if err != nil {
				return trustload.ErrProvenanceUnavailable
			}
			evidence, err := fixedBundleEvidence(cmd.Context(), loaded.Install.EvidenceRoot, bundle)
			if err != nil {
				return err
			}
			factory, err := stableVerifierFactory(cmd.Context())
			if err != nil {
				return err
			}
			if err := trustload.Enroll(cmd.Context(), in.Selection, factory, state, bundle, evidence); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "trust store provisioned")
			return nil
		},
	}
}

func newTrustRefreshCmd() *cobra.Command {
	var bundleInput string
	cmd := &cobra.Command{
		Use: "refresh", Args: cobra.NoArgs,
		Short: "Apply a newer sealed bootstrap bundle to the trust store",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if bundleInput == "" {
				return trustload.ErrProvenanceUnavailable
			}
			in, err := commandInvocation(cmd.Context())
			if err != nil {
				return err
			}
			loaded, err := trustload.Load(cmd.Context(), in.Selection)
			if err != nil {
				return maintenanceError(err)
			}
			bundle, err := readUntrustedDocument(cmd.Context(), bundleInput)
			if err != nil {
				return trustload.ErrProvenanceUnavailable
			}
			evidence, err := fixedBundleEvidence(cmd.Context(), loaded.Install.EvidenceRoot, bundle)
			if err != nil {
				return err
			}
			factory, err := stableVerifierFactory(cmd.Context())
			if err != nil {
				return err
			}
			_, err = trustload.Refresh(cmd.Context(), in.Selection, factory, bundle, evidence)
			return err
		},
	}
	cmd.Flags().StringVar(&bundleInput, "bundle-input", "", "candidate sealed JSON bootstrap bundle")
	return cmd
}

func newTrustRecoverCmd() *cobra.Command {
	return &cobra.Command{
		Use: "recover-state", Args: cobra.NoArgs,
		Short: "Recover the trust store after an interrupted update",
		RunE: func(cmd *cobra.Command, _ []string) error {
			in, err := commandInvocation(cmd.Context())
			if err != nil {
				return err
			}
			factory, err := stableVerifierFactory(cmd.Context())
			if err != nil {
				return err
			}
			return trustload.RecoverState(cmd.Context(), in.Selection, factory)
		},
	}
}

func fixedBundleEvidence(ctx context.Context, root string, bundleRaw []byte) (map[string][]byte, error) {
	bundle, err := trustload.DecodeStoredBundle(bundleRaw)
	if err != nil {
		return nil, trustload.ErrProvenanceUnavailable
	}
	reader, err := evidencecas.NewFSReader(root)
	if err != nil {
		return nil, trustload.ErrProvenanceUnavailable
	}
	defer reader.Close()
	refs := []string{bundle.EnvelopeCAS, bundle.ReceiptCAS, bundle.Transparency.CheckpointCAS, bundle.Transparency.InclusionProofCAS}
	if bundle.Transparency.ConsistencyProofCAS != "" {
		refs = append(refs, bundle.Transparency.ConsistencyProofCAS)
	}
	evidence := make(map[string][]byte, len(refs)+8)
	for index := 0; index < len(refs); index++ {
		ref := refs[index]
		if _, ok := evidence[ref]; ok {
			continue
		}
		raw, err := reader.Read(ctx, ref)
		if err != nil {
			return nil, trustload.ErrProvenanceUnavailable
		}
		evidence[ref] = raw
		if ref == bundle.EnvelopeCAS {
			envelope, err := bootstrap.DecodeEnvelope(raw)
			if err != nil {
				return nil, trustload.ErrProvenanceUnavailable
			}
			for _, key := range envelope.RootKeys {
				refs = append(refs, key.PublicKeyCAS)
			}
			for _, signature := range envelope.Signatures {
				refs = append(refs, signature.SignatureCAS)
			}
		}
	}
	return evidence, nil
}

func maintenanceError(err error) error {
	if err == nil || errors.Is(err, trustload.ErrAnchorMissing) {
		return trustload.ErrAnchorMissing
	}
	return err
}

// newTrustContextsCmd lists only fully authenticated installation contexts.
func newTrustContextsCmd() *cobra.Command {
	return &cobra.Command{Use: "contexts", Args: cobra.NoArgs, Short: "List authenticated installed project contexts as JSON", RunE: func(cmd *cobra.Command, _ []string) error {
		in, err := commandInvocation(cmd.Context())
		if err != nil {
			return err
		}
		loaded, err := trustload.Load(cmd.Context(), in.Selection)
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(loaded.Install.ProjectContexts)
	}}
}
