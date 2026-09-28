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
	root := &cobra.Command{Use: "trust", Short: "Проверка и обслуживание профиля доверия"}
	root.AddCommand(newTrustInspectCmd(), newTrustProvisionCmd(), newTrustRefreshCmd(), newTrustRecoverCmd())
	return root
}

func newTrustInspectCmd() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use: "inspect", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runtime, err := composeRuntime(cmd.Context())
			if err != nil {
				return err
			}
			defer runtime.Close()
			binding := runtime.TrustRuntime().Binding()
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				return enc.Encode(binding)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "trust authority verified")
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "print the stable trust-profile binding")
	return c
}

func newTrustProvisionCmd() *cobra.Command {
	return &cobra.Command{
		Use: "provision", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			in, err := commandInvocation(cmd.Context())
			if err != nil {
				return err
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
			return trustload.Enroll(cmd.Context(), in.Selection, factory, state, bundle, evidence)
		},
	}
}

func newTrustRefreshCmd() *cobra.Command {
	var bundleInput string
	cmd := &cobra.Command{
		Use: "refresh", Args: cobra.NoArgs,
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
	cmd.Flags().StringVar(&bundleInput, "bundle-input", "", "кандидатный закрытый JSON bootstrap bundle")
	return cmd
}

func newTrustRecoverCmd() *cobra.Command {
	return &cobra.Command{
		Use: "recover-state", Args: cobra.NoArgs,
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
