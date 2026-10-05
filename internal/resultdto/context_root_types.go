package resultdto

import (
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/contextwindow"
	"github.com/tplAIter/tplaiter/internal/exports"
)

// RootContextBody is a point-in-time authenticated read, not a project mutation
// plan, ownership proof, organization authorization or model-window admission.
type RootContextBody struct {
	TrustProfile         bootstrap.ProfileBinding `json:"trustProfile"`
	APIVersion           string                   `json:"apiVersion"`
	Qualification        string                   `json:"qualification"`
	MaterializationScope string                   `json:"materializationScope"`
	Snapshot             string                   `json:"snapshot"`
	RootLockDigest       string                   `json:"rootLockDigest"`
	DependencyLockDigest string                   `json:"dependencyLockDigest"`
	BindingsDigest       string                   `json:"bindingsDigest"`
	SourceGraphDigest    string                   `json:"sourceGraphDigest"`
	CatalogDigest        string                   `json:"catalogDigest"`
	Selections           []exports.Selection      `json:"selections"`
	Graph                exports.ExportGraph      `json:"graph"`
	Packet               contextindex.Packet      `json:"packet"`
	Files                []RootContextFile        `json:"files"`
}

type RootContextFile struct {
	SelectedIdentity string `json:"selectedIdentity"`
	ExportID         string `json:"exportID"`
	SourcePath       string `json:"sourcePath"`
	TargetPath       string `json:"targetPath"`
	Mode             string `json:"mode"`
	ContentSHA256    string `json:"contentSHA256"`
	Content          []byte `json:"content"` // JSON base64 preserves exact binary images.
}

// Spending measures the local image transport. The required packet is counted
// in its input; the final complete DTO has a separate exact Bytes bound.
type RootByteDelivery struct {
	ResponseSHA256    string                 `json:"responseSHA256"`
	State             string                 `json:"state"`
	EnvelopeSHA256    string                 `json:"envelopeSHA256"`
	BodySHA256        string                 `json:"bodySHA256"`
	EnvelopeBytes     int                    `json:"envelopeBytes"`
	OutputByteReserve int64                  `json:"outputByteReserve"`
	Profile           contextwindow.Profile  `json:"profile"`
	Spending          contextwindow.Spending `json:"spending"`
}

type ContextRootSelectionData struct {
	Body     RootContextBody  `json:"body"`
	Delivery RootByteDelivery `json:"delivery"`
	Bytes    int              `json:"bytes"`
}
