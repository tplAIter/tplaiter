package resultdto

import (
	"github.com/tplAIter/tplaiter/internal/contextindex"
)

// LocalPreviewData contains anonymous declarations and same-session byte
// observations. It cannot be used as authenticated context-index evidence.
type LocalPreviewData struct {
	Assets                  []LocalPreviewAsset     `json:"assets"`
	APIVersion              string                  `json:"apiVersion"`
	Kind                    string                  `json:"kind"`
	Qualification           string                  `json:"qualification"`
	SourceAuthentication    string                  `json:"sourceAuthentication"`
	PublisherAuthentication string                  `json:"publisherAuthentication"`
	OrganizationAdmission   string                  `json:"organizationAdmission"`
	Selection               LocalPreviewSelection   `json:"selection"`
	Observation             LocalPreviewObservation `json:"observation"`
	CatalogWire             *LocalPreviewBytes      `json:"catalogWire,omitempty"`
	Metadata                contextindex.Packet     `json:"metadata"`
	Resources               []LocalPreviewResource  `json:"resources"`
	Bytes                   int                     `json:"bytes"`
}
type LocalPreviewObservation struct {
	CatalogByteLength     int    `json:"catalogByteLength"`
	CatalogSHA256         string `json:"catalogSHA256"`
	HandshakeResultSHA256 string `json:"handshakeResultSHA256"`
	SchemaSHA256          string `json:"schemaSHA256"`
	ObservedAt            string `json:"observedAt"`
}
type LocalPreviewBytes struct {
	Encoding   string `json:"encoding"`
	Data       string `json:"data"`
	SHA256     string `json:"sha256"`
	ByteLength int    `json:"byteLength"`
}
type LocalPreviewResource struct {
	SourceID         string `json:"sourceID"`
	AssetID          string `json:"assetID"`
	ItemID           string `json:"itemID"`
	Path             string `json:"path"`
	DeclaredMode     string `json:"declaredMode"`
	ContentSHA256    string `json:"contentSHA256"`
	DescriptorDigest string `json:"descriptorDigest"`
	Encoding         string `json:"encoding"`
	Data             string `json:"data"`
	ByteLength       int    `json:"byteLength"`
	ResourceURI      string `json:"resourceURI"`
}

type LocalPreviewSelection struct {
	RegistrationID     string `json:"registrationID"`
	RegistrationSHA256 string `json:"registrationSHA256"`
	InstallationID     string `json:"installationID"`
	ProjectContext     string `json:"projectContext"`
	EndpointIdentity   string `json:"endpointIdentity"`
	CodeIdentity       string `json:"codeIdentity"`
	PeerUID            uint32 `json:"peerUID"`
	PeerPID            int    `json:"peerPID"`
}

// LocalPreviewAsset exposes captured read IDs and declared pins, not a body read.
type LocalPreviewAsset struct {
	SourceID         string `json:"sourceID"`
	AssetID          string `json:"assetID"`
	ItemID           string `json:"itemID"`
	Path             string `json:"path"`
	Revision         string `json:"revision"`
	ContentSHA256    string `json:"contentSHA256"`
	DescriptorDigest string `json:"descriptorDigest"`
	ByteLength       int    `json:"byteLength"`
	ResourceURI      string `json:"resourceURI"`
}
