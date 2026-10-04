// Package projectcheck provides read-only ownership checks over projectverify.
// Closed inventory decoding and canonical path/symlink validation reject invalid
// versions, metadata, duplicate paths, tombstone collisions and unsafe paths.
// Artifact reads stay under a held root and never follow symlink targets. Invalid
// inventories fail with typed diagnostics and cannot project an OK machine result.
// Report fields and Run/RunResult signatures remain stable. This package does not
// install a CLI or MCP surface or create caller-selected identity authority.
package projectcheck
