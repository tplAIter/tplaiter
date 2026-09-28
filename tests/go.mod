// Module tests is the tplater CLI e2e harness.
//
// Keeping it separate from the root go.mod is deliberate: e2e tests run the
// binary as a black box through os/exec, so they need no tplater internal
// dependencies or the root module's build/lint graph. The root go.work links
// this module for local development, while CI runs each module separately with
// GOWORK=off.
module github.com/tplAIter/tplaiter/tests

go 1.26
