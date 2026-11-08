// Package executionpolicy defines the current containment boundary. ARTEX has
// not yet integrated an isolated task runner, so local tools must not execute in
// the credential-bearing control plane. There is deliberately no environment or
// UI switch that labels the old same-UID execution path as a sandbox.
package executionpolicy

import "errors"

var ErrIsolatedRunnerRequired = errors.New("active tools are unavailable: an isolated task runner is required; the management interface and stored results remain available")

func RequireIsolatedRunner() error { return ErrIsolatedRunnerRequired }
