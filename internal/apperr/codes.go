package apperr

// Registry of error codes. Each code starts with the area it comes from.
// Add new codes here so they stay unique and discoverable.
const (
	// CLI
	CLIUnexpected   = "CLI_UNEXPECTED_ERROR"
	CLIUsage        = "CLI_USAGE_INVALID"
	CLIInputAborted = "CLI_INPUT_ABORTED"

	// Configuration and files
	ConfigPermissionsTooOpen = "CONFIG_PERMISSIONS_TOO_OPEN"
	ConfigNotOwned           = "CONFIG_NOT_OWNED"
	ConfigUnreadable         = "CONFIG_UNREADABLE"
	ConfigInvalid            = "CONFIG_INVALID"
	ConfigWriteFailed        = "CONFIG_WRITE_FAILED"
	ConfigNotInitialized     = "CONFIG_NOT_INITIALIZED"
	ConfigLockFailed         = "CONFIG_LOCK_FAILED"
)
