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

	// Vault: passphrase and key
	VaultTTYRequired        = "VAULT_TTY_REQUIRED"
	VaultPassphraseInvalid  = "VAULT_PASSPHRASE_INVALID"
	VaultPassphraseTooShort = "VAULT_PASSPHRASE_TOO_SHORT"
	VaultPassphraseTooLong  = "VAULT_PASSPHRASE_TOO_LONG"
	VaultPassphraseTooWeak  = "VAULT_PASSPHRASE_TOO_WEAK"
	VaultPassphraseMismatch = "VAULT_PASSPHRASE_MISMATCH"
	VaultKeyExists          = "VAULT_KEY_EXISTS"
	VaultKeyMissing         = "VAULT_KEY_MISSING"
	VaultKeyFileInvalid     = "VAULT_KEY_FILE_INVALID"
	VaultKeyCreateFailed    = "VAULT_KEY_CREATE_FAILED"
	VaultUnlockFailed       = "VAULT_UNLOCK_FAILED"
	VaultUnlockRateLimited  = "VAULT_UNLOCK_RATE_LIMITED"
	VaultLocked             = "VAULT_LOCKED"
)
