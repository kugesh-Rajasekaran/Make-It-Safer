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

	// Servers and SSH
	ServerExists          = "SERVER_EXISTS"
	ServerNotFound        = "SERVER_NOT_FOUND"
	ServerUnreachable     = "SERVER_UNREACHABLE"
	ServerHostKeyMismatch = "SERVER_HOSTKEY_MISMATCH"
	ServerHostKeyUnknown  = "SERVER_HOSTKEY_UNKNOWN"
	ServerHostKeyRejected = "SERVER_HOSTKEY_REJECTED"
	ServerAuthFailed      = "SERVER_AUTH_FAILED"
	ServerCommandFailed   = "SERVER_COMMAND_FAILED"
	ServerUnsupportedOS   = "SERVER_UNSUPPORTED_OS"

	// Server setup
	SetupSSHMissing   = "SETUP_SSH_MISSING"
	SetupFailed       = "SETUP_FAILED"
	SetupVerifyFailed = "SETUP_VERIFY_FAILED"
	SetupInvalidKey   = "SETUP_INVALID_KEY"

	// Inventories (collector output)
	InventoryInvalid  = "INVENTORY_INVALID"
	InventoryTooLarge = "INVENTORY_TOO_LARGE"
	InventoryNotFound = "INVENTORY_NOT_FOUND"

	// Vulnerability data sources
	FeedsHostNotAllowed = "FEEDS_HOST_NOT_ALLOWED"
	FeedsUnavailable    = "FEEDS_UNAVAILABLE"
	FeedsRequestFailed  = "FEEDS_REQUEST_FAILED"
	FeedsInvalidData    = "FEEDS_INVALID_DATA"
	OSVQueryFailed      = "OSV_QUERY_FAILED"
	CVEInvalidID        = "CVE_INVALID_ID"
	CVEListFailed       = "CVE_LIST_READ_FAILED"

	// Background service
	DaemonNotRunning     = "DAEMON_NOT_RUNNING"
	DaemonAlreadyRunning = "DAEMON_ALREADY_RUNNING"
	DaemonPeerRejected   = "DAEMON_PEER_REJECTED"
	DaemonBadRequest     = "DAEMON_BAD_REQUEST"
	DaemonFailed         = "DAEMON_FAILED"
	ServiceInstallFailed = "SERVICE_INSTALL_FAILED"
	ServiceUnsupported   = "SERVICE_UNSUPPORTED"

	// Fix flow, terminals and notifications
	FixInvalidPackage = "FIX_INVALID_PACKAGE"
	FixNothingToDo    = "FIX_NOTHING_TO_DO"
	TerminalNotFound  = "TERMINAL_NOT_FOUND"
	TerminalFailed    = "TERMINAL_FAILED"
	NotifyUnavailable = "NOTIFY_UNAVAILABLE"

	// Findings
	FindingsNotFound          = "FINDINGS_NOT_FOUND"
	FindingsInvalidTransition = "FINDINGS_INVALID_TRANSITION"
	FindingsStateDamaged      = "FINDINGS_STATE_DAMAGED"
)
