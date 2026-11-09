#!/bin/sh
# Make-It-Safer installer. Downloads the release for this computer from
# GitHub, checks its SHA-256 checksum, and installs:
#   - mis into ~/.local/bin
#   - on macOS, the notification helper into ~/Applications
# It needs no sudo, changes nothing else, and an installed background
# service restarts with the new version.
#
#   curl -fsSL https://raw.githubusercontent.com/kugesh-Rajasekaran/Make-It-Safer/main/install.sh | sh
#
# Options (environment variables):
#   MIS_VERSION=v0.1.0   install that release instead of the latest
#   PREFIX=/some/dir     install mis into /some/dir/bin (default ~/.local)
set -eu

repo="kugesh-Rajasekaran/Make-It-Safer"
app="Make-It-Safer Notifier.app"

say() { printf '%s\n' "$*"; }
fail() {
	printf 'Make-It-Safer install failed: %s\n' "$*" >&2
	exit 1
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

# Everything runs from main, so a download cut short can't run half a script.
main() {
	prefix="${PREFIX:-$HOME/.local}"
	version="${MIS_VERSION:-latest}"

	case "$(uname -s)" in
	Darwin) os=darwin ;;
	Linux) os=linux ;;
	*) fail "$(uname -s) isn't supported: macOS and Linux only" ;;
	esac
	case "$(uname -m)" in
	arm64 | aarch64) arch=arm64 ;;
	x86_64 | amd64) arch=amd64 ;;
	*) fail "processor $(uname -m) isn't supported" ;;
	esac

	if [ "$version" = latest ]; then
		base="https://github.com/$repo/releases/latest/download"
	else
		base="https://github.com/$repo/releases/download/$version"
	fi
	asset="mis_${os}_${arch}.tar.gz"

	tmp="$(mktemp -d)"
	# Ctrl-C and kill must end the installer, not just clean up and carry on.
	trap 'rm -rf "$tmp"' EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM

	say "Downloading $asset ($version)…"
	curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$asset" "$base/$asset" || fail "cannot download $base/$asset"
	curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/checksums.txt" "$base/checksums.txt" || fail "cannot download $base/checksums.txt"

	want="$(awk -v f="$asset" '$2 == f || $2 == "*" f {print $1}' "$tmp/checksums.txt")"
	[ -n "$want" ] || fail "$asset is missing from checksums.txt"
	got="$(sha256 "$tmp/$asset")"
	[ "$got" = "$want" ] || fail "checksum mismatch for $asset: expected $want, got $got"
	say "✓ Checksum matches"

	tar -xzf "$tmp/$asset" -C "$tmp"
	mkdir -p "$prefix/bin"
	install -m 0755 "$tmp/mis" "$prefix/bin/mis"
	say "✓ Installed $prefix/bin/mis"

	if [ "$os" = darwin ]; then
		mkdir -p "$HOME/Applications"
		pkill -f "$HOME/Applications/$app/Contents/MacOS/Notifier" 2>/dev/null || true # the service starts the new one
		rm -rf "$HOME/Applications/$app"
		cp -R "$tmp/$app" "$HOME/Applications/"
		xattr -dr com.apple.quarantine "$HOME/Applications/$app" 2>/dev/null || true
		say "✓ Installed ~/Applications/$app (shows the notifications)"
	fi

	if "$prefix/bin/mis" service status --json 2>/dev/null | grep -q '"installed":true'; then
		if "$prefix/bin/mis" service install >/dev/null; then
			say "✓ Restarted the background service with the new version"
		else
			printf 'mis is installed, but the background service could not be restarted with it.\nTry again with: %s/bin/mis service install\n' "$prefix" >&2
			exit 1
		fi
	fi

	say ""
	"$prefix/bin/mis" version
	case ":$PATH:" in
	*":$prefix/bin:"*) ;;
	*)
		say ""
		say "$prefix/bin isn't on your PATH yet. Add this line to ~/.zshrc (or ~/.bashrc), then open a new terminal:"
		say "  export PATH=\"$prefix/bin:\$PATH\""
		;;
	esac
	say ""
	say "Next: run  mis init  for the guided setup."
}

main "$@"
