#!/bin/sh
# One-liner installer for dotler prebuilt release binaries.
# Usage:
#   curl -fsSL https://msisdev.github.io/dotler/install.sh | sh
#
# Environment variables:
#   DOTLER_INSTALL_DIR  Target directory for the binary (default: ~/.local/bin)
#   DOTLER_VERSION      Release tag to install, e.g. v0.1.0 (default: latest)
#   DOTLER_LIBC         Linux C library target: musl (default) or gnu
#   DOTLER_REPO         GitHub repository owner/name (default: msisdev/dotler)

set -eu

REPO="${DOTLER_REPO:-msisdev/dotler}"
VERSION="${DOTLER_VERSION:-latest}"
INSTALL_DIR="${DOTLER_INSTALL_DIR:-$HOME/.local/bin}"
LIBC="${DOTLER_LIBC:-musl}"

err() {
    printf "Error: %s\n" "$1" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "Required command '$1' was not found in PATH."
    fi
}

download() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        err "Neither 'curl' nor 'wget' was found. Please install curl or wget."
    fi
}

verify_sha256() {
    archive_path="$1"
    sha_file="$2"
    expected="$(awk '{print $1}' "$sha_file")"
    if [ -z "$expected" ]; then
        err "Failed to read expected SHA-256 checksum."
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$archive_path" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$archive_path" | awk '{print $1}')"
    elif command -v openssl >/dev/null 2>&1; then
        actual="$(openssl dgst -sha256 "$archive_path" | awk '{print $NF}')"
    else
        printf "Warning: No SHA-256 tool found; skipping checksum verification.\n" >&2
        return 0
    fi

    if [ "$actual" != "$expected" ]; then
        err "SHA-256 checksum mismatch (expected $expected, got $actual)."
    fi
}

detect_target() {
    os_name="$(uname -s)"
    arch_name="$(uname -m)"

    case "$arch_name" in
        x86_64|amd64)
            arch="x86_64"
            ;;
        aarch64|arm64)
            arch="aarch64"
            ;;
        *)
            err "Unsupported CPU architecture: $arch_name"
            ;;
    esac

    case "$os_name" in
        Linux)
            case "$LIBC" in
                musl)
                    target="${arch}-unknown-linux-musl"
                    ;;
                gnu)
                    target="${arch}-unknown-linux-gnu"
                    ;;
                *)
                    err "Unsupported DOTLER_LIBC value '$LIBC' (expected 'musl' or 'gnu')."
                    ;;
            esac
            ;;
        Darwin)
            target="${arch}-apple-darwin"
            ;;
        *)
            err "Unsupported operating system: $os_name (use install.ps1 on Windows or 'cargo install dotler')."
            ;;
    esac

    printf "%s" "$target"
}

main() {
    need_cmd uname
    need_cmd tar
    need_cmd mktemp
    need_cmd awk

    target="$(detect_target)"
    archive="dotler-${target}.tar.gz"
    checksum_file="${archive}.sha256"

    if [ -n "${DOTLER_RELEASE_BASE_URL:-}" ]; then
        base_url="${DOTLER_RELEASE_BASE_URL%/}"
    elif [ "$VERSION" = "latest" ]; then
        base_url="https://github.com/${REPO}/releases/latest/download"
    else
        case "$VERSION" in
            v*) tag="$VERSION" ;;
            *)  tag="v$VERSION" ;;
        esac
        base_url="https://github.com/${REPO}/releases/download/${tag}"
    fi

    tmp_dir="$(mktemp -d 2>/dev/null || mktemp -d -t dotler-install)"
    trap 'rm -rf "$tmp_dir"' EXIT INT TERM

    printf "Downloading dotler (%s) from %s...\n" "$target" "$REPO"
    download "${base_url}/${archive}" "${tmp_dir}/${archive}"
    download "${base_url}/${checksum_file}" "${tmp_dir}/${checksum_file}"

    verify_sha256 "${tmp_dir}/${archive}" "${tmp_dir}/${checksum_file}"

    tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir"
    if [ ! -f "${tmp_dir}/dotler" ]; then
        err "Extracted archive did not contain the 'dotler' binary."
    fi

    mkdir -p "$INSTALL_DIR"
    chmod +x "${tmp_dir}/dotler"
    mv -f "${tmp_dir}/dotler" "${INSTALL_DIR}/dotler"

    printf "Installed dotler to %s/dotler\n" "$INSTALL_DIR"
    if "${INSTALL_DIR}/dotler" --version >/dev/null 2>&1; then
        "${INSTALL_DIR}/dotler" --version
    fi

    case ":${PATH:-}:" in
        *":${INSTALL_DIR}:"*)
            ;;
        *)
            printf "\nHint: '%s' is not in your PATH. Add it to your shell profile:\n" "$INSTALL_DIR"
            printf "  export PATH=\"%s:\$PATH\"\n" "$INSTALL_DIR"
            ;;
    esac
}

main "$@"
