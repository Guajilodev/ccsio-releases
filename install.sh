#!/usr/bin/env bash
# install.sh — the public ccsio installer (odd/tasks/distribution.md, S1/S2/S4/S9/S10).
#
# What it promises, in the order it does it:
#
#   1. reads manifest.json, manifest.json.sig and allowed_signers from a channel that
#      holds artifacts and no source;
#   2. verifies the signature over the exact manifest bytes, with the recipe proven by
#      hand in Log L4:
#        ssh-keygen -Y verify -f allowed_signers -I <principal> -n ccsio-release \
#          -s manifest.json.sig < manifest.json
#      against the trust list EMBEDDED in this script, which the publisher wrote, and
#      never against the list the channel serves: whoever controls a channel can write a
#      self-consistent allowed_signers, which is how E9 was found (S11, Log L10);
#   3. verifies the sha256 that the verified manifest declares for this platform's
#      tarball, and that the archive holds one binary and no path that escapes;
#   4. extracts under <root>/tmp, and only moves a complete version into
#      versions/<ver>/ once every check above passed;
#   5. finishes only when the name `ccsio` on the caller's PATH reaches the build this run
#      wrote, recognizing the bin directory it was given even through a symlink. What it
#      reaches instead — somebody else's file, or a launcher pinned to a build this run did
#      not install — is named, with its own exit code and the command that fixes it, and is
#      never deleted or overwritten (S12, E11).
#
# A version pointer is the only thing that ever changes in place: <root>/current points
# at versions/<ver>, and <bin-dir>/ccsio is a symlink to a launcher that reads that
# pointer. Nothing running is overwritten, so going back a version is a pointer move and
# not a download.
#
# Every refusal says why, in one line, with its own exit code, and happens before a
# single byte is written. It never escalates privileges, it installs no dependency, and it
# writes nowhere outside the install root and the bin directory it was given.
set -euo pipefail

PROGRAM=ccsio
NAMESPACE=ccsio-release
PRINCIPAL=${CCSIO_RELEASE_PRINCIPAL:-release@ccsio.ai}
# The releases repo: artifacts only, no source, readable without a token. The source repo
# stays private (S1, and L8 of odd/tasks/semver.md).
DEFAULT_CHANNEL=https://raw.githubusercontent.com/Guajilodev/ccsio-releases/main

# One exit code per refusal, so a script can tell a tampered artifact from a dead mirror.
E_USAGE=2      # bad argument, unusable channel address, nowhere to install
E_TOOL=3       # a tool this installer cannot do without is missing
E_CHANNEL=4    # the channel did not serve something it must
E_NO_SIGNERS=5 # no allowed_signers: there is no anchor to verify against
E_UNSIGNED=6   # no manifest.json.sig: an unsigned manifest is only a request to trust it
E_KEY=7        # signed by a key the trust list does not name
E_ALTERED=8    # the signature does not cover these bytes
E_NAMESPACE=9  # not the ccsio-release namespace, in the trust list or in the signature
E_SHA=10       # the download does not hash to what the manifest declares
E_PLATFORM=11  # no artifact for this os/arch
E_EXISTS=12    # a different build already holds this version directory
E_ARTIFACT=13  # unusable artifact: a name this script will not fetch, or an escaping path
E_SHIM=14      # the name on PATH is somebody else's file
E_VERSION=15   # the channel does not offer that version
E_MANIFEST=16  # not a ccsio release manifest
E_PRINCIPAL=17 # the trust list names no key for our principal
E_SHADOW=18    # a different ccsio wins the name on PATH

# The trust region below is bounded by two marker lines: this prefix plus "begin", and
# this prefix plus "end". The prefix is spelled once, here, so that each marker line
# appears exactly once in this file, which is what lets scripts/publish-channel.sh count
# them and refuse an installer whose region it cannot fill.
TRUST_MARK='@ccsio:trust-list:'

# ---------------------------------------------------------------------------
# the trust list this copy of install.sh decides with (S11)
# ---------------------------------------------------------------------------
#
# The release trust list, one allowed_signers line per accepted release key, burned in by
# scripts/publish-channel.sh from the repository's internal/release/allowed_signers when it
# copies this file into the channel. The committed file keeps the region below EMPTY on
# purpose: an installer read out of the source tree verifies no channel and says so, which
# is the same fail-closed rule the anchor compiled into the binary follows (S6). Nobody
# fills this in by hand, and it is never taken from the channel being verified: whoever can
# write into a channel can write a self-consistent allowed_signers, a manifest signed to
# match it, and a shell script wearing a version number, which is how E9 was found in the
# rehearsal (Log L10). CCSIO_ALLOWED_SIGNERS=<file> overrides whatever is here, for a test
# or for someone who keeps their own copy of the anchor.
#
# The quoted heredoc is what makes the region data instead of code: the lines between the
# two markers are never executed, only copied out into a file for ssh-keygen -Y verify.
# Changing the markers, the delimiter CCSIO_TRUST_LIST, or this assignment breaks
# scripts/publish-channel.sh, which refuses to publish an installer whose region it cannot
# fill and verify.
EMBEDDED_TRUST_LIST=$(cat <<'CCSIO_TRUST_LIST'
#@ccsio:trust-list:begin
release@ccsio.ai namespaces="ccsio-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEBVE9g2g+OzfQHjtqhRafKdejYkkif8xUweQf04366O ccsio-release-2026
#@ccsio:trust-list:end
CCSIO_TRUST_LIST
)

WORK=""
OPT_VERSION=""
OPT_LIST=0
ROOT=""
BIN_DIR=""
CHANNEL=""
DLMODE=""
REMOTE=0
SIGNERS=""
MANIFEST=""
SIG_FILE=""
VERSION=""
OS=""
ARCH=""

say() { printf 'install: %s\n' "$*" >&2; }

die() {
	local code=$1
	shift
	printf 'install: %s\n' "$*" >&2
	exit "$code"
}

# The scratch directory is the only thing this script may leave behind by accident, so it
# goes on every path out, including a signal.
cleanup() {
	if [ -n "$WORK" ] && [ -d "$WORK" ]; then
		rm -rf -- "$WORK"
	fi
}
trap cleanup EXIT

usage() {
	cat <<EOF
install.sh — install the ccsio CLI from its release channel, without npm and without a
token: the channel serves artifacts only, and this script verifies them before it writes.

Usage:
  ./install.sh [--version <x>] [--list] [--root <dir>] [--bin-dir <dir>] [--help]

What is verified before anything is written:
  signature   manifest.json carries a signature for the '$NAMESPACE' namespace made by a
              key that the trust list names for '$PRINCIPAL', checked with
              ssh-keygen -Y verify -f <trust list> -I $PRINCIPAL -n $NAMESPACE
  trust list  WHERE THE ANCHOR COMES FROM: the release keys embedded in this copy of
              install.sh, written into its marked region by scripts/publish-channel.sh from
              the release repository's internal/release/allowed_signers. The channel also
              serves an allowed_signers, and this script reads it, compares it and reports a
              difference on stderr; but it is not the channel that decides, because a channel
              that may name its own keys can sign anything with them (S11, E9). The
              committed scripts/install.sh keeps that region empty, so an installer read out
              of the source tree verifies no channel and says so; the only other list this
              script decides with is a checkout's own internal/release/allowed_signers, the
              file the ccsio binary embeds (S6). CCSIO_ALLOWED_SIGNERS=<path> outranks both.
  sha256      the tarball this platform is about to run hashes to what the verified
              manifest declares, with sha256sum (or shasum -a 256)
  archive     the tarball holds paths that stay inside its own directory, and exactly one
              '$PROGRAM' binary
  the name    once it is written, the first $PROGRAM on your PATH is the file this run
              installed; see exit 18

Where it writes, and nowhere else:
  <root>/versions/<version>/$PROGRAM   one directory per version, side by side
  <root>/current                      the number of the version in use
  <root>/bin/$PROGRAM                  the launcher that reads that number
  <bin-dir>/$PROGRAM                    a symlink to that launcher
  <root>/tmp                          scratch, removed on the way out either way

Defaults: <root> is \$HOME/.ccsio and <bin-dir> is \$HOME/.local/bin, so an install needs
no arguments and no privileges.

Options:
  --version <x>   install x rather than the version the channel offers as current
  --list          print what the channel offers, and install nothing
  --root <dir>    install root (default \$HOME/.ccsio, or CCSIO_ROOT)
  --bin-dir <dir> where the name on PATH goes (default \$HOME/.local/bin, CCSIO_BIN_DIR)
  -h, --help      this text

Environment:
  CCSIO_CHANNEL_URL   the channel to read; the default is
                      $DEFAULT_CHANNEL
  CCSIO_ROOT          the install root
  CCSIO_BIN_DIR       the directory holding the name on PATH
  CCSIO_ALLOWED_SIGNERS  a trust list to decide with instead of the one embedded in this
                      script; it outranks the embedded list and the channel's copy
  CCSIO_RELEASE_PRINCIPAL  the identity the trust list is read for (default $PRINCIPAL)

Exit codes:
  0 installed, or already installed       9  not the release namespace
  2 bad argument or channel address       10  sha256 mismatch
  3 a required tool is missing            11  no artifact for this platform
  4 the channel served nothing            12  a different build holds that version
  5 no allowed_signers to verify with     13  unusable artifact
  6 manifest not signed                   14  the name on PATH is not ours to replace
  7 signed by an untrusted key            15  that version is not offered
  8 manifest altered after signing        16  malformed manifest
                                          17  no key for our principal
                                          18  another ccsio wins the name on PATH

  5 is left without an anchor in either of two ways: this copy of install.sh carries an
  empty embedded trust list (the committed script, read from a source tree, verifies no
  channel), or its marked region has been edited and cannot be read as one.

  14 is about the file in the bin directory: a $PROGRAM already there that is not our
  launcher is refused and left alone. 18 is about the name: the install is complete on
  disk, but the first $PROGRAM your PATH reaches is not the build this run installed,
  whether somebody else's file or a launcher pinned to an older version. The message
  prints its full path, what it answers to --version, and the command that fixes it.
  install.sh will not delete or overwrite that file; it names it.

From the channel, read it first and then run it:
  curl -fsSL "\$CCSIO_CHANNEL/install.sh" -o install.sh
  ./install.sh
EOF
}

# ---------------------------------------------------------------------------
# arguments and addresses
# ---------------------------------------------------------------------------

valid_version() {
	# A version becomes a directory name here and a file name on the channel, so it has
	# to be a version and not a path.
	case $1 in
	[0-9]*) ;;
	*) return 1 ;;
	esac
	case $1 in
	*[!0-9A-Za-z._+-]*) return 1 ;;
	esac
	[ "${#1}" -le 64 ]
}

need_value() {
	# need_value <flag> <arguments left>
	[ "$2" -ge 2 ] || die "$E_USAGE" "$1 needs a value"
}

absolute() {
	# absolute <path> — no cd, so it works for a directory that does not exist yet
	case $1 in
	/*) printf '%s\n' "$1" ;;
	*) printf '%s\n' "$PWD/$1" ;;
	esac
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case $1 in
		-h | --help)
			usage
			exit 0
			;;
		--version)
			need_value "$1" "$#"
			OPT_VERSION=$2
			shift 2
			;;
		--version=*)
			OPT_VERSION=${1#*=}
			shift
			;;
		--list)
			OPT_LIST=1
			shift
			;;
		--root)
			need_value "$1" "$#"
			ROOT=$2
			shift 2
			;;
		--root=*)
			ROOT=${1#*=}
			shift
			;;
		--bin-dir)
			need_value "$1" "$#"
			BIN_DIR=$2
			shift 2
			;;
		--bin-dir=*)
			BIN_DIR=${1#*=}
			shift
			;;
		--)
			shift
			[ "$#" -eq 0 ] || die "$E_USAGE" "unknown argument: $1"
			;;
		*)
			die "$E_USAGE" "unknown argument: $1 (--help lists them)"
			;;
		esac
	done
	if [ -n "$OPT_VERSION" ] && ! valid_version "$OPT_VERSION"; then
		die "$E_USAGE" "invalid --version value: $OPT_VERSION (a version is a number like 0.2.0, not a path)"
	fi
}

resolve_dirs() {
	[ -n "$ROOT" ] || ROOT=${CCSIO_ROOT:-}
	[ -n "$BIN_DIR" ] || BIN_DIR=${CCSIO_BIN_DIR:-}
	if [ -z "$ROOT" ] || [ -z "$BIN_DIR" ]; then
		[ -n "${HOME:-}" ] ||
			die "$E_USAGE" "no home to install into: set HOME, or pass --root and --bin-dir"
		[ -n "$ROOT" ] || ROOT=$HOME/.ccsio
		[ -n "$BIN_DIR" ] || BIN_DIR=$HOME/.local/bin
	fi
	# A leading ~ is expanded here rather than by the shell: the installer runs under
	# set -u, and a case pattern is not a place where tilde expansion happens.
	if [ "$ROOT" = "~" ]; then
		ROOT=$HOME
	elif [ "${ROOT#~/}" != "$ROOT" ]; then
		ROOT=$HOME/${ROOT#~/}
	fi
	if [ "$BIN_DIR" = "~" ]; then
		BIN_DIR=$HOME
	elif [ "${BIN_DIR#~/}" != "$BIN_DIR" ]; then
		BIN_DIR=$HOME/${BIN_DIR#~/}
	fi
	ROOT=$(absolute "$ROOT")
	BIN_DIR=$(absolute "$BIN_DIR")
}

resolve_channel() {
	CHANNEL=${CCSIO_CHANNEL_URL:-$DEFAULT_CHANNEL}
	REMOTE=0
	case $CHANNEL in
	http://* | https://*)
		REMOTE=1
		;;
	file://*)
		CHANNEL=${CHANNEL#file://}
		;;
	esac
	while [ "${CHANNEL%/}" != "$CHANNEL" ]; do
		CHANNEL=${CHANNEL%/}
	done
	if [ "$REMOTE" = 0 ]; then
		[ -d "$CHANNEL" ] ||
			die "$E_USAGE" "the channel is neither an http(s) URL nor a directory: $CHANNEL (CCSIO_CHANNEL_URL)"
		CHANNEL=$(cd -- "$CHANNEL" && pwd)
	fi
}

check_tools() {
	local name
	for name in ssh-keygen tar awk sed grep mktemp cp mv ln rm mkdir chmod cat find cmp readlink tr uname basename dirname; do
		command -v "$name" >/dev/null 2>&1 ||
			die "$E_TOOL" "$name is required by install.sh and was not found in PATH"
	done
	if command -v sha256sum >/dev/null 2>&1; then
		HASH=(sha256sum)
	elif command -v shasum >/dev/null 2>&1; then
		HASH=(shasum -a 256)
	else
		die "$E_TOOL" "no sha256 tool found: install.sh needs sha256sum or shasum -a 256 to check the artifact hashes"
	fi
	if [ "$REMOTE" = 1 ]; then
		if command -v curl >/dev/null 2>&1; then
			DL=(curl -fsSL --retry 2 --retry-delay 1 --max-time 120)
			DLMODE=curl
		elif command -v wget >/dev/null 2>&1; then
			DL=(wget -q --timeout=60 --tries=2)
			DLMODE=wget
		else
			die "$E_TOOL" "reading an http(s) channel needs curl or wget in PATH"
		fi
	fi
}

fetch() {
	# fetch <name on the channel> <dest> -> 0 when the channel served it, 1 when it did not
	local name=$1 dest=$2
	if [ "$REMOTE" = 1 ]; then
		case $DLMODE in
		curl) "${DL[@]}" --output "$dest" --url "$CHANNEL/$name" || return 1 ;;
		wget) "${DL[@]}" -O "$dest" "$CHANNEL/$name" || return 1 ;;
		esac
		return 0
	fi
	[ -f "$CHANNEL/$name" ] || return 1
	cp -- "$CHANNEL/$name" "$dest" || return 1
}

hash_file() {
	local line
	line=$("${HASH[@]}" -- "$1") || return 1
	printf '%s\n' "${line%%[[:space:]]*}"
}

# ---------------------------------------------------------------------------
# the trust list, and the signature over the manifest
# ---------------------------------------------------------------------------

script_self() {
	# script_self — this file, with symlinks followed, so an installer read out of a
	# checkout finds that checkout instead of the caller's working directory.
	local p=${BASH_SOURCE[0]:-} link guard=0
	[ -n "$p" ] || return 1
	case $p in
	/*) ;;
	*) p=$PWD/${p#./} ;;
	esac
	while [ -L "$p" ] && [ "$guard" -lt 40 ]; do
		link=$(readlink -- "$p") || break
		case $link in
		/*) p=$link ;;
		*) p=$(dirname -- "$p")/$link ;;
		esac
		guard=$((guard + 1))
	done
	printf '%s\n' "$p"
}

source_tree_anchor() {
	# source_tree_anchor — the release trust list of the source tree this copy of
	# install.sh was read from, printed as an absolute path, or nothing when there is no
	# such list or it is empty. That file is the one compiled into the ccsio binary
	# (internal/release/allowed_signers, S6), so an installer run from a checkout and a
	# binary built from that checkout decide with the same key, and neither of them ever
	# decides with the list the channel serves. A machine with no release key cut yet gets
	# nothing here, which is the fail-closed answer.
	local self anchor
	self=$(script_self) || return 0
	anchor=$(dirname -- "$self")/../internal/release/allowed_signers
	[ -f "$anchor" ] || return 0
	[ -s "$anchor" ] || return 0
	printf '%s\n' "$anchor"
}

trust_region_lines() {
	# trust_region_lines <the text between the markers of this copy of install.sh> — the
	# publisher's lines, markers dropped. It returns 1 when the markers are not there once
	# each and in order, which means this file was edited rather than published, and an
	# edited region is not an anchor.
	printf '%s\n' "$1" | awk -v mark="$TRUST_MARK" '
		index($0, mark "begin") { begins++; inside = 1; next }
		index($0, mark "end") { ends++; inside = 0; next }
		inside { print }
		END { exit !(begins == 1 && ends == 1) }
	'
}

trust_keys() {
	# trust_keys <file> — the keys of a trust list on stderr-clean stdout: comments and
	# blank lines out, trailing blanks trimmed. Used to tell an empty region from a filled
	# one, and to compare two lists that differ only in layout.
	sed -e 's/[[:space:]]*$//' -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$1"
}

load_signers() {
	# The list ssh-keygen verifies against, and where it came from. S11 is the whole point
	# of this function: the answer is never the channel's. The channel still publishes
	# allowed_signers, and this reads it, compares it, and says out loud when it disagrees
	# with the list it carries.
	SIGNERS=$WORK/signers
	local pinned=${CCSIO_ALLOWED_SIGNERS:-}
	local source='' marked keys tree served
	local cmp_a=$WORK/cmp_embedded cmp_b=$WORK/cmp_channel

	if [ -n "$pinned" ]; then
		[ -f "$pinned" ] ||
			die "$E_NO_SIGNERS" "CCSIO_ALLOWED_SIGNERS points at $pinned, which is not a readable file: refusing to fall back to guessing"
		cp -- "$pinned" "$SIGNERS" ||
			die "$E_NO_SIGNERS" "CCSIO_ALLOWED_SIGNERS points at $pinned, which cannot be read"
		[ -n "$(trust_keys "$SIGNERS")" ] ||
			die "$E_NO_SIGNERS" "CCSIO_ALLOWED_SIGNERS points at $pinned, which names no key: an empty anchor is the fail-closed answer, not a permissive one"
		source="$pinned, pinned by CCSIO_ALLOWED_SIGNERS, which outranks the list embedded in this installer and the channel's"
	else
		if ! marked=$(trust_region_lines "$EMBEDDED_TRUST_LIST"); then
			die "$E_NO_SIGNERS" "the marked trust region of this copy of install.sh is malformed or repeated, so the file was edited rather than published: refusing to read an anchor out of it, and refusing to guess one"
		fi
		printf '%s\n' "$marked" >"$SIGNERS"
		keys=$(trust_keys "$SIGNERS")
		if [ -n "$keys" ]; then
			source="the release keys embedded in this install.sh by scripts/publish-channel.sh, not the channel's"
		else
			# The committed installer: an empty region on purpose. The checkout's own anchor is
			# the only other answer, and a tree without one verifies nothing.
			tree=$(source_tree_anchor)
			if [ -z "$tree" ]; then
				die "$E_NO_SIGNERS" "this copy of install.sh carries no embedded trust list, so it verifies no channel and installs nothing: the committed scripts/install.sh keeps that region empty on purpose, and the anchor is not taken from the channel being checked. Run the install.sh the channel serves, or set CCSIO_ALLOWED_SIGNERS=<file> to your own copy of the release trust list"
			fi
			cp -- "$tree" "$SIGNERS" ||
				die "$E_NO_SIGNERS" "$tree cannot be read, and this copy of install.sh carries no embedded trust list either: refusing to guess an anchor"
			source="$tree, this source checkout's own release anchor (the file the ccsio binary is built with); this install.sh has no embedded trust list because no publisher wrote one into it"
		fi
	fi

	# The channel's copy: published for a person to read, never believed by this script.
	served=$WORK/channel_signers
	fetch allowed_signers "$served" ||
		die "$E_NO_SIGNERS" "the channel has no allowed_signers: $CHANNEL does not publish the complete channel S1 names, and this installer reads that file to compare it with its own anchor (it never verifies with it)"
	trust_keys "$SIGNERS" >"$cmp_a"
	trust_keys "$served" >"$cmp_b"
	say "trust list: $source"
	if cmp -s "$cmp_a" "$cmp_b"; then
		say "channel's allowed_signers: the same keys, as published"
	else
		say "note: the channel's allowed_signers is not the trust list this installer decides with; it is published to be read and not believed, and verifying continues with the list named above"
	fi

	# The trust list has to name our principal and authorize our namespace. ssh-keygen
	# rejects either mismatch, but only this reading can say which one it was, and S2 asks
	# the installer to say why it stopped.
	local verdict
	verdict=$(
		awk -v principal="$PRINCIPAL" -v ns="$NAMESPACE" '
			/^[[:space:]]*#/ { next }
			/^[[:space:]]*$/ { next }
			{
				nsp = ""
				for (i = 2; i <= NF; i++) if ($i ~ /^namespaces=/) nsp = $i
				if ($1 == principal || $1 == "*") {
					saw = 1
					sub(/^namespaces=/, "", nsp)
					gsub(/"/, "", nsp)
					n = split(nsp, list, ",")
					for (k = 1; k <= n; k++) if (list[k] == ns) authorized = 1
				}
			}
			END {
				if (!saw) print "no-principal"
				else if (!authorized) print "no-namespace"
				else print "ok"
			}
		' "$SIGNERS"
	)
	case $verdict in
	ok) ;;
	no-principal)
		die "$E_PRINCIPAL" "the trust list this installer decides with lists no key for principal $PRINCIPAL: this is not the ccsio release channel"
		;;
	no-namespace)
		die "$E_NAMESPACE" "the trust list this installer decides with does not authorize the $NAMESPACE namespace for $PRINCIPAL: a signature in another namespace is not a release signature"
		;;
	*)
		die "$E_MANIFEST" "the trust list this installer decides with could not be read as one"
		;;
	esac
}

verify_signature() {
	# verify_signature <name on the channel> <manifest file> <signature file>
	local name=$1 man=$2 sig=$3 out reason fp
	[ -f "$sig" ] ||
		die "$E_UNSIGNED" "$name is not signed: the channel serves no $name.sig, and an unsigned manifest is only a request to install whatever it points at"

	if out=$(ssh-keygen -Y verify -f "$SIGNERS" -I "$PRINCIPAL" -n "$NAMESPACE" -s "$sig" <"$man" 2>&1); then
		return 0
	fi

	# Which link broke? ssh-keygen checks the key and the payload together, so ask it the
	# one question it answers separately: which key made this signature. find-principals
	# does not look at the payload, so a key that matches while the signature fails means
	# the bytes moved after signing.
	reason=$(printf '%s\n' "$out" | sed -n '1p')
	case $reason in
	*"namespace does not match"*)
		die "$E_NAMESPACE" "$name was signed in a namespace other than $NAMESPACE: $reason"
		;;
	esac
	fp=$(ssh-keygen -Y find-principals -f "$SIGNERS" -s "$sig" <"$man" 2>/dev/null) || fp=""
	if [ -z "$fp" ]; then
		die "$E_KEY" "$name was signed by a key the trust list this installer carries does not name, so it is not trusted (it verifies $PRINCIPAL in the $NAMESPACE namespace, and never with the list the channel serves)"
	fi
	die "$E_ALTERED" "the signature does not cover $name: these bytes changed after the release was signed ($reason)"
}

# ---------------------------------------------------------------------------
# the manifest
# ---------------------------------------------------------------------------

# The manifest is fetched before the trust list and trusted only afterwards: a mirror that
# is down has to be reported as a channel that served nothing, not as a channel with no
# signers, and nothing read here is used until check_manifest says it is signed.
get_manifest() {
	# get_manifest <name on the channel> -> 0 when the channel served it
	MANIFEST=$WORK/$1
	fetch "$1" "$MANIFEST" || return 1
	SIG_FILE=$WORK/$1.sig
	fetch "$1.sig" "$SIG_FILE" || SIG_FILE=$WORK/$1.absent.sig
	return 0
}

check_manifest() {
	verify_signature "$1" "$MANIFEST" "$SIG_FILE"
}

manifest_version() {
	awk '
		function qstr(rec, key,   re, s, e) {
			re = "\"" key "\"[ \t]*:[ \t]*\""
			if (!match(rec, re)) return ""
			s = RSTART + RLENGTH
			e = index(substr(rec, s), "\"")
			if (e == 0) return ""
			return substr(rec, s, e - 1)
		}
		BEGIN { RS = "\0" }
		{
			head = $0
			i = index(head, "\"artifacts\"")
			if (i > 0) head = substr(head, 1, i - 1)
			v = qstr(head, "version")
			if (v != "") print v
		}
	' "$MANIFEST"
}

manifest_versions() {
	awk '
		BEGIN { RS = "\0" }
		{
			i = index($0, "\"versions\"")
			if (!i) next
			t = substr($0, i)
			b = index(t, "[")
			e = index(t, "]")
			if (!b || !e || e < b) next
			body = substr(t, b + 1, e - b - 1)
			while (match(body, /"[^"]*"/)) {
				print substr(body, RSTART + 1, RLENGTH - 2)
				body = substr(body, RSTART + RLENGTH)
			}
		}
	' "$MANIFEST"
}

# The release document is signed as a whole, so these bytes are exactly what the publisher
# wrote; how they are laid out is theirs to choose. This reads the document, one
# os/arch/file/sha256 line per artifact, and does not care about line breaks.
manifest_artifacts() {
	awk '
		function qstr(rec, key,   re, s, e) {
			re = "\"" key "\"[ \t]*:[ \t]*\""
			if (!match(rec, re)) return ""
			s = RSTART + RLENGTH
			e = index(substr(rec, s), "\"")
			if (e == 0) return ""
			return substr(rec, s, e - 1)
		}
		BEGIN { RS = "\0" }
		{
			i = index($0, "\"artifacts\"")
			if (!i) next
			t = substr($0, i)
			b = index(t, "[")
			e = index(t, "]")
			if (!b || !e || e < b) next
			body = substr(t, b + 1, e - b - 1)
			n = split(body, parts, "}")
			for (k = 1; k <= n; k++) {
				os = qstr(parts[k], "os")
				arch = qstr(parts[k], "arch")
				file = qstr(parts[k], "file")
				sha = qstr(parts[k], "sha256")
				if (os != "" && arch != "" && file != "" && sha != "")
					print os "\t" arch "\t" file "\t" sha
			}
		}
	' "$MANIFEST"
}

detect_platform() {
	local sys machine
	sys=$(uname -s)
	machine=$(uname -m)
	case $sys in
	Linux) OS=linux ;;
	Darwin) OS=darwin ;;
	*) OS=$(printf '%s' "$sys" | tr '[:upper:]' '[:lower:]') ;;
	esac
	case $machine in
	x86_64 | amd64) ARCH=amd64 ;;
	aarch64 | arm64) ARCH=arm64 ;;
	*) ARCH=$(printf '%s' "$machine" | tr '[:upper:]' '[:lower:]') ;;
	esac
}

# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------

main() {
	parse_args "$@"
	resolve_dirs
	resolve_channel
	check_tools

	mkdir -p "$ROOT"
	mkdir -p "$ROOT/tmp"
	chmod 700 "$ROOT/tmp"
	WORK=$(mktemp -d "$ROOT/tmp/run.XXXXXX")

	get_manifest manifest.json ||
		die "$E_CHANNEL" "cannot read manifest.json from the channel ($CHANNEL): without the release manifest there is nothing verified to install"
	load_signers
	check_manifest manifest.json
	VERSION=$(manifest_version)
	[ -n "$VERSION" ] ||
		die "$E_MANIFEST" "manifest.json declares no version: it is not a ccsio release manifest"
	valid_version "$VERSION" ||
		die "$E_MANIFEST" "manifest.json declares a version this installer cannot name: $VERSION"

	if [ -n "$OPT_VERSION" ] && [ "$OPT_VERSION" != "$VERSION" ]; then
		local wanted=manifest-"$OPT_VERSION".json
		get_manifest "$wanted" ||
			die "$E_VERSION" "the channel does not offer version $OPT_VERSION: it has no $wanted, and it offers $(printf '%s' "$(manifest_versions | tr '\n' ' ')" | sed 's/[[:space:]]*$//')"
		check_manifest "$wanted"
		local declares
		declares=$(manifest_version)
		[ "$declares" = "$OPT_VERSION" ] ||
			die "$E_VERSION" "$wanted is not a manifest for version $OPT_VERSION: it declares $declares"
		VERSION=$OPT_VERSION
	fi

	detect_platform

	if [ "$OPT_LIST" = 1 ]; then
		list_channel
		exit 0
	fi
	pick_artifact
}

pick_artifact() {
	local artifacts=$WORK/artifacts.tsv
	manifest_artifacts >"$artifacts"
	[ -s "$artifacts" ] ||
		die "$E_MANIFEST" "manifest.json declares no artifacts for any platform, so there is nothing this installer could verify"

	local file want
	file=$(awk -F'\t' -v o="$OS" -v a="$ARCH" '$1 == o && $2 == a { print $3; exit }' "$artifacts")
	if [ -z "$file" ]; then
		die "$E_PLATFORM" "no artifact for $OS/$ARCH on this channel: it offers $(awk -F'\t' '{ printf "%s/%s ", $1, $2 }' "$artifacts" | sed 's/[[:space:]]*$//')"
	fi
	want=$(awk -F'\t' -v o="$OS" -v a="$ARCH" '$1 == o && $2 == a { print $4; exit }' "$artifacts" | tr '[:upper:]' '[:lower:]')

	case $file in
	/* | .* | -* | */ | *..*)
		die "$E_ARTIFACT" "artifact name is not fetchable as a file inside the channel: $file"
		;;
	esac
	# A relative path is allowed (a channel may keep one directory per version, which is
	# the other shape S1 names); the name that reaches the tool is still a ccsio tarball.
	case ${file##*/} in
	"$PROGRAM"-*.tar.gz) ;;
	*) die "$E_ARTIFACT" "artifact name is not a ccsio release tarball: $file" ;;
	esac
	case $want in
	*[!0-9a-f]*) die "$E_MANIFEST" "manifest.json declares a sha256 that is not hexadecimal for $file" ;;
	esac
	[ "${#want}" -eq 64 ] ||
		die "$E_MANIFEST" "manifest.json declares a sha256 that is not 64 hex digits for $file"

	say "verified: the manifest signature in the $NAMESPACE namespace, and $VERSION for $OS/$ARCH"

	local tarball=$WORK/artifact.tar.gz
	fetch "$file" "$tarball" ||
		die "$E_CHANNEL" "cannot read $file from the channel ($CHANNEL), which the verified manifest names for $OS/$ARCH"

	local got
	got=$(hash_file "$tarball")
	[ "$got" = "$want" ] ||
		die "$E_SHA" "sha256 mismatch for $file: the verified manifest declares $want, what was downloaded hashes as $got"

	# Refuse an archive that would write outside its own directory before handing it to
	# tar. (GNU tar refuses them too; the message here is the one that says who refused.)
	local members
	if ! members=$(tar -tzf "$tarball" 2>&1); then
		die "$E_ARTIFACT" "$file is not a readable .tar.gz: $(printf '%s\n' "$members" | sed -n '1p')"
	fi
	if printf '%s\n' "$members" | grep -Eq '(^|/)\.\.(/|$)|^/'; then
		die "$E_ARTIFACT" "$file is refused: the archive contains an unsafe path, one that is absolute or leaves its own directory"
	fi

	local extract=$WORK/extract
	mkdir -p "$extract"
	chmod 700 "$extract"
	tar -xzf "$tarball" -C "$extract" ||
		die "$E_ARTIFACT" "$file could not be extracted"

	local found count binary
	found=$(find "$extract" -type f -name "$PROGRAM")
	count=$(printf '%s\n' "$found" | grep -c . || true)
	if [ "$count" != 1 ]; then
		die "$E_ARTIFACT" "$file contains $count $PROGRAM binaries where a release ships exactly one"
	fi
	binary=$(printf '%s\n' "$found" | sed -n '1p')
	chmod 0755 "$binary"

	say "verified: sha256 $got for $file"
	install_version "$binary"
}

list_channel() {
	local offered
	offered=$(manifest_versions | grep -v "^$VERSION\$" || true)
	printf 'ccsio %s, from %s, signature verified in the %s namespace\n' "$VERSION" "$CHANNEL" "$NAMESPACE"
	if [ -n "$offered" ]; then
		printf 'also on this channel: %s\n' "$(printf '%s' "$offered" | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
	fi
	printf 'os\tarch\tfile\tsha256\n'
	manifest_artifacts
}

# ---------------------------------------------------------------------------
# the name on PATH (S12)
# ---------------------------------------------------------------------------

path_entries() {
	# path_entries — one line per directory the caller's PATH names, in order, keeping an
	# empty entry (which means the current directory). Split by hand rather than with
	# `for dir in $PATH`, which would glob-match an entry holding a * .
	local rest=${PATH:-} dir
	while :; do
		dir=${rest%%:*}
		printf '%s\n' "$dir"
		case $rest in
		*:*) rest=${rest#*:} ;;
		*) break ;;
		esac
	done
}

canon_dir() {
	# canon_dir <dir> — an absolute spelling that survives symlinks in the path (/tmp that
	# is really /private/tmp), printed from a subshell because the installer's own working
	# directory is none of its business. Physical, with pwd -P: the logical path would leave
	# a symlink standing in for its target, and then a --bin-dir spelled through a link never
	# matches the real directory the caller's PATH holds, which is the name check skipping
	# itself while the note claims the directory is off PATH.
	local d=${1:-}
	[ -n "$d" ] || d=$PWD
	if [ -d "$d" ]; then
		(
			CDPATH=
			cd -- "$d" && pwd -P
		)
	else
		absolute "$d"
	fi
}

path_dirs() {
	# path_dirs — the PATH entries canon_dir'd, so a trailing slash or a symlinked prefix
	# still recognizes the directory it is.
	path_entries | while IFS= read -r dir; do
		[ -n "$dir" ] || dir=$PWD
		while [ "$dir" != "/" ] && [ "${dir%/}" != "$dir" ]; do
			dir=${dir%/}
		done
		canon_dir "$dir"
	done
}

resolve_chain() {
	# resolve_chain <path> — the file a name reaches, following the launcher -> version
	# chain the way the launcher itself does. S12 compares files, not names.
	local p=$1 link dir base guard=0
	while [ -L "$p" ]; do
		guard=$((guard + 1))
		[ "$guard" -le 40 ] || return 1
		link=$(readlink -- "$p") || return 1
		case $link in
		/*) p=$link ;;
		*) p=$(dirname -- "$p")/$link ;;
		esac
	done
	dir=$(dirname -- "$p")
	base=$(basename -- "$p")
	printf '%s/%s\n' "$(canon_dir "$dir")" "$base"
}

first_on_path() {
	# first_on_path <name> — the first thing the caller's PATH resolves <name> to, which is
	# the file the user gets when they type it. `command -v` would also answer with a shell
	# function or an alias, and neither is something this installer can install over.
	local name=$1 dir cand
	while IFS= read -r dir; do
		cand=$dir/$name
		# The test the shell makes before running a name: executable, and not a directory.
		# A directory by that name is nobody winning it, and refusing over one would be this
		# script inventing an obstacle.
		if [ -x "$cand" ] && [ ! -d "$cand" ]; then
			printf '%s\n' "$cand"
			return 0
		fi
	done < <(path_dirs)
	return 1
}

bin_dir_on_path() {
	local want dir
	want=$(canon_dir "$BIN_DIR")
	while IFS= read -r dir; do
		if [ "$dir" = "$want" ]; then
			return 0
		fi
	done < <(path_dirs)
	return 1
}

chain_is_this_run() {
	# chain_is_this_run <where the name's chain ends> — the only two files the name may
	# reach. The version directory this run installed is the promise itself. The launcher is
	# allowed as itself and only as a regular script: it reads <root>/current when it runs,
	# and this run has just written that pointer, so it reaches this build and every later
	# one. A launcher somebody replaced with a link to another version resolves past itself
	# to a build this run did not install, and comparing the name against itself cannot see
	# that: shim and winner are the same file there, so equal chains proved nothing.
	local ours=$1 launcher=$ROOT/bin/$PROGRAM
	if [ "$ours" = "$(canon_dir "$ROOT/versions/$VERSION")/$PROGRAM" ]; then
		return 0
	fi
	if [ "$ours" = "$(canon_dir "$ROOT/bin")/$PROGRAM" ] && [ -f "$launcher" ] && [ ! -L "$launcher" ]; then
		return 0
	fi
	return 1
}

check_name_on_path() {
	# check_name_on_path — S12: installing is over when the name the user is about to type
	# is the file this run wrote. E11 came out of the rehearsal (Log L10) because nobody had
	# ever asked: the installer printed its own shim, exited 0, and `ccsio --version` still
	# answered a build nobody registered. When $BIN_DIR is not on PATH at all nothing was
	# claimed about the name, so the old note stands and the run succeeds.
	local shim=$BIN_DIR/$PROGRAM winner ours theirs
	if ! bin_dir_on_path; then
		say "note: $BIN_DIR is not on PATH, so add it to run $PROGRAM by name"
		return 0
	fi
	if ! winner=$(first_on_path "$PROGRAM"); then
		say "note: nothing named $PROGRAM resolves on PATH, not even $shim"
		return 0
	fi
	ours=$(resolve_chain "$shim") || ours=''
	if [ -n "$ours" ] && ! chain_is_this_run "$ours"; then
		not_this_build "$winner" "$shim" "$ours"
	fi
	if [ -n "$ours" ] && theirs=$(resolve_chain "$winner") && [ "$theirs" = "$ours" ]; then
		return 0
	fi
	shadowed "$winner" "$shim"
}

what_it_reports() {
	# what_it_reports <path> — the first line that file answers to --version, which is how a
	# refusal says what the user would actually run. Its exit status is not read, on purpose:
	# the question is what it prints, not whether it liked the argument. Running it is not a
	# side effect this script invented; it is what typing the name does.
	local path=$1 line
	line=$(
		{
			if command -v timeout >/dev/null 2>&1; then
				timeout 5 "$path" --version
			else
				"$path" --version
			fi
		} 2>&1 | sed -n '1p'
	) || true
	[ -n "$line" ] || line='(it printed nothing for --version)'
	printf '%s\n' "$line"
}

shadowed() {
	# shadowed <the file that wins the name> <the file this run wrote> — name it, say what
	# it answers, give the one command that fixes it, and leave the other file alone: S12
	# forbids deleting or overwriting what is not ours.
	local winner=$1 shim=$2 reports
	reports=$(what_it_reports "$winner")
	say "the name on PATH belongs to somebody else, so this install did not finish:"
	say "  wins on PATH:       $winner  (it reports: $reports)"
	say "  this install wrote: $shim -> $ROOT/versions/$VERSION/$PROGRAM"
	say "  to fix it, run:      PATH=\"$BIN_DIR:\$PATH\""
	say "  then check with:     command -v $PROGRAM"
	say "  install.sh will not delete or overwrite $winner: it is not ours to touch"
	die "$E_SHADOW" "another $PROGRAM wins on PATH: $winner is not the ccsio this installer just wrote (exit 18: the files are installed, the name is not)"
}

not_this_build() {
	# not_this_build <winner> <the file this run wrote> <where the name's chain ends> — the
	# name resolves, but past our own launcher to a build this run did not install. Same exit
	# code as a foreign winner, because it is the same broken promise, and a different fix:
	# the file in question lives inside the install root, and the command that repairs it is
	# the one that removes it so the next run writes its own launcher. Nothing here deletes,
	# overwrites or "repairs" it: S12 names what it will not touch.
	local winner=$1 shim=$2 ends=$3 launcher=$ROOT/bin/$PROGRAM reports
	reports=$(what_it_reports "$winner")
	say "the name on PATH does not reach the version this run installed, so this install did not finish:"
	say "  wins on PATH:       $winner  (it reports: $reports)"
	say "  its chain ends at:  $ends"
	say "  this install wrote: $shim -> $ROOT/versions/$VERSION/$PROGRAM"
	say "  $launcher is a link to a build this run did not install, so the name runs that one"
	say "  to fix it, run:      rm -- \"$launcher\""
	say "  then re-run this installer, and check with: command -v $PROGRAM"
	say "  install.sh will not delete or overwrite $launcher: it is not ours to touch"
	die "$E_SHADOW" "$PROGRAM resolves to a build this run did not install: $ends is not the $PROGRAM this installer just wrote (exit 18: the files are installed, the name is not)"
}

install_version() {
	# Every policy refusal happens in here before a byte moves.
	local binary=$1
	local dest=$ROOT/versions/$VERSION
	local launcher=$ROOT/bin/$PROGRAM
	local shim=$BIN_DIR/$PROGRAM
	local already=0

	if [ -e "$dest" ] || [ -L "$dest" ]; then
		if [ -f "$dest/$PROGRAM" ] && cmp -s "$dest/$PROGRAM" "$binary"; then
			already=1
			say "$PROGRAM $VERSION is already installed, and this is the same build: nothing to write"
		else
			die "$E_EXISTS" "a different build of $PROGRAM $VERSION is already installed at $dest: refusing to overwrite a version this machine already holds (the channel offers another artifact under the same number)"
		fi
	fi

	# The name on PATH is the only thing here that might belong to somebody else, so it
	# is checked while everything is still reversible.
	if [ -L "$shim" ]; then
		if [ "$(readlink "$shim")" != "$launcher" ]; then
			die "$E_SHIM" "$shim already links to $(readlink "$shim"): refusing to overwrite something that is not the ccsio launcher"
		fi
	elif [ -e "$shim" ]; then
		die "$E_SHIM" "$shim already exists and is not a ccsio launcher: refusing to overwrite it (remove it, or install with --bin-dir)"
	fi

	if [ "$already" = 0 ]; then
		mkdir -p "$dest"
		chmod 700 "$dest"
		mv -- "$binary" "$dest/$PROGRAM"
		say "installed $dest/$PROGRAM"
	fi

	set_current

	if [ -d "$launcher" ]; then
		die "$E_SHIM" "$launcher is a directory, so the ccsio launcher cannot live there"
	fi
	if [ ! -e "$launcher" ]; then
		mkdir -p "$ROOT/bin"
		write_launcher "$launcher"
		say "launcher $launcher"
	else
		say "launcher $launcher already exists and is left alone"
	fi

	mkdir -p "$BIN_DIR"
	if [ ! -e "$shim" ] && [ ! -L "$shim" ]; then
		ln -s "$launcher" "$shim"
		say "on PATH: $shim -> $launcher"
	fi

	say "$PROGRAM $VERSION is current ($ROOT/current holds the number; installed versions live in $ROOT/versions)"
	check_name_on_path
}

set_current() {
	# The pointer is a file holding the version number, replaced by rename: writing it is
	# atomic, it never has to be re-written by an updater, and `mv` onto a symlink that
	# points at a directory would move the file *into* that directory instead.
	local cur="" tmp=$ROOT/.current.$$
	if [ -f "$ROOT/current" ]; then
		read -r cur <"$ROOT/current" || true
	fi
	if [ "$cur" = "$VERSION" ]; then
		return 0
	fi
	printf '%s\n' "$VERSION" >"$tmp"
	chmod 644 "$tmp"
	mv -f "$tmp" "$ROOT/current"
}

write_launcher() {
	local path=$1
	local tmp=$path.tmp.$$
	cat >"$tmp" <<'LAUNCHER'
#!/bin/sh
# ccsio launcher, written once by install.sh.
#
# It reads the pointer instead of a copy of it: changing the current version writes a new
# number into <root>/current, so nothing on PATH is ever rewritten and a running ccsio is
# never replaced in place. It follows its own symlink because ~/.local/bin/ccsio is that
# link, and $0 alone would point the root at ~/.local.
self=$0
case $self in
*/*) ;;
*) self=$(command -v -- "$0" 2>/dev/null || printf '%s' "$0") ;;
esac
while [ -L "$self" ]; do
	link=$(readlink "$self") || break
	case $link in
	/*) self=$link ;;
	*) self=$(dirname -- "$self")/$link ;;
	esac
done
root=$(CDPATH= cd -- "$(dirname -- "$self")/.." && pwd) || root=""
version=""
if [ -n "$root" ] && [ -f "$root/current" ]; then
	read -r version <"$root/current" || version=""
fi
if [ -z "$version" ] || [ ! -x "$root/versions/$version/ccsio" ]; then
	printf 'ccsio: no version selected under %s\n' "${root:-$self/..}" >&2
	printf 'ccsio: install one from the release channel, or write its number into current\n' >&2
	exit 1
fi
exec "$root/versions/$version/ccsio" "$@"
LAUNCHER
	chmod 0755 "$tmp"
	mv -f "$tmp" "$path"
}

main "$@"
