#!/bin/bash
#
# AI Agent DFIR forensic acquisition collector for macOS.
#
# Designed for the system Bash 3.2 shipped with macOS. The collector uses only
# native utilities and does not require Python. Parsing and report generation
# are intentionally performed later with aia_dfir.py on an analyst workstation.
#

set -u
umask 077

SCRIPT_VERSION="2.2.2-macos-1"
OUTPUT_ROOT="/private/tmp"
SINGLE_HOME=""
ALL_USERS=0
NO_ZIP=0
VERBOSE=0

usage() {
    cat <<'EOF'
Usage: Collect-AIAgentForensics-macOS.sh [options]

Options:
  --output-root PATH   Parent directory for collection output
                       (default: /private/tmp)
  --user-home PATH     Collect one specific user home (default: current user)
  --all-users          Collect eligible profiles under /Users (root recommended)
  --no-zip             Leave the collection as a directory without creating ZIP
  --verbose            Print each collected artifact
  -h, --help           Show this help

Examples:
  sudo bash Collect-AIAgentForensics-macOS.sh --all-users
  bash Collect-AIAgentForensics-macOS.sh --user-home /Users/alice
  bash Collect-AIAgentForensics-macOS.sh --output-root /var/tmp --no-zip

The ZIP can be analyzed on a workstation with:
  python3 aia_dfir.py analyze AIAgentDFIR_<host>_<timestamp>.zip -o Investigation
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

warn() {
    printf 'WARNING: %s\n' "$*" >&2
}

log() {
    if [ "$VERBOSE" -eq 1 ]; then
        printf '%s\n' "$*"
    fi
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output-root)
            [ "$#" -ge 2 ] || die "--output-root requires a path"
            OUTPUT_ROOT=$2
            shift 2
            ;;
        --user-home)
            [ "$#" -ge 2 ] || die "--user-home requires a path"
            SINGLE_HOME=$2
            shift 2
            ;;
        --all-users)
            ALL_USERS=1
            shift
            ;;
        --no-zip)
            NO_ZIP=1
            shift
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1"
            ;;
    esac
done

[ "$(uname -s 2>/dev/null || true)" = "Darwin" ] ||
    warn "This collector is designed for macOS; continuing on $(uname -s 2>/dev/null || echo unknown)."

[ ! -z "$SINGLE_HOME" ] && [ "$ALL_USERS" -eq 1 ] &&
    die "--user-home and --all-users cannot be used together"

command -v find >/dev/null 2>&1 || die "find is required"
command -v cp >/dev/null 2>&1 || die "cp is required"
command -v stat >/dev/null 2>&1 || die "stat is required"

HOST_NAME=$(scutil --get ComputerName 2>/dev/null || hostname -s 2>/dev/null || hostname)
SAFE_HOST=$(printf '%s' "$HOST_NAME" | tr -c 'A-Za-z0-9._-' '_')
TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')

mkdir -p "$OUTPUT_ROOT" || die "Unable to create output root: $OUTPUT_ROOT"
OUTPUT_DIR="${OUTPUT_ROOT%/}/AIAgentDFIR_${SAFE_HOST}_${TIMESTAMP}"
if [ -e "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="${OUTPUT_DIR}_$$"
fi
RAW_DIR="$OUTPUT_DIR/Raw"
mkdir -p "$RAW_DIR" || die "Unable to create collection directory: $OUTPUT_DIR"

INVENTORY="$OUTPUT_DIR/Artifact_Inventory.csv"
ERRORS="$OUTPUT_DIR/Collection_Errors.csv"
SUMMARY="$OUTPUT_DIR/Collection_Summary.txt"
HASHES="$OUTPUT_DIR/SHA256SUMS.txt"

printf '%s\n' '"Username","ArtifactType","SourcePath","CollectedPath","Size","ModifiedUtc","SHA256"' > "$INVENTORY"
printf '%s\n' '"Username","SourcePath","Error"' > "$ERRORS"

csv_escape() {
    # CSV quoting: double embedded quote characters and wrap the field.
    printf '"'
    printf '%s' "$1" | sed 's/"/""/g'
    printf '"'
}

sha256_file() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" 2>/dev/null | awk '{print $NF}'
    else
        printf ''
    fi
}

file_size() {
    stat -f '%z' "$1" 2>/dev/null || wc -c < "$1" 2>/dev/null || printf '0'
}

file_mtime_utc() {
    local epoch
    epoch=$(stat -f '%m' "$1" 2>/dev/null || printf '')
    if [ ! -z "$epoch" ]; then
        date -u -r "$epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf ''
    fi
}

record_error() {
    local username=$1
    local source=$2
    local message=$3
    {
        csv_escape "$username"; printf ','
        csv_escape "$source"; printf ','
        csv_escape "$message"; printf '\n'
    } >> "$ERRORS"
    ERROR_COUNT=$((ERROR_COUNT + 1))
}

artifact_type() {
    local source=$1
    case "$source" in
        */.codex/sessions/*.jsonl) printf 'CodexSessionJsonl' ;;
        */.codex/*.sqlite|*/.codex/*.sqlite3|*/.codex/*.db) printf 'CodexRuntimeSqlite' ;;
        */.codex/*-wal) printf 'CodexSqliteWal' ;;
        */.codex/*-shm) printf 'CodexSqliteShm' ;;
        */.codex/session_index.jsonl) printf 'CodexSessionIndex' ;;
        */.gemini/antigravity-cli/brain/*/.system_generated/logs/transcript_full.jsonl)
            printf 'GeminiAntigravityTranscriptJsonl'
            ;;
        */.gemini/antigravity-cli/brain/*/transcript.jsonl)
            printf 'GeminiAntigravityTranscriptJsonl'
            ;;
        *) printf 'AIAgentArtifact' ;;
    esac
}

copy_artifact() {
    local home_path=$1
    local username=$2
    local source=$3
    local relative destination digest size modified kind

    case "$source" in
        "$home_path"/*) relative=${source#"$home_path"/} ;;
        *) relative=$(basename "$source") ;;
    esac

    destination="$RAW_DIR/$username/$relative"
    mkdir -p "$(dirname "$destination")" || {
        record_error "$username" "$source" "Unable to create destination directory"
        return
    }

    if ! cp -p "$source" "$destination" 2>/dev/null; then
        record_error "$username" "$source" "Copy failed (permission denied, locked, or unreadable)"
        return
    fi

    digest=$(sha256_file "$destination")
    size=$(file_size "$destination")
    modified=$(file_mtime_utc "$destination")
    kind=$(artifact_type "$source")

    {
        csv_escape "$username"; printf ','
        csv_escape "$kind"; printf ','
        csv_escape "$source"; printf ','
        csv_escape "$destination"; printf ','
        csv_escape "$size"; printf ','
        csv_escape "$modified"; printf ','
        csv_escape "$digest"; printf '\n'
    } >> "$INVENTORY"

    if [ ! -z "$digest" ]; then
        printf '%s  %s\n' "$digest" "${destination#"$OUTPUT_DIR"/}" >> "$HASHES"
    fi

    ARTIFACT_COUNT=$((ARTIFACT_COUNT + 1))
    case "$kind" in
        Codex*) CODEX_COUNT=$((CODEX_COUNT + 1)) ;;
        Gemini*) GEMINI_COUNT=$((GEMINI_COUNT + 1)) ;;
    esac
    log "Collected: $source"
}

collect_profile() {
    local home_path=$1
    local username
    username=$(basename "$home_path")

    [ -d "$home_path" ] || {
        record_error "$username" "$home_path" "User home does not exist"
        return
    }

    PROFILE_COUNT=$((PROFILE_COUNT + 1))

    # Codex conversation evidence.
    if [ -d "$home_path/.codex/sessions" ]; then
        while IFS= read -r -d '' source; do
            copy_artifact "$home_path" "$username" "$source"
        done < <(find "$home_path/.codex/sessions" -type f -name '*.jsonl' -print0 2>/dev/null)
    fi

    # Codex runtime databases and their consistency sidecars.
    if [ -d "$home_path/.codex" ]; then
        for source in "$home_path/.codex"/*; do
            [ -f "$source" ] || continue
            case "$(basename "$source")" in
                *.sqlite|*.sqlite3|*.db|*.sqlite-wal|*.sqlite-shm|*.db-wal|*.db-shm|session_index.jsonl)
                    copy_artifact "$home_path" "$username" "$source"
                    ;;
            esac
        done
    fi

    # Gemini Antigravity conversation evidence.
    if [ -d "$home_path/.gemini/antigravity-cli/brain" ]; then
        while IFS= read -r -d '' source; do
            copy_artifact "$home_path" "$username" "$source"
        done < <(
            find "$home_path/.gemini/antigravity-cli/brain" -type f \
                \( -name 'transcript_full.jsonl' -o -name 'transcript.jsonl' \) \
                -print0 2>/dev/null
        )
    fi
}

ARTIFACT_COUNT=0
CODEX_COUNT=0
GEMINI_COUNT=0
PROFILE_COUNT=0
ERROR_COUNT=0

DEFAULT_HOME=${HOME%/}
if [ ! -z "${SUDO_USER:-}" ] && [ "${SUDO_USER:-}" != "root" ]; then
    SUDO_HOME=$(dscl . -read "/Users/${SUDO_USER}" NFSHomeDirectory 2>/dev/null |
        awk '{print $2}')
    if [ -z "$SUDO_HOME" ]; then
        SUDO_HOME="/Users/${SUDO_USER}"
    fi
    if [ -d "$SUDO_HOME" ]; then
        DEFAULT_HOME=${SUDO_HOME%/}
    fi
fi

if [ "$ALL_USERS" -eq 1 ]; then
    [ "$(id -u)" -eq 0 ] || warn "--all-users is most complete when run with sudo"
    for profile in /Users/*; do
        [ -d "$profile" ] || continue
        case "$(basename "$profile")" in
            Shared|Guest|.localized) continue ;;
        esac
        if [ -d "$profile/.codex" ] || [ -d "$profile/.gemini" ]; then
            collect_profile "$profile"
        fi
    done
elif [ ! -z "$SINGLE_HOME" ]; then
    collect_profile "${SINGLE_HOME%/}"
else
    collect_profile "$DEFAULT_HOME"
fi

{
    printf 'AI Agent DFIR macOS Collector\n'
    printf 'CollectorVersion=%s\n' "$SCRIPT_VERSION"
    printf 'CollectedUtc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'Hostname=%s\n' "$HOST_NAME"
    printf 'RunningAs=%s\n' "$(id -un 2>/dev/null || printf unknown)"
    printf 'macOSVersion=%s\n' "$(sw_vers -productVersion 2>/dev/null || printf unknown)"
    printf 'ProfilesExamined=%s\n' "$PROFILE_COUNT"
    printf 'ArtifactCount=%s\n' "$ARTIFACT_COUNT"
    printf 'CodexArtifactCount=%s\n' "$CODEX_COUNT"
    printf 'GeminiArtifactCount=%s\n' "$GEMINI_COUNT"
    printf 'CollectionErrorCount=%s\n' "$ERROR_COUNT"
    printf 'RawArtifactsIncluded=true\n'
    printf 'AnalyzerRequired=true\n'
} > "$SUMMARY"

ARCHIVE=""
if [ "$NO_ZIP" -eq 0 ]; then
    ARCHIVE="${OUTPUT_DIR}.zip"
    if command -v ditto >/dev/null 2>&1; then
        ditto -c -k --sequesterRsrc --keepParent "$OUTPUT_DIR" "$ARCHIVE" ||
            die "Unable to create ZIP archive with ditto"
    elif command -v zip >/dev/null 2>&1; then
        (
            cd "$(dirname "$OUTPUT_DIR")" || exit 1
            zip -qry "$ARCHIVE" "$(basename "$OUTPUT_DIR")"
        ) || die "Unable to create ZIP archive with zip"
    else
        die "Neither ditto nor zip is available; rerun with --no-zip"
    fi
fi

printf 'AI_AGENT_DFIR_STATUS=SUCCESS\n'
printf 'COMPUTER=%s\n' "$HOST_NAME"
printf 'PROFILES=%s\n' "$PROFILE_COUNT"
printf 'CODEX_ARTIFACTS=%s\n' "$CODEX_COUNT"
printf 'GEMINI_ARTIFACTS=%s\n' "$GEMINI_COUNT"
printf 'ARTIFACTS=%s\n' "$ARTIFACT_COUNT"
printf 'COLLECTION_ERRORS=%s\n' "$ERROR_COUNT"
printf 'OUTPUT_DIRECTORY=%s\n' "$OUTPUT_DIR"
if [ ! -z "$ARCHIVE" ]; then
    printf 'RETRIEVE_FILE=%s\n' "$ARCHIVE"
fi

exit 0
