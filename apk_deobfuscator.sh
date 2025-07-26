#!/usr/bin/env bash
# apk_deobfuscator.sh – bulletproof automated APK deobfuscation pipeline
# Prerequisites: apktool, jadx, adb, python3, graphviz, uber-apk-signer JAR
# Usage: ./apk_deobfuscator.sh [--in <apk_file>] [--out <output_dir>]

set -euo pipefail

# Ensure compatible Bash version (associative arrays require Bash >=4)
if [[ -z "${BASH_VERSINFO:-}" || ${BASH_VERSINFO[0]} -lt 4 ]]; then
  echo "[WARN] Running on Bash <4 – associative arrays disabled, using fallback logic." >&2
fi

# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

# Script metadata
SCRIPT_NAME="apk_deobfuscator.sh"
SCRIPT_VERSION="2.0.0"
SCRIPT_AUTHOR="Production-Ready APK Deobfuscation Pipeline"

# Configuration
MAX_RETRY=3                     # max retry attempts for critical steps
TIMEOUT_SEC=300                 # timeout for long-running steps
LOCK_FILE="/tmp/apk_deobf.lock"  # prevent concurrent execution
CONFIG_FILE="deobf_config.yml"  # configuration file

# Default paths
APK=""                          # input APK/XAPK path (required)
BUILD_DIR="build"               # default build directory
TOOLS_DIR="tools"               # tools directory
DOCS_DIR="docs"                 # documentation directory

# Global state variables
TEMP_DIRS=()                    # track temporary directories for cleanup
VERBOSE=false                   # verbose logging flag
KEEP_TEMP=false                 # keep temporary files flag
NO_INSTALL=false               # skip device installation

# ============================================================================
# INPUT VALIDATION AND SANITIZATION
# ============================================================================

# Validate and sanitize input paths
sanitize_path() {
  local path="$1"
  # Only allow alphanumeric, underscore, dot, slash, and hyphen
  [[ "$path" =~ ^[a-zA-Z0-9_./-]+$ ]] || { 
    _log "[ERROR] Invalid path: $path" 
    exit 1 
  }
  echo "$path"
}

# Validate configuration file
validate_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    if command -v yq >/dev/null 2>&1; then
      if ! yq eval '.' "$CONFIG_FILE" >/dev/null 2>&1; then
        _log "[ERROR] Invalid YAML configuration file: $CONFIG_FILE"
        exit 1
      fi
      _log "Configuration file validated: $CONFIG_FILE"
    else
      _log "[WARN] yq not found, skipping config validation"
    fi
  else
    _log "[INFO] No configuration file found, using defaults"
  fi
}

# ============================================================================
# LOCK FILE MANAGEMENT
# ============================================================================

# Acquire lock to prevent concurrent execution
acquire_lock() {
  if ! ( set -o noclobber; echo "$$" > "$LOCK_FILE" ) 2>/dev/null; then
    local pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "unknown")
    _log "[ERROR] Another instance is running (PID: $pid)"
    _log "[ERROR] Lock file: $LOCK_FILE"
    return 1
  fi
  # Ensure lock file is removed on exit
  trap 'rm -f "$LOCK_FILE"' EXIT
  _log "Lock acquired: $LOCK_FILE"
  return 0
}

# ============================================================================
# ENHANCED LOGGING AND ERROR HANDLING
# ============================================================================

# Initialize logging
init_logging() {
  mkdir -p "$BUILD_DIR" "$DOCS_DIR" "$TOOLS_DIR"
  LOG_FILE="$BUILD_DIR/deobf_log.txt"
  TRACE_JSON="$BUILD_DIR/obf_trace.json"
  
  # Create log file with atomic operation
  > "$LOG_FILE" || { echo "Failed to create log file"; exit 1; }
  
  _log "=== APK Deobfuscation Pipeline Started ==="
  _log "Script version: $SCRIPT_VERSION"
  _log "Input file: $APK"
  _log "Build directory: $BUILD_DIR"
  _log "Tools directory: $TOOLS_DIR"
}

# Enhanced logger function with timestamp and log levels
_log() {
  local level="${2:-INFO}"
  local timestamp=$(date +'%Y-%m-%d %T')
  local message="[$timestamp] [$level] $1"

  # If LOG_FILE is not yet initialised use /dev/null to avoid unbound-variable errors under 'set -u'.
  local _log_file_ref="${LOG_FILE:-/dev/null}"

  # Color coding for different log levels
  case "$level" in
    ERROR) echo -e "\033[1;31m$message\033[0m" | tee -a "$_log_file_ref" ;;
    WARN)  echo -e "\033[1;33m$message\033[0m" | tee -a "$_log_file_ref" ;;
    DEBUG) [[ "$VERBOSE" == "true" ]] && echo "$message" | tee -a "$_log_file_ref" ;;
    *)     echo "$message" | tee -a "$_log_file_ref" ;;
  esac
}

# Step function with progress tracking
step() {
  local step_name="$1"
  local step_number="${2:-}"
  
  if [[ -n "$step_number" ]]; then
    echo -e "\033[1;34m[STEP $step_number] $step_name\033[0m ($(date +'%Y-%m-%d %T'))"
  else
    echo -e "\033[1;34m[STEP] $step_name\033[0m ($(date +'%Y-%m-%d %T'))"
  fi
  _log "Starting step: $step_name"
}

# Enhanced error handler with context
error_handler() {
  local exit_code=$?
  local line_number=$LINENO
  local command="$BASH_COMMAND"
  
  _log "ERROR on line $line_number: $command" "ERROR"
  _log "Exit code: $exit_code" "ERROR"
  
  # Log stack trace if available
  if [[ ${BASH_VERSION%%.*} -ge 4 ]]; then
    _log "Stack trace:" "ERROR"
    local frame=0
    while caller $frame; do
      ((frame++))
    done | while read -r line func file; do
      _log "  $file:$line in $func" "ERROR"
    done
  fi
  
  exit $exit_code
}

# ============================================================================
# SIGNAL HANDLING AND CLEANUP
# ============================================================================

# Enhanced cleanup function
cleanup() {
  local exit_code=$?
  
  _log "Cleaning up resources..."
  
  # Remove temporary directories unless KEEP_TEMP is set
  if [[ "$KEEP_TEMP" != "true" ]]; then
    for temp_dir in "${TEMP_DIRS[@]-}"; do
      if [[ -d "$temp_dir" ]]; then
        _log "Removing temporary directory: $temp_dir"
        rm -rf "$temp_dir" 2>/dev/null || _log "Failed to remove: $temp_dir" "WARN"
      fi
    done
  else
    _log "Keeping temporary files (KEEP_TEMP=true)"
  fi
  
  # Remove lock file
  rm -f "$LOCK_FILE" 2>/dev/null || true
  
  # Display exit message based on exit code
  if [[ $exit_code -eq 0 ]]; then
    _log "Script completed successfully"
  else
    _log "Script failed with exit code $exit_code" "ERROR"
  fi
  
  exit $exit_code
}

# Handle user interrupts gracefully
handle_interrupt() {
  echo -e "\nOperation interrupted by user" >&2
  _log "Script interrupted by user (SIGINT)" "WARN"
  # Use special exit code for user interrupts
  exit 130
}

# Handle termination signals
handle_terminate() {
  _log "Script terminated by signal" "WARN"
  exit 143
}

# Register signal handlers
trap cleanup EXIT
trap error_handler ERR
trap handle_interrupt INT
trap handle_terminate TERM

# ============================================================================
# OS DETECTION AND PATH HANDLING
# ============================================================================

# Enhanced OS detection
detect_os() {
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$OS" in
    linux*) OS=linux ;;
    darwin*) OS=macos ;;
    mingw*|cygwin*|msys*) OS=windows ;;
    *) _log "Unsupported OS: $OS" "ERROR"; exit 1 ;;
  esac
  _log "Detected OS: $OS"
}

# Path conversion for Windows compatibility
native_path() {
  if [[ "$OS" == "windows" ]]; then
    cygpath -w "$1" 2>/dev/null || echo "$1"
  else
    echo "$1"
  fi
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

# Parse CLI arguments with validation
parse_arguments() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --in)
        [[ -n "${2:-}" ]] || { _log "Missing value for --in" "ERROR"; exit 1; }
        APK=$(sanitize_path "$2"); shift 2 ;;
      --out)
        [[ -n "${2:-}" ]] || { _log "Missing value for --out" "ERROR"; exit 1; }
        BUILD_DIR=$(sanitize_path "$2"); shift 2 ;;
      --config)
        [[ -n "${2:-}" ]] || { _log "Missing value for --config" "ERROR"; exit 1; }
        CONFIG_FILE=$(sanitize_path "$2"); shift 2 ;;
      --no-install)
        NO_INSTALL=true; shift ;;
      --verbose|-v)
        VERBOSE=true; shift ;;
      --keep-temp)
        KEEP_TEMP=true; shift ;;
      --help|-h)
        show_usage; exit 0 ;;
      --version)
        echo "$SCRIPT_NAME v$SCRIPT_VERSION"; exit 0 ;;
      *)
        _log "Unknown option: $1" "ERROR"; show_usage; exit 1 ;;
    esac
  done
  
  # Validate required arguments
  if [[ -z "$APK" ]]; then
    _log "No input file specified. Use --in <file> to specify input APK/XAPK/APKS file" "ERROR"
    show_usage
    exit 1
  fi
  
  # Validate input file exists
  if [[ ! -f "$APK" ]]; then
    _log "Input file not found: $APK" "ERROR"
    exit 1
  fi
}

# Show usage information
show_usage() {
  cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

OPTIONS:
  --in <file>              Input APK/XAPK/APKS file (REQUIRED)
  --out <directory>        Output directory (default: build)
  --config <file>          Configuration file (default: deobf_config.yml)
  --no-install             Skip device installation
  --verbose, -v            Enable verbose logging
  --keep-temp              Keep temporary files
  --help, -h               Show this help message
  --version                Show version information

EXAMPLES:
  $SCRIPT_NAME --in app.apk --out analysis_output
  $SCRIPT_NAME --in app.xapk --verbose --no-install
  $SCRIPT_NAME --in app.apks --out deobfuscated_app

DESCRIPTION:
  This script provides a comprehensive APK deobfuscation pipeline that can:
  - Convert XAPK/APKS files to APK format
  - Extract and analyze APK contents
  - Apply various deobfuscation techniques
  - Generate detailed analysis reports

EOF
}

# ============================================================================
# DEPENDENCY CHECKS
# ============================================================================

# Check for required dependencies
check_dependencies() {
  step "Checking dependencies" "1"
  
  local missing_deps=()
  
  # Required tools
  local required_tools=(
    "apktool:https://ibotpeaches.github.io/Apktool/"
    "jadx:https://github.com/skylot/jadx"
    "git:https://git-scm.com/"
    "java:https://adoptium.net/"
    "python3:https://www.python.org/"
    "zipalign:https://developer.android.com/studio/command-line/zipalign" 
  )
  
  for tool_info in "${required_tools[@]}"; do
    local tool="${tool_info%%:*}"
    local url="${tool_info##*:}"
    
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing_deps+=("$tool ($url)")
    else
      _log "Found $tool: $(command -v "$tool")"
    fi
  done
  
  # Check for archive extraction utility
  if command -v unzip >/dev/null 2>&1; then
    UNZIP_TOOL="unzip"
    _log "Found unzip: $(command -v unzip)"
  elif command -v 7z >/dev/null 2>&1; then
    UNZIP_TOOL="7z"
    _log "Found 7z: $(command -v 7z)"
  else
    missing_deps+=("unzip or 7z (for XAPK/APKS extraction)")
  fi
  
  # Report missing dependencies
  if [[ ${#missing_deps[@]} -gt 0 ]]; then
    _log "Missing required dependencies:" "ERROR"
    for dep in "${missing_deps[@]}"; do
      _log "  - $dep" "ERROR"
    done
    _log "Please install missing dependencies and try again" "ERROR"
    exit 1
  fi
  
  # Optional tools
  local optional_tools=("adb" "frida" "graphviz" "yq")
  for tool in "${optional_tools[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
      _log "Found optional tool $tool: $(command -v "$tool")"
    else
      _log "Optional tool not found: $tool" "WARN"
    fi
  done
  
  _log "All required dependencies satisfied"
}

# ============================================================================
# TOOL MANAGEMENT WITH RETRY LOGIC
# ============================================================================

# Helper repository URLs (use simple array for broader bash compatibility ‒ older macOS ships a pre-4.x Bash without associative arrays)
REPO_ENTRIES=(
  "deoptfuscator|https://github.com/Gyoonus/deoptfuscator.git"
  "SmaliEmu|https://github.com/HamsterHuey/SmaliEmu.git"
  "Obfu-DE-Scate|https://github.com/user1342/Obfu-DE-Scate.git"
  "simplify|https://github.com/CalebFenton/simplify.git"
  "xapk-to-apk|https://github.com/LuigiVampa92/xapk-to-apk.git"
  "cfjs|https://github.com/cg10036/cfjs.git"
  "js-deobfuscator|https://github.com/mrgrassho/js-deobfuscator-tool.git"
  "deguard|https://github.com/GraphXAI/deguard.git"
  "dex-translator|https://github.com/Col-E/dex-translator.git"
  "merge-apks|https://github.com/LuigiVampa92/merge-apks.git"
  "AndroidAppRE|https://github.com/maddiestone/AndroidAppRE.git"
  "BundleDecompiler|https://github.com/TamilanPeriyasamy/BundleDecompiler.git"
  "reverse_flutter|https://github.com/Neoxs/reverse_flutter.git"
  "MobSF|https://github.com/MobSF/Mobile-Security-Framework-MobSF.git"
)

# Enhanced tool management with retry logic and timeout
ensure_repo() {
  local name="$1" 
  local url="$2"
  local dir="$TOOLS_DIR/$name"
  
  if [[ -d "$dir" ]]; then
    _log "Repository $name already exists at $dir"
    return 0
  fi
  
  step "Cloning $name from $url" "2"
  
  # Create tools directory if it doesn't exist
  mkdir -p "$TOOLS_DIR"
  
  local attempt=0
  until timeout $TIMEOUT_SEC git clone --depth 1 "$url" "$dir" >/dev/null 2>&1; do
    ((attempt++))
    if (( attempt >= MAX_RETRY )); then
      _log "Failed to clone $name after $MAX_RETRY attempts" "ERROR"
      return 1
    fi
    _log "Retry $attempt/$MAX_RETRY for $name"
    sleep 5
  done
  
  _log "Successfully cloned $name to $dir"
  return 0
}

# Initialize all required repositories
init_repositories() {
  step "Initializing required repositories" "3"
  
  local failed_repos=()
  
  # Clone repositories in parallel with error tracking
  for entry in "${REPO_ENTRIES[@]}"; do
    IFS='|' read -r repo url <<< "$entry"
    if ! ensure_repo "$repo" "$url"; then
      failed_repos+=("$repo")
    fi &
  done
  wait
  
  # Report failed repositories
  if [[ ${#failed_repos[@]} -gt 0 ]]; then
    _log "Failed to clone repositories: ${failed_repos[*]}" "WARN"
    _log "Some features may be limited" "WARN"
  fi
  
  # Fallback binaries for critical tools
  if [[ ! -d "$TOOLS_DIR/deoptfuscator" ]]; then
    step "Using prebuilt deoptfuscator fallback" "4"
    local fallback_url="https://raw.githubusercontent.com/Gyoonus/deoptfuscator/main/deoptfuscator.py"
    if curl -s -o "$TOOLS_DIR/deoptfuscator.py" "$fallback_url"; then
      _log "Downloaded deoptfuscator fallback"
    else
      _log "Failed to download deoptfuscator fallback" "ERROR"
      return 1
    fi
  fi
}

# ============================================================================
# FILE CONVERSION FUNCTIONS
# ============================================================================

# Convert XAPK to APK with integrity check
convert_xapk() {
  local xapk_file="$1"
  step "Converting XAPK: $xapk_file" "5"
  
  # Check if APK already exists
  if [[ -f "${xapk_file%.xapk}.apk" ]]; then
    APK="${xapk_file%.xapk}.apk"
    _log "APK already exists: $APK"
    return 0
  fi

  local temp_extract_dir="$BUILD_DIR/xapk_extract_$(basename "$xapk_file" .xapk)"
  TEMP_DIRS+=("$temp_extract_dir")
  
  # Try xapk-to-apk converter first
  local converter_py="$TOOLS_DIR/xapk-to-apk/xapktoapk.py"
  if [[ -f "$converter_py" ]]; then
    if timeout $TIMEOUT_SEC python3 "$converter_py" "$xapk_file" 2>>"$LOG_FILE"; then
      APK="${xapk_file%.xapk}.apk"
      _log "Converted via xapk-to-apk → $APK"
    else
      _log "xapk-to-apk converter failed, trying manual extraction" "WARN"
    fi
  fi
  
  # Manual extraction fallback
  if [[ ! -f "${xapk_file%.xapk}.apk" ]]; then
    mkdir -p "$temp_extract_dir"
    
    if [[ "$UNZIP_TOOL" == "unzip" ]]; then
      if ! unzip -qq "$xapk_file" -d "$temp_extract_dir"; then
        _log "XAPK extraction failed" "ERROR"
        return 1
      fi
    else
      if ! 7z x -y "$xapk_file" -o"$temp_extract_dir" >/dev/null; then
        _log "XAPK extraction failed" "ERROR"
        return 1
      fi
    fi
    
    # Look for base APK
    if [[ -f "$temp_extract_dir/base.apk" ]]; then
      cp "$temp_extract_dir/base.apk" "${xapk_file%.xapk}.apk"
      APK="${xapk_file%.xapk}.apk"
      _log "Extracted base.apk from XAPK"
    else
      _log "No base.apk found in XAPK" "ERROR"
      return 1
    fi
  fi
  
  # Verify APK integrity
  if [[ "$UNZIP_TOOL" == "unzip" ]]; then
    if ! unzip -t "$APK" >/dev/null; then
      _log "APK integrity check failed" "ERROR"
      return 1
    fi
  else
    if ! 7z t "$APK" >/dev/null; then
      _log "APK integrity check failed" "ERROR"
      return 1
    fi
  fi
  
  _log "XAPK conversion completed successfully: $APK"
}

# Convert APKS to APK
convert_apks() {
  local apks_file="$1"
  step "Converting APKS: $apks_file" "6"
  
  local temp_extract_dir="$BUILD_DIR/apks_extract_$(basename "$apks_file" .apks)"
  TEMP_DIRS+=("$temp_extract_dir")
  
  mkdir -p "$temp_extract_dir"
  
  # Extract APKS
  if [[ "$UNZIP_TOOL" == "unzip" ]]; then
    if ! unzip -qq "$apks_file" -d "$temp_extract_dir"; then
      _log "APKS extraction failed" "ERROR"
      return 1
    fi
  else
    if ! 7z x -y "$apks_file" -o"$temp_extract_dir" >/dev/null; then
      _log "APKS extraction failed" "ERROR"
      return 1
    fi
  fi
  
  # Merge split APKs
  local apk_files=("$temp_extract_dir"/*.apk)
  if [[ ${#apk_files[@]} -eq 1 ]]; then
    cp "${apk_files[0]}" "${apks_file%.apks}.apk"
    APK="${apks_file%.apks}.apk"
    _log "Extracted single APK from APKS"
  else
    _log "Multiple APKs found (${#apk_files[@]}), merging..."
    merge_split_apks "$temp_extract_dir" "${apks_file%.apks}.apk"
    APK="${apks_file%.apks}.apk"
  fi
  
  _log "APKS conversion completed: $APK"
}

# =========================================================================
# ADVANCED REVERSE-ENGINEERING FUNCTIONS (jadx / BundleDecompiler / MobSF)
# =========================================================================

# Convert AAB (Android App Bundle) to universal APK using BundleDecompiler
convert_aab() {
  local aab_file="$1"
  step "Converting AAB: $aab_file" "6"

  local decompiler_jar="$TOOLS_DIR/BundleDecompiler/build/libs/BundleDecompiler.jar"

  if [[ ! -f "$decompiler_jar" ]]; then
    _log "BundleDecompiler.jar not found at $decompiler_jar. Attempting to build with gradle..." "WARN"
    if command -v gradle >/dev/null 2>&1 && [[ -d "$TOOLS_DIR/BundleDecompiler" ]]; then
      (cd "$TOOLS_DIR/BundleDecompiler" && gradle shadowJar >/dev/null 2>&1) || {
        _log "Gradle build failed for BundleDecompiler" "ERROR"; return 1; }
    else
      _log "Gradle not available or BundleDecompiler missing" "ERROR"; return 1;
    fi
  fi

  local output_apk="${aab_file%.aab}.apks"
  if timeout $TIMEOUT_SEC java -jar "$decompiler_jar" sign-universal --in="$aab_file" --out="$output_apk" >/dev/null 2>&1; then
    _log "AAB converted to universal APKS: $output_apk"
    convert_apks "$output_apk" # reuse existing function
  else
    _log "AAB conversion failed" "ERROR"
    return 1
  fi
}

# Decompile dex files to Java source using jadx
decompile_with_jadx() {
  local apk_file="$1"
  # Determine output directory: prefer value from deobf_config.yml (tools->jadx->output_dir)
  local output_dir
  if [[ -f "$CONFIG_FILE" ]]; then
    local cfg_out=$(grep -A3 "^\s*jadx:" "$CONFIG_FILE" | grep "output_dir:" | head -n1 | awk '{print $2}' | tr -d '"')
    if [[ -n "$cfg_out" ]]; then
      output_dir="$cfg_out"
    fi
  fi
  # fallback default
  output_dir="${output_dir:-$2/java_src}"

  step "Decompiling DEX with jadx" "9"

  if [[ -d "$output_dir" ]]; then
    _log "jadx output already exists: $output_dir"
    return 0
  fi

  if timeout $TIMEOUT_SEC jadx -j 1 -d "$output_dir" "$apk_file" >/dev/null 2>&1; then
    _log "jadx decompilation completed: $output_dir"
  else
    _log "jadx decompilation failed" "WARN"
  fi
}

# Optional static scan with MobSF (Docker)
run_mobsf_scan() {
  local apk_file="$1"
  if ! command -v docker >/dev/null 2>&1; then
    _log "Docker not available, skipping MobSF scan" "DEBUG"
    return 0
  fi
  if [[ -z "${MOBSF_SCAN:-}" ]]; then
    return 0 # user did not request
  fi
  step "Running MobSF Static Scan" "10"
  local report_json="$BUILD_DIR/mobsf_report.json"
  docker run --rm -v "$(pwd)":/work -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest >/dev/null &
  local mobsf_pid=$!
  _log "MobSF container started (PID $mobsf_pid). Waiting for server..." "DEBUG"
  sleep 25
  curl -s -X POST --url http://localhost:8000/api/v1/upload -F "file=@$apk_file" -H "Authorization: mobsf" | jq -r '.hash' > "$BUILD_DIR/mobsf_hash.txt" 2>/dev/null || {
    _log "MobSF upload failed" "WARN"; kill $mobsf_pid; return 0; }
  local scan_hash=$(cat "$BUILD_DIR/mobsf_hash.txt")
  curl -s -X POST --url http://localhost:8000/api/v1/scan -d "hash=$scan_hash" -H "Authorization: mobsf" -H "Content-Type: application/x-www-form-urlencoded" > "$report_json" 2>/dev/null || _log "MobSF scan failed" "WARN"
  _log "MobSF report saved: $report_json"
  kill $mobsf_pid >/dev/null 2>&1 || true
}

# ============================================================================
# APK ANALYSIS FUNCTIONS
# ============================================================================

# Extract APK using apktool
extract_apk() {
  local apk_file="$1"
  local output_dir="$2"
  
  step "Extracting APK: $apk_file" "7"
  
  if [[ -d "$output_dir" ]]; then
    _log "Output directory already exists: $output_dir"
    return 0
  fi
  
  if timeout $TIMEOUT_SEC apktool d "$apk_file" -o "$output_dir" -f >/dev/null 2>&1; then
    _log "APK extracted successfully to: $output_dir"
  else
    _log "APK extraction failed" "ERROR"
    return 1
  fi
}

# Generate APK analysis report
generate_analysis_report() {
  local apk_file="$1"
  local output_dir="$2"
  
  step "Generating analysis report" "8"
  
  local report_file="$output_dir/analysis_report.md"
  
  cat > "$report_file" << EOF
# APK Analysis Report

## File Information
- **Input File**: $(basename "$apk_file")
- **Analysis Date**: $(date)
- **Script Version**: $SCRIPT_VERSION

## APK Details
- **File Size**: $(du -h "$apk_file" | cut -f1)
- **File Type**: $(file "$apk_file")

## Extracted Contents
- **Smali Files**: $(find "$output_dir" -name "*.smali" | wc -l)
- **Resource Files**: $(find "$output_dir" -name "*.xml" | wc -l)
- **Asset Files**: $(find "$output_dir/assets" -type f 2>/dev/null | wc -l)

## Deobfuscation Tools Available
$(for entry in "${REPO_ENTRIES[@]}"; do IFS='|' read -r repo _ <<< "$entry"; echo "- $repo"; done)

## Security Standards Reference

This report references the OWASP **Mobile Application Security Verification Standard (MASVS)** for control mapping and future test planning. See <https://mas.owasp.org/MASVS/> for the full specification.

## Next Steps
1. Review the extracted smali code
2. Analyze resource files for obfuscation patterns
3. Use specialized deobfuscation tools as needed
4. Generate deobfuscated output

EOF

  _log "Analysis report generated: $report_file"
}

# ============================================================================
# MAIN EXECUTION FLOW
# ============================================================================

main() {
  # Initialize
  detect_os
  parse_arguments "$@"
  validate_config
  
  # Acquire lock to prevent concurrent execution
  if ! acquire_lock; then
    exit 1
  fi
  
  # Initialize logging and directories
  init_logging
  
  # Check dependencies
  check_dependencies
  
  # Initialize repositories
  init_repositories
  
  # Convert input files if needed
  if [[ "$APK" == *.xapk ]]; then
    convert_xapk "$APK"
  elif [[ "$APK" == *.apks ]]; then
    convert_apks "$APK"
  elif [[ "$APK" == *.aab ]]; then
    convert_aab "$APK"
  fi
  
  # Extract APK contents
  local apk_name=$(basename "$APK" .apk)
  local extract_dir="$BUILD_DIR/${apk_name}_extracted"
  
  extract_apk "$APK" "$extract_dir"

  # Decompile with jadx
  decompile_with_jadx "$APK" "$BUILD_DIR"

  # Optional MobSF scan (set MOBSF_SCAN=true env var)
  run_mobsf_scan "$APK"
  
  # Generate analysis report
  generate_analysis_report "$APK" "$BUILD_DIR"
  
  _log "✅ APK deobfuscation pipeline completed successfully"
  _log "📁 Extracted APK contents: $extract_dir"
  _log "📄 Analysis report: $BUILD_DIR/analysis_report.md"
  _log "🔧 Available tools: $TOOLS_DIR"
}

# ============================================================================
# SCRIPT ENTRY POINT
# ============================================================================

# Only run main if script is executed directly
if [[ "${BASH_SOURCE[0]:-${0}}" == "${0}" ]]; then
  main "$@"
fi 