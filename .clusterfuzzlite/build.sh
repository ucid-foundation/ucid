# Copyright 2026 UCID Foundation
#
# Licensed under the EUPL, Version 1.2 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# =============================================================================
# ClusterFuzzLite Build Script for UCID
# =============================================================================
#
# Description:
#     This script builds fuzz targets for the UCID library using the
#     ClusterFuzzLite infrastructure. It compiles Python fuzz targets
#     with coverage instrumentation for effective fuzzing.
#
# Usage:
#     ./build.sh
#
# Environment Variables:
#     SRC         Source directory (set by OSS-Fuzz)
#     OUT         Output directory for compiled fuzzers (set by OSS-Fuzz)
#     WORK        Working directory (set by OSS-Fuzz)
#
# Fuzz Targets:
#     - fuzz_parser     : Tests UCID string parsing
#     - fuzz_validator  : Tests UCID validation
#     - fuzz_creator    : Tests UCID creation
#     - fuzz_h3         : Tests H3 spatial operations
#
# Reference:
#     https://google.github.io/clusterfuzzlite/
#     https://google.github.io/oss-fuzz/getting-started/new-project-guide/python-lang/
#
# =============================================================================

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Fuzz targets to build
readonly FUZZ_TARGETS=(
    "fuzz_parser"
    "fuzz_validator"
    "fuzz_creator"
    "fuzz_h3"
)

# =============================================================================
# Logging Functions
# =============================================================================

log_info() {
    echo "[INFO] $*"
}

log_error() {
    echo "[ERROR] $*" >&2
}

log_section() {
    echo ""
    echo "============================================================================="
    echo "$*"
    echo "============================================================================="
}

# =============================================================================
# Validation Functions
# =============================================================================

validate_environment() {
    log_section "Validating Build Environment"

    # Check required environment variables
    if [[ -z "${SRC:-}" ]]; then
        log_error "SRC environment variable not set"
        exit 1
    fi

    if [[ -z "${OUT:-}" ]]; then
        log_error "OUT environment variable not set"
        exit 1
    fi

    log_info "SRC directory: $SRC"
    log_info "OUT directory: $OUT"
    log_info "Environment validation complete"
}

# =============================================================================
# Installation Functions
# =============================================================================

install_dependencies() {
    log_section "Installing Dependencies"

    # Upgrade pip
    log_info "Upgrading pip..."
    pip3 install --upgrade pip setuptools wheel

    # Install UCID library
    log_info "Installing UCID library..."
    if [[ -d "$SRC/ucid" ]]; then
        pip3 install -e "$SRC/ucid[all]"
    else
        log_error "UCID source directory not found at $SRC/ucid"
        exit 1
    fi

    # Install fuzzing dependencies
    log_info "Installing atheris fuzzing library..."
    pip3 install atheris

    log_info "Dependencies installed successfully"
}

# =============================================================================
# Build Functions
# =============================================================================

compile_fuzz_targets() {
    log_section "Compiling Fuzz Targets"

    local target_count=0
    local success_count=0

    for target in "${FUZZ_TARGETS[@]}"; do
        target_count=$((target_count + 1))
        local target_file="$SRC/${target}.py"

        if [[ -f "$target_file" ]]; then
            log_info "Compiling: $target"

            if compile_python_fuzzer "$target_file"; then
                success_count=$((success_count + 1))
                log_info "Successfully compiled: $target"
            else
                log_error "Failed to compile: $target"
            fi
        else
            log_error "Target file not found: $target_file"
        fi
    done

    log_info "Compiled $success_count of $target_count fuzz targets"

    if [[ $success_count -eq 0 ]]; then
        log_error "No fuzz targets were compiled successfully"
        exit 1
    fi
}

# =============================================================================
# Corpus and Dictionary Functions
# =============================================================================

setup_seed_corpus() {
    log_section "Setting Up Seed Corpus"

    local corpus_dir="$SRC/ucid/.clusterfuzzlite/corpus"

    if [[ -d "$corpus_dir" ]]; then
        for target in "${FUZZ_TARGETS[@]}"; do
            local target_corpus="$corpus_dir/$target"

            if [[ -d "$target_corpus" ]]; then
                local out_corpus="$OUT/${target}_seed_corpus"
                mkdir -p "$out_corpus"
                cp -r "$target_corpus"/* "$out_corpus/" 2>/dev/null || true
                log_info "Copied seed corpus for: $target"
            fi
        done
    else
        log_info "No seed corpus directory found (optional)"
    fi
}

setup_dictionaries() {
    log_section "Setting Up Fuzzing Dictionaries"

    local dict_dir="$SRC/ucid/.clusterfuzzlite/dictionaries"

    if [[ -d "$dict_dir" ]]; then
        cp "$dict_dir"/*.dict "$OUT/" 2>/dev/null || true
        log_info "Copied fuzzing dictionaries"
    else
        log_info "No dictionaries directory found (optional)"
    fi

    # Create default UCID dictionary if none exists
    create_default_dictionary
}

create_default_dictionary() {
    local dict_file="$OUT/ucid.dict"

    if [[ ! -f "$dict_file" ]]; then
        log_info "Creating default UCID dictionary"

        cat > "$dict_file" << 'EOF'
# UCID Fuzzing Dictionary
# Common tokens and patterns for UCID string fuzzing

# Protocol prefix
"UCID-V1"
"UCID-V"

# Separators
":"

# Valid city codes
"IST"
"BER"
"LON"
"NEW"
"PAR"
"SYD"
"TOK"

# Context types
"15MIN"
"TRANSIT"
"WALK"
"NONE"
"CLIMATE"
"EQUITY"

# Grades
"A"
"B"
"C"
"D"
"F"

# Timestamp components
"W"
"T"
"2026"
"2025"

# Numeric patterns
"0.00"
"0.50"
"1.00"
"+41.015"
"+28.979"
"-90.0"
"+90.0"
"-180.0"
"+180.0"

# H3 patterns
"891f2ed6df7ffff"
"8"
"f"
EOF
        log_info "Default dictionary created at: $dict_file"
    fi
}

# =============================================================================
# Main Function
# =============================================================================

main() {
    log_section "UCID ClusterFuzzLite Build"
    log_info "Script: $SCRIPT_NAME"
    log_info "Directory: $SCRIPT_DIR"
    log_info "Started at: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

    # Run build steps
    validate_environment
    install_dependencies
    compile_fuzz_targets
    setup_seed_corpus
    setup_dictionaries

    log_section "Build Complete"
    log_info "Fuzz targets available in: $OUT"
    log_info "Finished at: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
}

# =============================================================================
# Entry Point
# =============================================================================

main "$@"
