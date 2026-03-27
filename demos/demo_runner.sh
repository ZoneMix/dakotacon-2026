#!/bin/bash
# DakotaCon 2026 — Demo Runner Utility
# Source this file in demo scripts: source "$(dirname "$0")/demo_runner.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/demo_config.sh"

# ANSI color codes
C_RESET='\033[0m'
C_BOLD='\033[1m'
C_DIM='\033[2m'
C_RED='\033[31m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_BLUE='\033[34m'
C_MAGENTA='\033[35m'
C_CYAN='\033[36m'
C_GRAY='\033[90m'
C_WHITE='\033[97m'

# Current prompt (scripts override this)
PROMPT="\$"
PROMPT_COLOR="$C_GREEN"
PROFILE="default"
REGION="us-east-2"

# Detect demo mode
DEMO_MODE="sim"
[[ -f "$SCRIPT_DIR/.demo_mode" ]] && DEMO_MODE=$(cat "$SCRIPT_DIR/.demo_mode" | tr -d '[:space:]')

is_live() { [[ "$DEMO_MODE" == "live" ]]; }

# ── Output Helpers ──

# Horizontal rule — thin gray line for visual separation
hr() {
    printf "${C_GRAY}────────────────────────────────────────${C_RESET}\n"
}

# Step header — numbered step with description
step() {
    local num="$1"
    local desc="$2"
    echo ""
    printf "${C_BOLD}${C_WHITE}Step ${num}: ${desc}${C_RESET}\n"
    hr
}

# Display a command with prompt (simulates typing)
type_cmd() {
    local cmd="$1"
    sleep "$TYPING_DELAY"
    printf "${PROMPT_COLOR}${PROMPT}${C_RESET} ${C_BOLD}${C_CYAN}${cmd}${C_RESET}\n"
    sleep "$CMD_DELAY"
}

# Run a command and show its output
run_cmd() {
    local cmd="$1"
    type_cmd "$cmd"
    eval "$cmd" 2>&1
    sleep "$OUTPUT_DELAY"
}

# Show a command with canned output (sim mode)
show_cmd() {
    local cmd="$1"
    local output="$2"
    type_cmd "$cmd"
    if [[ -n "$output" ]]; then
        echo "$output"
    fi
    sleep "$OUTPUT_DELAY"
}

# Commentary line (yellow, concise)
narrate() {
    printf "${C_YELLOW}${1}${C_RESET}\n"
    sleep 0.2
}

# Alert/finding (red, bold)
alert() {
    printf "${C_BOLD}${C_RED}[!] ${1}${C_RESET}\n"
}

# Success (green, bold)
success() {
    printf "${C_BOLD}${C_GREEN}[+] ${1}${C_RESET}\n"
}

# Info (blue)
info() {
    printf "${C_BLUE}[*] ${1}${C_RESET}\n"
}

# Key-value output line (label in gray, value in white)
kv() {
    local label="$1"
    local value="$2"
    printf "  ${C_GRAY}%-12s${C_RESET} ${C_WHITE}%s${C_RESET}\n" "${label}:" "$value"
}

# Section banner (magenta, compact)
banner() {
    local text="$1"
    local width=${#text}
    local border=$(printf '=%.0s' $(seq 1 $((width + 4))))
    echo ""
    printf "${C_BOLD}${C_MAGENTA}${border}${C_RESET}\n"
    printf "${C_BOLD}${C_MAGENTA}  ${text}${C_RESET}\n"
    printf "${C_BOLD}${C_MAGENTA}${border}${C_RESET}\n"
    sleep "$BANNER_DELAY"
}

# Pause for audience to read
pause() {
    sleep "${1:-$STEP_DELAY}"
}

# Set the prompt (with color)
set_prompt() {
    PROMPT="$1"
}

# Set prompt color
set_prompt_color() {
    PROMPT_COLOR="$1"
}
