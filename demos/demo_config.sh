#!/bin/bash
# DakotaCon 2026 — Demo Timing Configuration
# User scrolls manually in Ostendo, so keep delays minimal.

# Timing (seconds)
TYPING_DELAY=0.3      # Pause before command appears (simulates typing)
CMD_DELAY=0.1         # Pause after command before output starts
OUTPUT_DELAY=0.3      # Pause after output before next command
STEP_DELAY=0.5        # Pause between major steps
BANNER_DELAY=0.3      # Pause after banner headers

# Fast mode for rehearsal (halves all delays)
FAST_MODE="${FAST_MODE:-false}"
if [[ "$FAST_MODE" == "true" ]]; then
    TYPING_DELAY=0.15
    CMD_DELAY=0.05
    OUTPUT_DELAY=0.15
    STEP_DELAY=0.25
    BANNER_DELAY=0.15
fi
