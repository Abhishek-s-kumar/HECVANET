#!/bin/bash

# VANET Simulation Runner
# Usage: ./run_simulation.sh [options]

# Default values
SCENARIO="default"
VISUALIZATION=false
METRICS_DIR="output/metrics"
CONFIG_DIR="config"
SUMO_CONFIG="$CONFIG_DIR/sumo/map.sumocfg"
ATTACK_CONFIG="none"
DURATION=300  # Simulation time in seconds

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--scenario)
            SCENARIO="$2"
            shift 2
            ;;
        -v|--visualization)
            VISUALIZATION=true
            shift
            ;;
        -a|--attack)
            ATTACK_CONFIG="$2"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Create output directories
mkdir -p "$METRICS_DIR"
mkdir -p logs

# Configure attacks if specified
if [ "$ATTACK_CONFIG" != "none" ]; then
    echo "Configuring attack scenario: $ATTACK_CONFIG"
    ./scripts/setup_attacks.sh "$ATTACK_CONFIG"
fi

# Start Xvfb if visualization is enabled
if [ "$VISUALIZATION" = true ]; then
    echo "Starting virtual display for visualization..."
    Xvfb :99 -screen 0 1920x1080x24 > /dev/null 2>&1 &
    export DISPLAY=:99
    SUMO_CONFIG="$CONFIG_DIR/sumo/map_gui.sumocfg"
fi

# Start SUMO simulation
echo "Launching SUMO with config: $SUMO_CONFIG"
sumo -c "$SUMO_CONFIG" --remote-port 8813 > logs/sumo.log 2>&1 &

# Run NS-3 simulation with parameters
echo "Starting VANET simulation (Duration: ${DURATION}s, Scenario: ${SCENARIO})"
python3 simulation.py \
    --duration "$DURATION" \
    --scenario "$SCENARIO" \
    --attack-config "$ATTACK_CONFIG" \
    > logs/simulation.log 2>&1

# Clean up
pkill -f sumo
pkill -f Xvfb

echo "Simulation completed. Results saved to $METRICS_DIR/"
echo "Logs available in logs/ directory"

# Generate summary report
python3 metrics/generate_report.py --input "$METRICS_DIR" --output "output/report.html"
