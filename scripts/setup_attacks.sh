#!/bin/bash

# VANET Attack Configuration Script
# Usage: ./scripts/setup_attacks.sh <scenario> [parameters]

# Default values
SCENARIO="none"
OUTPUT_DIR="output/attack_configs"
NUM_FAKE_NODES=3
DROP_RATE=0.8
JAMMING_POWER=20  # dBm

# Create output directory
mkdir -p "$OUTPUT_DIR"

case "$1" in
    sybil)
        SCENARIO="sybil"
        [[ -n "$2" ]] && NUM_FAKE_NODES=$2
        cat > "$OUTPUT_DIR/sybil_attack.json" <<EOF
{
    "attack_type": "sybil",
    "parameters": {
        "num_fake_nodes": $NUM_FAKE_NODES,
        "target_vehicle": "random",
        "start_time": 300
    },
    "description": "Sybil attack creating $NUM_FAKE_NODES fake vehicle identities"
}
EOF
        echo "Configured Sybil attack with $NUM_FAKE_NODES fake nodes"
        ;;
    
    blackhole)
        SCENARIO="blackhole"
        [[ -n "$2" ]] && DROP_RATE=$2
        cat > "$OUTPUT_DIR/blackhole_attack.json" <<EOF
{
    "attack_type": "blackhole",
    "parameters": {
        "drop_rate": $DROP_RATE,
        "target_vehicle": "random",
        "start_time": 300,
        "duration": 60
    },
    "description": "Blackhole attack dropping ${DROP_RATE}% of packets"
}
EOF
        echo "Configured Blackhole attack with ${DROP_RATE} drop rate"
        ;;
    
    dos)
        SCENARIO="dos"
        [[ -n "$2" ]] && JAMMING_POWER=$2
        cat > "$OUTPUT_DIR/dos_attack.json" <<EOF
{
    "attack_type": "dos",
    "parameters": {
        "jamming_power": $JAMMING_POWER,
        "target_channel": "CCH",
        "start_time": 300,
        "duration": 120
    },
    "description": "DoS attack with ${JAMMING_POWER}dBm jamming power"
}
EOF
        echo "Configured DoS attack with ${JAMMING_POWER}dBm power"
        ;;
    
    mixed)
        SCENARIO="mixed"
        ./scripts/setup_attacks.sh sybil 3
        ./scripts/setup_attacks.sh blackhole 0.6
        ./scripts/setup_attacks.sh dos 25
        echo "Configured mixed attack scenario"
        ;;
    
    none|"")
        cat > "$OUTPUT_DIR/no_attack.json" <<EOF
{
    "attack_type": "none",
    "parameters": {},
    "description": "Baseline scenario with no attacks"
}
EOF
        echo "Configured baseline scenario with no attacks"
        ;;
    
    *)
        echo "Usage: $0 <attack_type> [parameters]"
        echo "Available attack types:"
        echo "  sybil [num_nodes] - Sybil attack (default: 3 fake nodes)"
        echo "  blackhole [drop_rate] - Blackhole attack (default: 0.8)"
        echo "  dos [jamming_power] - DoS attack (default: 20dBm)"
        echo "  mixed - Combination of all attacks"
        echo "  none - Baseline scenario (default)"
        exit 1
        ;;
esac

# Generate Python config file for simulation
cat > "$OUTPUT_DIR/attack_config.py" <<EOF
# Auto-generated attack configuration
ATTACK_CONFIG = {
    "scenario": "$SCENARIO",
    "config_files": [
$(ls -1 "$OUTPUT_DIR"/*.json | sed "s/^/        '/" | sed "s/$/',/")
    ]
}
EOF

echo "Attack configuration saved to $OUTPUT_DIR/"
