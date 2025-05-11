#!/bin/bash
set -eo pipefail

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Initializing runtime environment..."

# Set core paths
export PYTHONPATH="/usr/local/lib/python3.10/dist-packages:/app:${PYTHONPATH:-}"
export LD_LIBRARY_PATH="/app/ns-3-dev/build/lib:/usr/local/lib:${LD_LIBRARY_PATH:-}"

log "PYTHONPATH: $PYTHONPATH"
log "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"

# Verify NS-3 libraries
log "Checking NS-3 libraries..."
if ls /app/ns-3-dev/build/lib/libns3*.so 1>/dev/null 2>&1; then
    log "✅ NS-3 libraries found."
else
    log "❌ Error: NS-3 libraries missing!"
    exit 1
fi

# Refresh linker cache
log "Refreshing dynamic linker cache..."
ldconfig

# Show Python path configuration
log "Verifying Python environment..."
python3 -c "import sys; print('\nPython sys.path:\n' + '\n'.join(sys.path))"

log "✅ Environment ready. Executing command: $*"
exec "$@"
