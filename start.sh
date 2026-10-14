#!/usr/bin/env bash
# start.sh — AgentShield V3 startup script for Unix/macOS/Linux
# Usage:
#   ./start.sh                  # Start backend only
#   ./start.sh --dashboard      # Start backend + dashboard
#   ./start.sh --all            # Start infra (docker) + backend + dashboard
#   ./start.sh --infra-only     # Start docker services only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BACKEND_PORT="${BACKEND_PORT:-8000}"
DASHBOARD_PORT="${DASHBOARD_PORT:-8501}"
START_DASHBOARD=false
START_ALL=false

for arg in "$@"; do
    case $arg in
        --dashboard) START_DASHBOARD=true ;;
        --all)       START_ALL=true; START_DASHBOARD=true ;;
        --infra-only)
            echo "Starting infrastructure only..."
            docker compose up -d postgres redis
            echo "Infrastructure started."
            exit 0
            ;;
    esac
done

# ── Banner ─────────────────────────────────────────────────────────────────
echo ""
echo "  AgentShield V3 — Adaptive Zero-Trust Action Security"
echo "  Don't just detect — mathematically guarantee the boundary."
echo ""

# ── Check prerequisites ────────────────────────────────────────────────────
echo "[1/6] Checking prerequisites..."
if [ -f ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
    PIP=".venv/bin/pip"
else
    PYTHON="python3"
    PIP="pip3"
fi

# Check packages
for pkg in fastapi uvicorn sqlalchemy redis streamlit typer; do
    if ! $PYTHON -c "import $pkg" 2>/dev/null; then
        echo "  Installing missing packages from requirements.txt..."
        $PIP install -r requirements.txt --quiet
        break
    fi
done
echo "  Prerequisites OK"

# ── Check .env ─────────────────────────────────────────────────────────────
echo "[2/6] Checking configuration..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "  .env created from .env.example."
    echo "  IMPORTANT: Edit .env and set ADMIN_SECRET_TOKEN and Ed25519 keys."
fi

if ! grep -q "AGENTSHIELD_SIGNING_KEY_PEM=-----" .env 2>/dev/null; then
    echo "  WARNING: AGENTSHIELD_SIGNING_KEY_PEM not set. Ephemeral keys will be used."
fi
echo "  Configuration OK"

# ── Start infrastructure ────────────────────────────────────────────────────
if $START_ALL; then
    echo "[3/6] Starting infrastructure (Docker)..."
    if command -v docker &>/dev/null; then
        docker compose up -d postgres redis
        echo "  Waiting 5s for services to become healthy..."
        sleep 5
        echo "  Infrastructure started"
    else
        echo "  Docker not found — skipping. Ensure postgres and redis are running."
    fi
else
    echo "[3/6] Skipping infrastructure start (pass --all to start Docker services)"
fi

# ── Run migrations ──────────────────────────────────────────────────────────
echo "[4/6] Running database migrations..."
if $PYTHON -m alembic upgrade head 2>&1 | tail -3; then
    echo "  Migrations OK"
else
    echo "  WARNING: Migration failed. Database may be unavailable."
fi

# ── Start backend ──────────────────────────────────────────────────────────
echo "[5/6] Starting AgentShield backend on port ${BACKEND_PORT}..."
$PYTHON -m uvicorn backend.main:app \
    --host 0.0.0.0 \
    --port "${BACKEND_PORT}" \
    --reload \
    --log-level info &
BACKEND_PID=$!
sleep 2
echo "  Backend started (PID: ${BACKEND_PID})"
echo "  API docs: http://localhost:${BACKEND_PORT}/docs"

# ── Start dashboard ────────────────────────────────────────────────────────
DASHBOARD_PID=""
if $START_DASHBOARD; then
    echo "[6/6] Starting Streamlit dashboard on port ${DASHBOARD_PORT}..."
    AGENTSHIELD_API_URL="http://localhost:${BACKEND_PORT}" \
        $PYTHON -m streamlit run dashboard/app.py \
        --server.port "${DASHBOARD_PORT}" \
        --server.headless true \
        --theme.base dark &
    DASHBOARD_PID=$!
    sleep 2
    echo "  Dashboard started (PID: ${DASHBOARD_PID})"
    echo "  Dashboard: http://localhost:${DASHBOARD_PORT}"
else
    echo "[6/6] Dashboard not started (pass --dashboard to start)"
    echo "  To start: .venv/bin/streamlit run dashboard/app.py"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AgentShield V3 is running."
echo ""
echo "  API:      http://localhost:${BACKEND_PORT}"
echo "  API docs: http://localhost:${BACKEND_PORT}/docs"
if $START_DASHBOARD; then
    echo "  Dashboard: http://localhost:${DASHBOARD_PORT}"
fi
echo ""
echo "  CLI: .venv/bin/python -m terminal.agsh --help"
echo "  Stop: Ctrl+C"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Wait and cleanup ───────────────────────────────────────────────────────
trap "echo ''; echo 'Shutting down...'; kill $BACKEND_PID 2>/dev/null; [ -n '$DASHBOARD_PID' ] && kill $DASHBOARD_PID 2>/dev/null; exit 0" SIGINT SIGTERM
wait $BACKEND_PID
