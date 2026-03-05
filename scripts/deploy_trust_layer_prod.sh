#!/usr/bin/env bash
# deploy_trust_layer_prod.sh — Deploy Trust Layer to production with gates + rollback + release
#
# Usage: ./scripts/deploy_trust_layer_prod.sh [--minor|--major] [--force] [--skip-smoke]
#
# Flags:
#   --force        Bypass CI GitHub check
#   --skip-smoke   Skip post-deploy smoke test (use for emergency hotfixes)
#   --minor        Bump minor version (1.0.x → 1.1.0)
#   --major        Bump major version (1.x.x → 2.0.0)
#   (default)      Bump patch (1.0.2 → 1.0.3)

set -euo pipefail

# --- Configuration ---
REPO_DIR="/opt/claude-ceo/workspace/arkforge-trust-layer"
SERVICE="arkforge-trust-layer"
HEALTH_URL="https://arkforge.fr/trust/v1/health"
PROOF_SPEC_DIR="/opt/claude-ceo/workspace/proof-spec"
AGENT_CLIENT_DIR="/opt/claude-ceo/workspace/agent-client"
SETTINGS_ENV="/opt/claude-ceo/config/settings.env"
LOG_FILE="/opt/claude-ceo/logs/deploy_trust_layer.log"
OVH_HOST="ubuntu@51.91.99.178"
OVH_REPO="/opt/claude-ceo/workspace/arkforge-trust-layer"
SMOKE_TEST_SCRIPT="$REPO_DIR/scripts/smoke_test_prod.py"

# --- Args ---
VERSION_BUMP="patch"
FORCE_CI=false
SKIP_SMOKE=false
for arg in "$@"; do
    case "$arg" in
        --minor)      VERSION_BUMP="minor" ;;
        --major)      VERSION_BUMP="major" ;;
        --force)      FORCE_CI=true ;;
        --skip-smoke) SKIP_SMOKE=true ;;
    esac
done

# --- Logging ---
mkdir -p "$(dirname "$LOG_FILE")"
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG_FILE"; }
fail() { log "ERROR: $*"; telegram_notify "Deploy FAILED: $*"; exit 1; }

# --- Telegram notification ---
telegram_notify() {
    local msg="[Trust Layer Deploy] $1"
    local token="" chat_ids=""
    # Load from vault via Python
    if token=$(python3 -c "
import sys; sys.path.insert(0, '/opt/claude-ceo')
from automation.vault import vault
t = vault.get_section('telegram') or {}
print(t.get('bot_token', ''))
" 2>/dev/null) && [ -n "$token" ]; then
        chat_ids=$(python3 -c "
import sys; sys.path.insert(0, '/opt/claude-ceo')
from automation.vault import vault
t = vault.get_section('telegram') or {}
print(t.get('chat_ids', ''))
" 2>/dev/null)
    fi
    if [ -z "$token" ] || [ -z "$chat_ids" ]; then
        log "WARN: Telegram not configured, skipping notification"
        return 0
    fi
    for chat_id in $(echo "$chat_ids" | tr ',' ' '); do
        curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
            -d "chat_id=${chat_id}&text=${msg}&parse_mode=Markdown" > /dev/null 2>&1 || true
    done
}

# --- Version bump helper ---
bump_version() {
    local current="$1" bump="$2"
    local major minor patch
    major=$(echo "$current" | cut -d. -f1 | tr -d 'v')
    minor=$(echo "$current" | cut -d. -f2)
    patch=$(echo "$current" | cut -d. -f3)
    case "$bump" in
        major) echo "v$((major + 1)).0.0" ;;
        minor) echo "v${major}.$((minor + 1)).0" ;;
        patch) echo "v${major}.${minor}.$((patch + 1))" ;;
    esac
}

# --- Ensure we're on main and up to date ---
cd "$REPO_DIR"
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "main" ]; then
    fail "Not on main branch (current: $CURRENT_BRANCH). Switch to main before deploying."
fi

log "=== Trust Layer Deploy — $(date -u) ==="
log "Branch: main | Version bump: $VERSION_BUMP | Force CI: $FORCE_CI | Skip smoke: $SKIP_SMOKE"

# ============================================================
# PHASE 1 — GATES LOCALES
# ============================================================
log "--- Phase 1: Gates ---"

# Gate 1 — CI GitHub
if [ "$FORCE_CI" = false ]; then
    log "Gate 1/4: CI GitHub on main..."
    CI_STATUS=$(gh run list --repo ark-forge/trust-layer --branch main --limit 1 --json conclusion --jq '.[0].conclusion' 2>/dev/null || echo "unknown")
    if [ "$CI_STATUS" != "success" ]; then
        fail "CI gate FAILED — last run: '$CI_STATUS'. Use --force to bypass."
    fi
    log "Gate 1/4: CI OK (last run: success)"
else
    log "Gate 1/4: CI bypassed (--force)"
fi

# Gate 2 — proof-spec check_consistency
log "Gate 2/4: proof-spec check_consistency.py..."
if [ ! -f "$PROOF_SPEC_DIR/check_consistency.py" ]; then
    fail "proof-spec not found at $PROOF_SPEC_DIR"
fi
if ! python3 "$PROOF_SPEC_DIR/check_consistency.py" >> "$LOG_FILE" 2>&1; then
    fail "proof-spec check_consistency.py FAILED"
fi
log "Gate 2/4: proof-spec OK"

# Gate 3 — agent-client tests
log "Gate 3/4: agent-client pytest..."
if [ ! -d "$AGENT_CLIENT_DIR/tests" ]; then
    fail "agent-client not found at $AGENT_CLIENT_DIR"
fi
if ! python3 -m pytest "$AGENT_CLIENT_DIR/tests/" -q --tb=short >> "$LOG_FILE" 2>&1; then
    fail "agent-client tests FAILED"
fi
log "Gate 3/4: agent-client tests OK"

# Gate 4 — Trust Layer tests
log "Gate 4/4: trust-layer pytest..."
if ! python3 -m pytest tests/ -q --tb=short >> "$LOG_FILE" 2>&1; then
    fail "trust-layer tests FAILED"
fi
log "Gate 4/4: trust-layer tests OK"

log "All gates PASSED"

# ============================================================
# PHASE 2 — DEPLOY
# ============================================================
log "--- Phase 2: Deploy ---"

# Save current commit for rollback
PREV_COMMIT=$(git rev-parse HEAD)
log "Previous commit: $PREV_COMMIT"

# Pull latest
log "git pull origin main..."
git pull origin main >> "$LOG_FILE" 2>&1

NEW_COMMIT=$(git rev-parse HEAD)
if [ "$NEW_COMMIT" = "$PREV_COMMIT" ]; then
    log "No new commits to deploy. Exiting."
    exit 0
fi
log "New commit: $NEW_COMMIT"

# Restart local failover service
log "Restarting local $SERVICE (failover)..."
sudo systemctl restart "$SERVICE"

# Deploy to OVH primary (nginx routes to OVH — must update it too)
log "Deploying to OVH primary ($OVH_HOST)..."
if ssh -o ConnectTimeout=10 "$OVH_HOST" \
    "GIT_DIR=${OVH_REPO}/.git GIT_WORK_TREE=${OVH_REPO} git pull origin main 2>&1 && \
     sudo systemctl restart arkforge-trust-layer 2>&1" >> "$LOG_FILE" 2>&1; then
    log "OVH deploy OK"
else
    log "WARN: OVH deploy failed — rolling back local, aborting"
    git checkout "$PREV_COMMIT" >> "$LOG_FILE" 2>&1
    sudo systemctl restart "$SERVICE"
    fail "OVH deploy FAILED — rolled back local to $PREV_COMMIT"
fi

# Health check via nginx (validates full stack: nginx → OVH primary, 6 × 5s = 30s)
log "Health check: $HEALTH_URL (6 attempts × 5s)..."
HEALTHY=false
for i in $(seq 1 6); do
    sleep 5
    STATUS=$(curl -s --max-time 5 "$HEALTH_URL" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    e = d.get('environment', 'production')
    s = d.get('status', '')
    print(f\"{s}:{e}\")
except Exception as ex:
    print(f'error:{ex}')
" 2>/dev/null || echo "error:timeout")
    SVC_STATUS=$(echo "$STATUS" | cut -d: -f1)
    SVC_ENV=$(echo "$STATUS" | cut -d: -f2)
    log "Attempt $i/6: status=$SVC_STATUS environment=$SVC_ENV"
    if [ "$SVC_STATUS" = "ok" ] && [ "$SVC_ENV" = "production" ]; then
        HEALTHY=true
        break
    fi
done

if [ "$HEALTHY" = false ]; then
    log "Health check FAILED — rolling back local to $PREV_COMMIT"
    git reset --hard "$PREV_COMMIT" >> "$LOG_FILE" 2>&1
    sudo systemctl restart "$SERVICE"
    # Tenter rollback OVH aussi
    ssh -o ConnectTimeout=10 "$OVH_HOST" \
        "cd ${OVH_REPO} && git reset --hard $PREV_COMMIT && sudo systemctl restart arkforge-trust-layer" \
        >> "$LOG_FILE" 2>&1 || log "WARN: Rollback OVH non confirmé"
    fail "Health check FAILED — rolled back to $PREV_COMMIT"
fi

log "Service healthy after deploy"

# ============================================================
# PHASE 2.5 — SMOKE TEST
# ============================================================
if [ "$SKIP_SMOKE" = true ]; then
    log "--- Phase 2.5: Smoke test SKIPPED (--skip-smoke) ---"
else
    log "--- Phase 2.5: Smoke test ---"
    if [ ! -f "$SMOKE_TEST_SCRIPT" ]; then
        log "WARN: Smoke test script not found at $SMOKE_TEST_SCRIPT — skipping"
    else
        SMOKE_LOG="$LOG_FILE.smoke"
        SMOKE_BASE_URL="${HEALTH_URL%/v1/health}"  # strip /v1/health → https://arkforge.fr/trust
        if python3 "$SMOKE_TEST_SCRIPT" \
               --base-url "$SMOKE_BASE_URL" \
               --ovh-host "$OVH_HOST" \
               2>&1 | tee -a "$SMOKE_LOG" | tail -6; then
            log "Phase 2.5: Smoke test PASSED"
            SMOKE_RESULT="PASSED"
        else
            SMOKE_EXIT=${PIPESTATUS[0]}
            log "Phase 2.5: Smoke test FAILED (exit $SMOKE_EXIT)"
            SMOKE_RESULT="FAILED"

            # Rollback local (reset sur le commit précédent, reste sur main)
            log "Rollback local: git reset --hard $PREV_COMMIT"
            git reset --hard "$PREV_COMMIT" >> "$LOG_FILE" 2>&1
            sudo systemctl restart "$SERVICE"

            # Rollback OVH (reset + restart, vérification explicite)
            log "Rollback OVH: git reset --hard $PREV_COMMIT"
            if ssh -o ConnectTimeout=10 "$OVH_HOST" \
                "cd ${OVH_REPO} && \
                 git reset --hard $PREV_COMMIT >> /tmp/rollback.log 2>&1 && \
                 sudo systemctl restart arkforge-trust-layer >> /tmp/rollback.log 2>&1" \
                >> "$LOG_FILE" 2>&1; then
                log "Rollback OVH OK"
            else
                log "CRITICAL: Rollback OVH FAILED — serveur OVH peut être dans un état incohérent"
                telegram_notify "CRITICAL: rollback OVH FAILED après smoke test — intervention manuelle requise"
            fi

            # Vérification post-rollback (2 × 5s)
            ROLLBACK_OK=false
            for i in 1 2; do
                sleep 5
                RB_STATUS=$(curl -s --max-time 5 "$HEALTH_URL" | python3 -c "
import sys, json
try: print(json.load(sys.stdin).get('status',''))
except: print('error')
" 2>/dev/null || echo "error")
                if [ "$RB_STATUS" = "ok" ]; then ROLLBACK_OK=true; break; fi
            done
            if [ "$ROLLBACK_OK" = true ]; then
                log "Service opérationnel après rollback"
            else
                log "WARN: Service ne répond pas après rollback — vérification manuelle requise"
            fi

            fail "Smoke test FAILED — rolled back both servers to $PREV_COMMIT"
        fi
    fi
fi

# ============================================================
# PHASE 3 — RELEASE
# ============================================================
log "--- Phase 3: Release ---"

LAST_TAG=$(git tag --sort=-v:refname | head -1)
if [ -z "$LAST_TAG" ]; then
    LAST_TAG="v0.0.0"
fi
NEW_TAG=$(bump_version "$LAST_TAG" "$VERSION_BUMP")
log "Version: $LAST_TAG → $NEW_TAG"

# Build changelog (commits since last tag)
CHANGELOG=$(git log "${LAST_TAG}..HEAD" --oneline --no-merges 2>/dev/null | head -20 | sed 's/^/• /' || echo "• No changelog available")

git tag "$NEW_TAG"
git push origin "$NEW_TAG" >> "$LOG_FILE" 2>&1
log "Tag $NEW_TAG pushed"

# ============================================================
# PHASE 4 — NOTIFICATION
# ============================================================
SMOKE_STATUS_MSG=""
if [ "$SKIP_SMOKE" = true ]; then
    SMOKE_STATUS_MSG=" | smoke: skipped"
elif [ "${SMOKE_RESULT:-}" = "PASSED" ]; then
    SMOKE_STATUS_MSG=" | smoke: ✓"
fi
NOTIFY_MSG="Deploy $LAST_TAG → $NEW_TAG OK${SMOKE_STATUS_MSG}\n\n${CHANGELOG}"
telegram_notify "$NOTIFY_MSG"
log "Telegram notification sent"

log "=== Deploy $NEW_TAG COMPLETE ==="
echo ""
echo "  Trust Layer $NEW_TAG deployed successfully"
echo "  Health: $HEALTH_URL"
echo "  Changelog since $LAST_TAG:"
echo "$CHANGELOG"
