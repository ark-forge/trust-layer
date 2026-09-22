#!/usr/bin/env bash
# deploy_trust_layer_prod.sh — Deploy Trust Layer to production with gates + staged rollout + rollback
#
# Usage: ./scripts/deploy_trust_layer_prod.sh [--force] [--skip-smoke]
#
# Flags:
#   --force        Bypass CI GitHub check
#   --skip-smoke   Skip post-deploy smoke test (use for emergency hotfixes)
#
# The version is decided in the PR, never here: bump trust_layer/__init__.py and add the
# "## [x.y.z]" entry to CHANGELOG.md before merging. This script pushes nothing to main
# (main requires the CI check; a push from here would bypass it). It only pushes the tag.
#
# Topology (checked at start from /var/lib/arkforge/failover_state.json on both nodes):
#   PRIMARY  = this host (VPS1). Serves trust.arkforge.tech directly (nginx → 127.0.0.1:8100),
#              no HA upstream: its restart is a short outage, nothing falls back.
#   STANDBY  = VPS2 (OVH). Writes blocked, no traffic.
#
# Staged rollout:
#   Phase 2a — Deploy to STANDBY first, canary on it (no traffic at risk)
#   Phase 2b — Deploy to PRIMARY, health check direct then through the public URL
#   Phase 2.5 — Full smoke test against production

set -euo pipefail

# --- Configuration ---
REPO_DIR="/opt/claude-ceo/workspace/arkforge-trust-layer"
SERVICE="arkforge-trust-layer"
HEALTH_URL="https://trust.arkforge.tech/v1/health"
LOCAL_URL="http://127.0.0.1:8100"
PROOF_SPEC_DIR="/opt/claude-ceo/workspace/proof-spec"
AGENT_CLIENT_DIR="/opt/claude-ceo/workspace/agent-client"
SETTINGS_ENV="/opt/claude-ceo/config/settings.env"
LOG_FILE="/opt/claude-ceo/logs/deploy_trust_layer.log"
FAILOVER_STATE="/var/lib/arkforge/failover_state.json"
STANDBY_HOST="ubuntu@51.91.99.178"
STANDBY_REPO="/opt/claude-ceo/workspace/arkforge-trust-layer"
SMOKE_TEST_SCRIPT="$REPO_DIR/scripts/smoke_test_prod.py"
SECURITY_TEST_SCRIPT="$REPO_DIR/scripts/security_smoke_test.py"
SSH="ssh -o ConnectTimeout=10"

# --- Dépendances ---
# Rien d'autre n'installe requirements.txt : sans cette commande, une montée de dépendance est taguée
# mais n'atteint jamais la prod (constaté le 21/09 : cryptography 50 « déployé » le 11/09, absent).
# Exécutée dans le dépôt d'un nœud : venv = celui de l'ExecStart effectif (drop-ins compris), puis
# contrôle des épingles, sauté seulement si le commit (rollback) ne porte pas encore le contrôleur.
DEPS_CMD='bin=$(dirname "$(systemctl show -p ExecStart --value '"$SERVICE"' | sed -n "s/.*path=\([^ ;]*\).*/\1/p" | tail -1)") \
  && "$bin/pip" install -q --disable-pip-version-check -r requirements.txt \
  && { [ ! -f scripts/check_requirements_installed.py ] || "$bin/python" scripts/check_requirements_installed.py requirements.txt; }'

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

# --- Args ---
FORCE_CI=false
SKIP_SMOKE=false
for arg in "$@"; do
    case "$arg" in
        --force)      FORCE_CI=true ;;
        --skip-smoke) SKIP_SMOKE=true ;;
        --minor|--major)
            echo "$arg n'existe plus : la version se fixe dans la PR (trust_layer/__init__.py + CHANGELOG.md)." >&2
            exit 2 ;;
        *)
            echo "Argument inconnu : $arg" >&2
            exit 2 ;;
    esac
done

# --- JSON field from stdin ("" if unreadable) ---
json_field() {
    python3 -c "
import sys, json
try: print(json.load(sys.stdin).get('$1', ''))
except Exception: print('')
"
}

# --- Health of a node: "status version role" ---
local_health() { curl -s --max-time 5 "$LOCAL_URL/v1/health" 2>/dev/null || true; }
standby_health() { $SSH "$STANDBY_HOST" "curl -s --max-time 5 $LOCAL_URL/v1/health" 2>/dev/null || true; }
standby_http_code() { $SSH "$STANDBY_HOST" "curl -s -o /dev/null -w '%{http_code}' --max-time 5 $LOCAL_URL$1" 2>/dev/null || echo "000"; }

# --- Rollbacks ---
rollback_local_tree() {
    git reset --hard "$PREV_COMMIT" >> "$LOG_FILE" 2>&1
}
rollback_primary() {
    log "Rollback primary: git reset --hard $PREV_COMMIT"
    rollback_local_tree
    bash -c "$DEPS_CMD" >> "$LOG_FILE" 2>&1 || log "CRITICAL: dépendances du rollback primary non réinstallées"
    sudo -n /usr/local/sbin/arkforge-run relance "$SERVICE"
}
rollback_standby() {
    log "Rollback standby: git reset --hard $STANDBY_PREV_COMMIT"
    if $SSH "$STANDBY_HOST" \
        "cd ${STANDBY_REPO} && git reset --hard $STANDBY_PREV_COMMIT && { $DEPS_CMD; } && sudo -n /usr/local/sbin/arkforge-run relance $SERVICE" \
        >> "$LOG_FILE" 2>&1; then
        log "Rollback standby OK"
    else
        log "CRITICAL: Rollback standby FAILED — intervention manuelle requise"
        telegram_notify "CRITICAL: rollback standby FAILED — intervention manuelle requise"
    fi
}
check_public_after_rollback() {
    local i status
    for i in 1 2; do
        sleep 5
        status=$(curl -s --max-time 5 "$HEALTH_URL" | json_field status 2>/dev/null || echo "error")
        if [ "$status" = "ok" ]; then log "Service opérationnel après rollback"; return 0; fi
    done
    log "WARN: Service ne répond pas après rollback — vérification manuelle requise"
}

# ============================================================
# PHASE 0 — TOPOLOGY + SOURCES
# ============================================================
cd "$REPO_DIR"
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "main" ]; then
    fail "Not on main branch (current: $CURRENT_BRANCH). Switch to main before deploying."
fi

log "=== Trust Layer Deploy — $(date -u) ==="
log "Force CI: $FORCE_CI | Skip smoke: $SKIP_SMOKE"

# Roles are read, never assumed: after a failover the order below would restart the node
# serving traffic first. Refuse rather than guess.
LOCAL_STATE=$(cat "$FAILOVER_STATE" 2>/dev/null || echo "{}")
STANDBY_STATE=$($SSH "$STANDBY_HOST" "cat $FAILOVER_STATE" 2>/dev/null || echo "{}")
LOCAL_ROLE="$(echo "$LOCAL_STATE" | json_field role)/$(echo "$LOCAL_STATE" | json_field writes)"
STANDBY_ROLE="$(echo "$STANDBY_STATE" | json_field role)/$(echo "$STANDBY_STATE" | json_field writes)"
log "Topology: local=$LOCAL_ROLE standby($STANDBY_HOST)=$STANDBY_ROLE"
if [ "$LOCAL_ROLE" != "primary/enabled" ] || [ "$STANDBY_ROLE" != "standby/blocked" ]; then
    fail "Topology unexpected (local=$LOCAL_ROLE, $STANDBY_HOST=$STANDBY_ROLE). This script deploys standby first then the local primary; after a failover it must not run as is."
fi

# Gates must test the code about to be deployed: update every clone they read first.
PREV_COMMIT=$(git rev-parse HEAD)
log "Previous commit (rollback point): $PREV_COMMIT"
git pull --ff-only origin main >> "$LOG_FILE" 2>&1 || fail "git pull --ff-only failed on $REPO_DIR"
for dir in "$PROOF_SPEC_DIR" "$AGENT_CLIENT_DIR"; do
    if ! git -C "$dir" pull --ff-only origin main >> "$LOG_FILE" 2>&1; then
        rollback_local_tree
        fail "git pull --ff-only failed on $dir"
    fi
done
NEW_COMMIT=$(git rev-parse HEAD)
log "Deploy commit: $NEW_COMMIT | proof-spec: $(git -C "$PROOF_SPEC_DIR" rev-parse --short HEAD)"

# The security and smoke gates are checked HERE, before anything is deployed: a missing script used to
# produce a WARN in Phase 2.5 and let the deploy through ungated. Checked after the pull, because the gates
# must be those of the commit about to be deployed. Skipping stays possible, but only on purpose (--skip-smoke).
if [ "$SKIP_SMOKE" = false ]; then
    for gate in "$SECURITY_TEST_SCRIPT" "$SMOKE_TEST_SCRIPT"; do
        if [ ! -f "$gate" ]; then
            rollback_local_tree
            fail "Gate script missing at $NEW_COMMIT: $gate — refusing to deploy ungated (use --skip-smoke to decide otherwise)"
        fi
    done
fi

STANDBY_PREV_COMMIT=$($SSH "$STANDBY_HOST" "git -C ${STANDBY_REPO} rev-parse HEAD" 2>/dev/null || echo "unknown")
log "Standby commit: $STANDBY_PREV_COMMIT"
if [ "$NEW_COMMIT" = "$PREV_COMMIT" ] && [ "$STANDBY_PREV_COMMIT" = "$NEW_COMMIT" ]; then
    log "Rien à déployer — primary et standby sont déjà sur $NEW_COMMIT. Exiting."
    exit 0
fi
if [ "$STANDBY_PREV_COMMIT" = "unknown" ]; then
    rollback_local_tree
    fail "Cannot read standby commit on $STANDBY_HOST — no rollback point, refusing to deploy"
fi

# --- Version: decided in the PR ---
NEW_VERSION=$(grep -oP '(?<=__version__ = ")[^"]+' trust_layer/__init__.py 2>/dev/null || echo "")
NEW_TAG="v$NEW_VERSION"
LAST_TAG=$(git tag --sort=-v:refname | head -1)
if [ -z "$LAST_TAG" ]; then LAST_TAG="v0.0.0"; fi
log "Version: $LAST_TAG → $NEW_TAG"
if [ -z "$NEW_VERSION" ]; then
    rollback_local_tree
    fail "Cannot read __version__ from trust_layer/__init__.py"
fi
if [ -n "$(git tag -l "$NEW_TAG")" ] \
   || [ "$(printf '%s\n%s\n' "$LAST_TAG" "$NEW_TAG" | sort -V | tail -1)" != "$NEW_TAG" ]; then
    rollback_local_tree
    fail "Version $NEW_VERSION is not above $LAST_TAG — bump trust_layer/__init__.py in a PR"
fi
if ! grep -q "^## \[$NEW_VERSION\]" CHANGELOG.md; then
    rollback_local_tree
    fail "CHANGELOG.md has no '## [$NEW_VERSION]' entry — add it in the PR"
fi

CHANGELOG=$(git log "${LAST_TAG}..HEAD" --oneline --no-merges 2>/dev/null | head -20 | sed 's/^/• /' || echo "• No changelog available")

# ============================================================
# PHASE 1 — GATES LOCALES
# ============================================================
log "--- Phase 1: Gates ---"

# Gate 1 — CI GitHub on the exact commit being deployed
if [ "$FORCE_CI" = false ]; then
    log "Gate 1/4: CI GitHub on $NEW_COMMIT..."
    CI_OK=$(gh api "repos/ark-forge/trust-layer/commits/$NEW_COMMIT/check-runs" \
        --jq '[.check_runs[] | select(.name == "test" and .conclusion == "success")] | length' 2>/dev/null || echo "0")
    # gh prints its error body on stdout: anything but a positive count is a failure.
    if ! [[ "$CI_OK" =~ ^[1-9][0-9]*$ ]]; then
        rollback_local_tree
        fail "CI gate FAILED — no successful 'test' check on $NEW_COMMIT. Use --force to bypass."
    fi
    log "Gate 1/4: CI OK"
else
    log "Gate 1/4: CI bypassed (--force)"
fi

# Gate 2 — proof-spec check_consistency
log "Gate 2/4: proof-spec check_consistency.py..."
if [ ! -f "$PROOF_SPEC_DIR/check_consistency.py" ]; then
    rollback_local_tree
    fail "proof-spec not found at $PROOF_SPEC_DIR"
fi
if ! python3 "$PROOF_SPEC_DIR/check_consistency.py" >> "$LOG_FILE" 2>&1; then
    rollback_local_tree
    fail "proof-spec check_consistency.py FAILED"
fi
log "Gate 2/4: proof-spec OK"

# Gate 3 — agent-client tests
log "Gate 3/4: agent-client pytest..."
if [ ! -d "$AGENT_CLIENT_DIR/tests" ]; then
    rollback_local_tree
    fail "agent-client not found at $AGENT_CLIENT_DIR"
fi
if ! python3 -m pytest "$AGENT_CLIENT_DIR/tests/" -q --tb=short >> "$LOG_FILE" 2>&1; then
    rollback_local_tree
    fail "agent-client tests FAILED"
fi
log "Gate 3/4: agent-client tests OK"

# Gate 4 — Trust Layer tests, sur les dépendances du commit à déployer
log "Gate 4/4: trust-layer pytest..."
if ! "$REPO_DIR/venv/bin/pip" install -q --disable-pip-version-check -r requirements-dev.txt >> "$LOG_FILE" 2>&1; then
    rollback_local_tree
    fail "pip install requirements-dev.txt FAILED (venv des tests)"
fi
if ! "$REPO_DIR/venv/bin/python3" -m pytest tests/ -q --tb=short >> "$LOG_FILE" 2>&1; then
    rollback_local_tree
    fail "trust-layer tests FAILED"
fi
log "Gate 4/4: trust-layer tests OK"

log "All gates PASSED"

# ============================================================
# PHASE 2 — DEPLOY (staged rollout: standby first → primary)
# ============================================================
log "--- Phase 2: Deploy ---"

# ----------------------------------------------------------------
# Phase 2a — Deploy to STANDBY + canary (no traffic at risk)
# ----------------------------------------------------------------
log "--- Phase 2a: Deploy to standby ($STANDBY_HOST) ---"
# Sync vault secrets before deploy (ensures SMTP, Stripe keys are current on the standby)
VAULT_FILE="/opt/claude-ceo/config/vault.json.enc"
rsync -az --no-group -e "$SSH" "$VAULT_FILE" "${STANDBY_HOST}:${VAULT_FILE}" >> "$LOG_FILE" 2>&1 \
    && log "Phase 2a: vault synced to standby" \
    || log "WARN: vault sync failed (non-blocking)"

STANDBY_OK=true
if ! $SSH "$STANDBY_HOST" \
    "cd ${STANDBY_REPO} && git pull --ff-only origin main 2>&1 && { $DEPS_CMD; } 2>&1 && sudo -n /usr/local/sbin/arkforge-run relance $SERVICE 2>&1" \
    >> "$LOG_FILE" 2>&1; then
    log "Phase 2a: git pull / restart failed on standby"
    STANDBY_OK=false
fi

if [ "$STANDBY_OK" = true ]; then
    # The version served proves the process runs the new code, not just that the tree moved.
    STANDBY_VERSION=""
    for i in 1 2 3 4; do
        sleep 5
        H=$(standby_health)
        STANDBY_VERSION=$(echo "$H" | json_field version)
        log "Phase 2a attempt $i/4: status=$(echo "$H" | json_field status) version=$STANDBY_VERSION role=$(echo "$H" | json_field role)"
        if [ "$(echo "$H" | json_field status)" = "ok" ] && [ "$STANDBY_VERSION" = "$NEW_VERSION" ]; then break; fi
    done
    if [ "$STANDBY_VERSION" != "$NEW_VERSION" ]; then STANDBY_OK=false; fi
fi

if [ "$STANDBY_OK" = true ]; then
    for path in /v1/pricing /; do
        CODE=$(standby_http_code "$path")
        log "Phase 2a canary: $path → HTTP $CODE"
        if [ "$CODE" != "200" ]; then STANDBY_OK=false; fi
    done
fi

if [ "$STANDBY_OK" = false ]; then
    rollback_standby
    rollback_local_tree
    fail "Phase 2a FAILED on standby — rolled back standby to $STANDBY_PREV_COMMIT (primary untouched)"
fi
log "Phase 2a OK — standby runs $NEW_VERSION"

# ----------------------------------------------------------------
# Phase 2b — Deploy to PRIMARY (short outage: nothing falls back)
# ----------------------------------------------------------------
log "--- Phase 2b: Deploy to primary (local) ---"
if ! bash -c "$DEPS_CMD" >> "$LOG_FILE" 2>&1; then
    rollback_primary
    rollback_standby
    fail "Phase 2b: dépendances non installées sur le primary — primary et standby remis à leur commit précédent"
fi
log "Phase 2b: dépendances installées et vérifiées"
sudo -n /usr/local/sbin/arkforge-run relance "$SERVICE"

PRIMARY_OK=false
for i in $(seq 1 6); do
    sleep 5
    H=$(local_health)
    log "Phase 2b attempt $i/6: status=$(echo "$H" | json_field status) version=$(echo "$H" | json_field version) role=$(echo "$H" | json_field role)"
    if [ "$(echo "$H" | json_field status)" = "ok" ] && [ "$(echo "$H" | json_field version)" = "$NEW_VERSION" ]; then
        PRIMARY_OK=true
        break
    fi
done

# Then through the public URL: validates Cloudflare → nginx → primary.
if [ "$PRIMARY_OK" = true ]; then
    PRIMARY_OK=false
    for i in $(seq 1 6); do
        H=$(curl -s --max-time 5 "$HEALTH_URL" || true)
        log "Public health $i/6: status=$(echo "$H" | json_field status) environment=$(echo "$H" | json_field environment) version=$(echo "$H" | json_field version)"
        if [ "$(echo "$H" | json_field status)" = "ok" ] \
           && [ "$(echo "$H" | json_field environment)" = "production" ] \
           && [ "$(echo "$H" | json_field version)" = "$NEW_VERSION" ]; then
            PRIMARY_OK=true
            break
        fi
        sleep 5
    done
fi

if [ "$PRIMARY_OK" = false ]; then
    log "Phase 2b FAILED — rolling back both nodes"
    rollback_primary
    rollback_standby
    check_public_after_rollback
    fail "Phase 2b FAILED — rolled back primary to $PREV_COMMIT and standby to $STANDBY_PREV_COMMIT"
fi

log "Service healthy after deploy"

# ============================================================
# PHASE 2.5 — SMOKE TEST
# ============================================================
if [ "$SKIP_SMOKE" = true ]; then
    log "--- Phase 2.5: Smoke test SKIPPED (--skip-smoke) ---"
else
    log "--- Phase 2.5: Smoke test ---"
    # Phase 0 already refused a missing gate before deploying. Kept as a second lock, and it fails closed:
    # a script that disappeared between Phase 0 and here rolls back instead of letting the deploy through.
    if [ ! -f "$SMOKE_TEST_SCRIPT" ] || [ ! -f "$SECURITY_TEST_SCRIPT" ]; then
        log "Phase 2.5: gate script missing after deploy — rolling back"
        rollback_primary
        rollback_standby
        check_public_after_rollback
        fail "Gate script missing ($SECURITY_TEST_SCRIPT / $SMOKE_TEST_SCRIPT) — rolled back primary to $PREV_COMMIT and standby to $STANDBY_PREV_COMMIT"
    else
        SMOKE_LOG="$LOG_FILE.smoke"
        SMOKE_BASE_URL="${HEALTH_URL%/v1/health}"  # strip /v1/health → https://trust.arkforge.tech
        SMOKE_INTERNAL_SECRET=$(grep "^TRUST_LAYER_INTERNAL_SECRET=" "$SETTINGS_ENV" | cut -d= -f2-)
        # Stripe webhook secret: same resolution order as the server (vault, then
        # settings.env). /v1/admin/smoke/setup no longer hands it out (2026-09-12).
        SMOKE_WEBHOOK_SECRET=$(python3 -c "
import sys
sys.path.insert(0, '/opt/claude-ceo')
try:
    from automation.vault import vault
    s = vault.get_section('stripe') or {}
    print(s.get('tl_webhook_secret') or s.get('tl_webhook_secret_test') or '')
except Exception:
    print('')
" 2>/dev/null)
        if [ -z "$SMOKE_WEBHOOK_SECRET" ]; then
            SMOKE_WEBHOOK_SECRET=$(grep "^STRIPE_TL_WEBHOOK_SECRET=" "$SETTINGS_ENV" | cut -d= -f2-)
        fi
        # Both gates must pass. The security test runs first: its ephemeral key uses
        # a smoke.invalid email, swept by the teardown at the end of the smoke test.
        if python3 "$SECURITY_TEST_SCRIPT" --url "$SMOKE_BASE_URL" 2>&1 | tee -a "$SMOKE_LOG" | tail -8 \
           && TRUST_LAYER_INTERNAL_SECRET="$SMOKE_INTERNAL_SECRET" \
              TRUST_LAYER_SMOKE_WEBHOOK_SECRET="$SMOKE_WEBHOOK_SECRET" python3 "$SMOKE_TEST_SCRIPT" \
               --base-url "$SMOKE_BASE_URL" \
               2>&1 | tee -a "$SMOKE_LOG" | tail -6; then
            log "Phase 2.5: Smoke test PASSED"
            SMOKE_RESULT="PASSED"
        else
            SMOKE_EXIT=${PIPESTATUS[0]}
            log "Phase 2.5: Smoke test FAILED (exit $SMOKE_EXIT)"
            SMOKE_RESULT="FAILED"
            rollback_primary
            rollback_standby
            check_public_after_rollback
            fail "Smoke test FAILED — rolled back primary to $PREV_COMMIT and standby to $STANDBY_PREV_COMMIT"
        fi
    fi
fi

# ============================================================
# PHASE 3 — RELEASE
# ============================================================
log "--- Phase 3: Release ---"
# Only the tag is pushed. Release notes come from .github/workflows/release.yml;
# CHANGELOG.md was written in the PR.
git tag "$NEW_TAG"
git push origin "$NEW_TAG" >> "$LOG_FILE" 2>&1
log "Tag $NEW_TAG pushed"

# ============================================================
# PHASE 3b — SYNC arkforge-mcp (PyPI)
# ============================================================
log "--- Phase 3b: Sync arkforge-mcp ---"
MCP_DIR="/opt/claude-ceo/workspace/mcp-servers/arkforge-trust"
MCP_PUBLISH_VENV="/opt/arkforge-venvs/mcp-publish"
MCP_RESULT="skipped"

if [ ! -d "$MCP_DIR" ]; then
    log "WARN: arkforge-mcp not found at $MCP_DIR — skipping MCP sync"
else
    cd "$MCP_DIR"

    # Bump patch version in pyproject.toml
    CURRENT_MCP=$(grep '^version' pyproject.toml | grep -oP '[\d.]+')
    MCP_MAJOR=$(echo "$CURRENT_MCP" | cut -d. -f1)
    MCP_MINOR=$(echo "$CURRENT_MCP" | cut -d. -f2)
    MCP_PATCH=$(echo "$CURRENT_MCP" | cut -d. -f3)
    NEW_MCP="${MCP_MAJOR}.${MCP_MINOR}.$((MCP_PATCH + 1))"

    sed -i "s/^version = .*/version = \"$NEW_MCP\"/" pyproject.toml
    sed -i "s/arkforge-mcp\/[0-9][0-9.]*/arkforge-mcp\/$NEW_MCP/" src/arkforge_mcp/server.py

    # Build + publish (stderr capturé séparément pour diagnostic)
    MCP_BUILD_OK=false
    MCP_UPLOAD_OK=false
    if rm -rf dist/ && "$MCP_PUBLISH_VENV/bin/python3" -m build -q >> "$LOG_FILE" 2>&1; then
        MCP_BUILD_OK=true
        TWINE_OUT=$("$MCP_PUBLISH_VENV/bin/twine" upload dist/* 2>&1)
        echo "$TWINE_OUT" >> "$LOG_FILE"
        if echo "$TWINE_OUT" | grep -q "View at:"; then
            MCP_UPLOAD_OK=true
        elif echo "$TWINE_OUT" | grep -q "already exists"; then
            log "WARN: MCP $NEW_MCP already on PyPI — skipping upload (idempotent)"
            MCP_UPLOAD_OK=true
        else
            log "WARN: MCP publish failed — twine output: $(echo "$TWINE_OUT" | tail -3)"
        fi
    else
        log "WARN: MCP build failed"
    fi

    if $MCP_UPLOAD_OK; then
        log "MCP $CURRENT_MCP → $NEW_MCP published to PyPI"
        MCP_RESULT="$CURRENT_MCP → $NEW_MCP"

        # Commit + push to arkforge-mcp repo
        git add pyproject.toml src/arkforge_mcp/server.py
        git commit -m "chore: sync to trust-layer $NEW_TAG" >> "$LOG_FILE" 2>&1 || true
        git push >> "$LOG_FILE" 2>&1 || log "WARN: MCP git push failed (non-blocking)"
        log "arkforge-mcp repo updated (aligned with TL $NEW_TAG)"
    else
        # Revert version bump pour éviter désynchronisation
        git checkout pyproject.toml src/arkforge_mcp/server.py 2>/dev/null || true
        MCP_RESULT="FAILED (build=$MCP_BUILD_OK, upload=$MCP_UPLOAD_OK)"
    fi

    cd "$REPO_DIR"
fi

# ============================================================
# PHASE 4 — NOTIFICATION
# ============================================================
SMOKE_STATUS_MSG=""
if [ "$SKIP_SMOKE" = true ]; then
    SMOKE_STATUS_MSG=" | smoke: skipped"
elif [ "${SMOKE_RESULT:-}" = "PASSED" ]; then
    SMOKE_STATUS_MSG=" | smoke: ✓"
fi
MCP_STATUS_MSG=" | mcp: $MCP_RESULT"
NOTIFY_MSG="Deploy $LAST_TAG → $NEW_TAG OK${SMOKE_STATUS_MSG}${MCP_STATUS_MSG}\n\n${CHANGELOG}"
telegram_notify "$NOTIFY_MSG"
log "Telegram notification sent"

log "=== Deploy $NEW_TAG COMPLETE ==="
echo ""
echo "  Trust Layer $NEW_TAG deployed successfully"
echo "  Health: $HEALTH_URL"
echo "  Changelog since $LAST_TAG:"
echo "$CHANGELOG"
