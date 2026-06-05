#!/usr/bin/env bash
# deploy_trust_layer_azure.sh — Deploy Trust Layer to Azure Container Apps
#
# Prérequis : az CLI loggé (az login), accès SSH VPS (clé ~/.ssh/vps_ovh)
#
# Usage:
#   ./scripts/deploy_trust_layer_azure.sh [--skip-gates] [--skip-smoke] [--minor|--major]
#
# Flags:
#   --skip-gates   Bypass CI + tests (hotfix uniquement)
#   --skip-smoke   Bypass smoke test post-deploy
#   --minor        Bump minor (1.0.x → 1.1.0)
#   --major        Bump major (1.x.x → 2.0.0)
#   (défaut)       Bump patch (1.0.2 → 1.0.3)

set -euo pipefail

# ============================================================
# CONFIGURATION
# ============================================================
VPS_HOST="ubuntu@57.131.27.61"
VPS_SSH_KEY="$HOME/.ssh/vps_ovh"
VPS_REPO="/opt/claude-ceo/workspace/arkforge-trust-layer"
BUILD_CTX="/tmp/tl-build-ctx"

ACR="crarkforgeprod"
ACR_IMAGE="crarkforgeprod.azurecr.io/trust-layer"
CONTAINER_APP="ca-trust-layer-prod"
RESOURCE_GROUP="rg-arkforge-prod"
HEALTH_URL="https://trust.arkforge.tech/v1/health"

LOG_FILE="/tmp/deploy_trust_layer_azure.log"

# ============================================================
# ARGS
# ============================================================
VERSION_BUMP="patch"
SKIP_GATES=false
SKIP_SMOKE=false
for arg in "$@"; do
    case "$arg" in
        --minor)       VERSION_BUMP="minor" ;;
        --major)       VERSION_BUMP="major" ;;
        --skip-gates)  SKIP_GATES=true ;;
        --skip-smoke)  SKIP_SMOKE=true ;;
    esac
done

# ============================================================
# HELPERS
# ============================================================
log()  { echo "[$(date -u +%H:%M:%SZ)] $*" | tee -a "$LOG_FILE"; }
fail() { log "ERROR: $*"; exit 1; }

vps() { ssh -i "$VPS_SSH_KEY" -o ConnectTimeout=10 "$VPS_HOST" "$@"; }

bump_version() {
    local cur="$1" bump="$2"
    local maj min pat
    maj=$(echo "$cur" | cut -d. -f1 | tr -d 'v')
    min=$(echo "$cur" | cut -d. -f2)
    pat=$(echo "$cur" | cut -d. -f3)
    case "$bump" in
        major) echo "v$((maj+1)).0.0" ;;
        minor) echo "v${maj}.$((min+1)).0" ;;
        patch) echo "v${maj}.${min}.$((pat+1))" ;;
    esac
}

mkdir -p "$(dirname "$LOG_FILE")"
log "=== Trust Layer → Azure deploy — $(date -u) ==="
log "Bump: $VERSION_BUMP | skip-gates: $SKIP_GATES | skip-smoke: $SKIP_SMOKE"

# ============================================================
# PHASE 1 — GATES (s'exécutent sur le VPS)
# ============================================================
if [ "$SKIP_GATES" = false ]; then
    log "--- Phase 1: Gates ---"

    log "Gate 1/3: proof-spec check_consistency..."
    if ! vps "python3 /opt/claude-ceo/workspace/proof-spec/check_consistency.py" >> "$LOG_FILE" 2>&1; then
        fail "Gate 1 FAILED — proof-spec check_consistency.py"
    fi
    log "Gate 1/3: OK"

    log "Gate 2/3: agent-client tests..."
    if ! vps "cd /opt/claude-ceo/workspace/agent-client && python3 -m pytest tests/ -q --tb=short" >> "$LOG_FILE" 2>&1; then
        fail "Gate 2 FAILED — agent-client tests"
    fi
    log "Gate 2/3: OK"

    log "Gate 3/3: trust-layer tests..."
    if ! vps "cd $VPS_REPO && python3 -m pytest tests/ -q --tb=short" >> "$LOG_FILE" 2>&1; then
        fail "Gate 3 FAILED — trust-layer tests"
    fi
    log "Gate 3/3: OK"

    log "Toutes les gates OK"
else
    log "Gates SKIPPED (--skip-gates)"
fi

# ============================================================
# PHASE 2 — VERSION BUMP SUR VPS
# ============================================================
log "--- Phase 2: Version bump ---"
LAST_TAG=$(vps "git -C $VPS_REPO tag --sort=-v:refname | head -1" 2>/dev/null || echo "v0.0.0")
[ -z "$LAST_TAG" ] && LAST_TAG="v0.0.0"
NEW_TAG=$(bump_version "$LAST_TAG" "$VERSION_BUMP")
NEW_VERSION="${NEW_TAG#v}"
log "Version: $LAST_TAG → $NEW_TAG"

PREV_COMMIT=$(vps "git -C $VPS_REPO rev-parse HEAD")

CURRENT_APP_VERSION=$(vps "grep -oP '(?<=__version__ = \")[^\"]+' $VPS_REPO/trust_layer/__init__.py 2>/dev/null || echo ''")
if [ "$CURRENT_APP_VERSION" != "$NEW_VERSION" ]; then
    vps "sed -i 's/^__version__ = .*/__version__ = \"$NEW_VERSION\"/' $VPS_REPO/trust_layer/__init__.py"
    vps "cd $VPS_REPO && git add trust_layer/__init__.py && git commit -m 'chore: bump version to $NEW_VERSION'" >> "$LOG_FILE" 2>&1
    log "Version bumped: $CURRENT_APP_VERSION → $NEW_VERSION"
else
    log "Version déjà à $NEW_VERSION — pas de bump"
fi

NEW_COMMIT=$(vps "git -C $VPS_REPO rev-parse HEAD")

# ============================================================
# PHASE 3 — BUILD IMAGE AZURE (depuis local via az acr build)
# ============================================================
log "--- Phase 3: Build image ACR ---"

log "Rsync VPS → $BUILD_CTX..."
rsync -az --delete \
    --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='.venv' --exclude='venv' --exclude='proofs' --exclude='data' \
    -e "ssh -i $VPS_SSH_KEY" \
    "${VPS_HOST}:${VPS_REPO}/" "$BUILD_CTX/"
log "Rsync OK ($(du -sh "$BUILD_CTX" | cut -f1))"

IMAGE_TAG="${ACR_IMAGE}:${NEW_TAG}"
log "Build: $IMAGE_TAG..."
if ! az acr build \
    -r "$ACR" \
    -t "${ACR_IMAGE}:${NEW_TAG}" \
    -t "${ACR_IMAGE}:latest" \
    -f "$BUILD_CTX/Dockerfile" \
    "$BUILD_CTX/" >> "$LOG_FILE" 2>&1; then
    fail "Phase 3 FAILED — az acr build"
fi
log "Build OK → $IMAGE_TAG"

# ============================================================
# PHASE 4 — DEPLOY CONTAINER APP
# ============================================================
log "--- Phase 4: Deploy Container App ---"

# Sauvegarder l'image courante pour rollback
PREV_IMAGE=$(az containerapp show \
    -n "$CONTAINER_APP" -g "$RESOURCE_GROUP" \
    --query 'properties.template.containers[0].image' -o tsv 2>/dev/null)
log "Image précédente (rollback): $PREV_IMAGE"

if ! az containerapp update \
    -n "$CONTAINER_APP" -g "$RESOURCE_GROUP" \
    --image "$IMAGE_TAG" \
    --revision-suffix "${NEW_TAG//./-}" >> "$LOG_FILE" 2>&1; then
    fail "Phase 4 FAILED — az containerapp update"
fi
log "Container App mis à jour → $IMAGE_TAG"

# ============================================================
# PHASE 5 — HEALTH CHECK (8 × 10s = 80s max)
# ============================================================
log "--- Phase 5: Health check $HEALTH_URL ---"
HEALTHY=false
for i in $(seq 1 8); do
    sleep 10
    STATUS=$(curl -s --max-time 8 "$HEALTH_URL" | python3 -c "
import sys, json
try: print(json.load(sys.stdin).get('status','error'))
except: print('error')
" 2>/dev/null || echo "error")
    log "Attempt $i/8: status=$STATUS"
    if [ "$STATUS" = "ok" ]; then
        HEALTHY=true
        break
    fi
done

if [ "$HEALTHY" = false ]; then
    log "Health check FAILED — rollback vers $PREV_IMAGE"
    az containerapp update \
        -n "$CONTAINER_APP" -g "$RESOURCE_GROUP" \
        --image "$PREV_IMAGE" >> "$LOG_FILE" 2>&1 && log "Rollback OK" || log "WARN: Rollback failed"
    fail "Health check FAILED après deploy — rolled back vers $PREV_IMAGE"
fi
log "Service healthy"

# ============================================================
# PHASE 6 — SMOKE TEST (optionnel)
# ============================================================
if [ "$SKIP_SMOKE" = false ]; then
    log "--- Phase 6: Smoke test ---"
    SMOKE_SCRIPT="$BUILD_CTX/scripts/smoke_test_prod.py"
    if [ -f "$SMOKE_SCRIPT" ]; then
        SMOKE_BASE=$(echo "$HEALTH_URL" | sed 's|/v1/health||')
        TL_SECRET=$(az containerapp secret show \
            -n "$CONTAINER_APP" -g "$RESOURCE_GROUP" \
            --secret-name trust-layer-internal-secret \
            --query value -o tsv 2>/dev/null || echo "")
        if [ -z "$TL_SECRET" ]; then
            log "WARN: could not read trust-layer-internal-secret from ACA — smoke test skipped"
        elif ! TRUST_LAYER_INTERNAL_SECRET="$TL_SECRET" python3 "$SMOKE_SCRIPT" --base-url "$SMOKE_BASE" >> "$LOG_FILE" 2>&1; then
            log "Smoke test FAILED — rollback vers $PREV_IMAGE"
            az containerapp update \
                -n "$CONTAINER_APP" -g "$RESOURCE_GROUP" \
                --image "$PREV_IMAGE" >> "$LOG_FILE" 2>&1 && log "Rollback OK" || log "WARN: Rollback failed"
            fail "Smoke test FAILED — rolled back vers $PREV_IMAGE"
        fi
        log "Smoke test OK"
    else
        log "Smoke test script introuvable — skipped"
    fi
else
    log "Smoke test SKIPPED (--skip-smoke)"
fi

# ============================================================
# PHASE 7 — TAG GIT + NOTIFICATION
# ============================================================
log "--- Phase 7: Release ---"
vps "cd $VPS_REPO && git tag $NEW_TAG && git push origin main $NEW_TAG" >> "$LOG_FILE" 2>&1
log "Tag $NEW_TAG pushé"

log "=== Deploy $NEW_TAG COMPLETE ==="
echo ""
echo "  Trust Layer $NEW_TAG déployé sur Azure Container Apps"
echo "  Image: $IMAGE_TAG"
echo "  Health: $HEALTH_URL"
echo "  Log: $LOG_FILE"
