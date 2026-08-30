#!/usr/bin/env bash
# Structural validation for the OpenAPI document beyond YAML well-formedness.
#
# Catches the PR #22 review bug classes:
#   1. Path templates missing/extra {param} segments vs declared in:path params
#      (resolving $ref'd parameters from components/parameters).
#   2. $refs to components/responses/* used where a schema object is required.
#
# Requires: python3 (PyYAML) for the one-time YAML→JSON conversion — the same
# dependency `make deploy-check` already has — and jq for the queries.

set -euo pipefail

OPENAPI_FILE="${1:-api/openapi.yaml}"
ERRORS=()

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# --- YAML → JSON once; every later query is pure jq -------------------------
if ! JSON=$(python3 -c '
import json, sys, yaml
json.dump(yaml.safe_load(open(sys.argv[1])), sys.stdout)
' "$OPENAPI_FILE" 2>/dev/null); then
    echo "错误: 无法解析 $OPENAPI_FILE (需要 python3 + PyYAML)" >&2
    exit 1
fi

# --- 检查 1: 路径模板参数 vs 声明的 in:path 参数 -----------------------------
# 返回某路径下声明的所有 in:path 参数名（含 $ref 解析），每行一个。
declared_params() {
    local template="$1"
    printf '%s' "$JSON" | jq -r --arg t "$template" '
      . as $root |
      def pname($p):
        ($p["$ref"] // "") as $ref |
        if ($ref | startswith("#/components/parameters/")) then
          ($ref | split("/") | last) as $n |
          ($root.components.parameters[$n] // {}) |
          select(.in == "path") | .name // empty
        elif (($p.in // "") == "path") then
          $p.name // empty
        else
          empty
        end;
      [ (.paths[$t].parameters // [])[] | pname(.) ] +
      [ ["get","put","post","delete","options","head","patch"][] as $m
        | select(.paths[$t][$m] != null)
        | (.paths[$t][$m].parameters // [])[] | pname(.) ] |
      unique | .[]'
}

# 返回路径模板里的 {param} 片段，每行一个。
template_params() {
    echo "$1" | grep -oE '\{[^}/]+\}' | tr -d '{}' || true
}

while IFS= read -r template; do
    [[ -z "$template" ]] && continue

    # comm 需要排序后的输入；排序同时去重。
    local_declared=$(declared_params "$template" | sort -u)
    local_template=$(template_params "$template" | sort -u)

    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        if ! echo "$local_template" | grep -qxF "$name"; then
            ERRORS+=("$template: in:path 参数 [$name] 未出现在路径模板中")
        fi
    done <<< "$local_declared"

    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        if ! echo "$local_declared" | grep -qxF "$name"; then
            ERRORS+=("$template: 路径模板参数 [$name] 从未声明为 in:path 参数")
        fi
    done <<< "$local_template"
done < <(printf '%s' "$JSON" | jq -r '.paths | keys[]')

# --- 检查 2: schema 位置引用了 response 对象 --------------------------------
while IFS= read -r ref; do
    [[ -z "$ref" ]] && continue
    ERRORS+=("schema.\$ref 指向 response 对象: $ref")
done < <(printf '%s' "$JSON" | jq -r '
    [ .. | objects
      | select(has("schema"))
      | .schema | objects
      | .["$ref"]? // empty
      | select(startswith("#/components/responses/")) ] | .[]')

# --- 汇总 -------------------------------------------------------------------
if [[ ${#ERRORS[@]} -gt 0 ]]; then
    echo -e "${RED}openapi-check: 发现 ${#ERRORS[@]} 个问题${NC}" >&2
    for e in "${ERRORS[@]}"; do
        echo -e "  ${RED}✗${NC} $e" >&2
    done
    exit 1
fi

PATH_COUNT=$(printf '%s' "$JSON" | jq '.paths | length')
echo -e "${GREEN}openapi-check OK ($PATH_COUNT paths)${NC}"
