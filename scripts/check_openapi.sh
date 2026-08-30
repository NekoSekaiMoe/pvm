#!/usr/bin/env bash
# Structural validation for the OpenAPI document beyond YAML well-formedness.

set -euo pipefail

OPENAPI_FILE="${1:-api/openapi.yaml}"
ERRORS=()
EXIT_CODE=0

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# 检查依赖
if ! command -v yq &> /dev/null; then
    echo "错误: 需要安装 yq (https://github.com/mikefarah/yq)"
    exit 1
fi

# 提取路径模板中的参数
path_params() {
    local template="$1"
    echo "$template" | grep -oE '{[^}/]+}' | sed 's/[{}]//g' || true
}

# 获取参数名称（处理 $ref）
get_param_names() {
    local param="$1"
    local ref=$(echo "$param" | yq '.$ref // ""')
    
    if [[ -n "$ref" && "$ref" =~ ^#/components/parameters/ ]]; then
        local name=$(echo "$ref" | awk -F'/' '{print $NF}')
        local target=$(yq ".components.parameters.\"$name\"" "$OPENAPI_FILE")
        if [[ -n "$target" ]] && echo "$target" | yq -e '.in == "path"' &>/dev/null; then
            echo "$target" | yq '.name // ""'
        fi
    else
        local in=$(echo "$param" | yq '.in // ""')
        if [[ "$in" == "path" ]]; then
            echo "$param" | yq '.name // ""'
        fi
    fi
}

# 收集路径中声明的参数
collect_declared_params() {
    local template="$1"
    local declared=""
    
    # 路径级别的参数
    while IFS= read -r param; do
        if [[ -n "$param" ]]; then
            local name=$(get_param_names "$param")
            if [[ -n "$name" ]]; then
                declared="$declared $name"
            fi
        fi
    done < <(yq ".paths.\"$template\".parameters[]?" "$OPENAPI_FILE" 2>/dev/null || true)
    
    # 各个 HTTP 方法的参数
    for method in get put post delete options head patch; do
        while IFS= read -r param; do
            if [[ -n "$param" ]]; then
                local name=$(get_param_names "$param")
                if [[ -n "$name" ]]; then
                    declared="$declared $name"
                fi
            fi
        done < <(yq ".paths.\"$template\".$method.parameters[]?" "$OPENAPI_FILE" 2>/dev/null || true)
    done
    
    echo "$declared" | tr ' ' '\n' | sort -u | grep -v '^$' || true
}

# 检查响应引用
check_response_refs() {
    local node="$1"
    local where="$2"
    
    # 使用 yq 递归查找所有 schema.$ref
    while IFS= read -r ref; do
        if [[ -n "$ref" && "$ref" =~ ^#/components/responses/ ]]; then
            ERRORS+=("${where}: schema.\$ref 指向了 response 对象: $ref")
            EXIT_CODE=1
        fi
    done < <(yq ".. | select(has(\"schema\")) | .schema.\$ref // \"\"" "$OPENAPI_FILE" | grep -v '^$' || true)
}

# 主检查逻辑
main() {
    # 检查文件是否存在
    if [[ ! -f "$OPENAPI_FILE" ]]; then
        echo "错误: 文件不存在: $OPENAPI_FILE"
        exit 1
    fi
    
    # 获取所有路径
    local paths=$(yq '.paths | keys | .[]' "$OPENAPI_FILE" 2>/dev/null || true)
    local path_count=$(echo "$paths" | wc -l)
    
    for template in $paths; do
        # 路径模板中的参数
        local tmpl_params=$(path_params "$template" | sort -u)
        
        # 声明的参数
        local declared_params=$(collect_declared_params "$template")
        
        # 检查缺失和多余
        local missing=$(comm -23 <(echo "$declared_params") <(echo "$tmpl_params") 2>/dev/null || true)
        local extra=$(comm -13 <(echo "$declared_params") <(echo "$tmpl_params") 2>/dev/null || true)
        
        if [[ -n "$missing" ]]; then
            ERRORS+=("${template}: in:path 参数不在模板中: $(echo $missing | tr '\n' ' ' | sed 's/ $//')")
            EXIT_CODE=1
        fi
        if [[ -n "$extra" ]]; then
            ERRORS+=("${template}: 模板参数未声明: $(echo $extra | tr '\n' ' ' | sed 's/ $//')")
            EXIT_CODE=1
        fi
    done
    
    # 检查响应引用
    check_response_refs "$OPENAPI_FILE" "$OPENAPI_FILE"
    
    # 输出结果
    if [[ $EXIT_CODE -ne 0 ]]; then
        for err in "${ERRORS[@]}"; do
            echo -e "${RED}openapi-check: $err${NC}" >&2
        done
        return 1
    else
        echo -e "${GREEN}openapi-check OK (${path_count} paths)${NC}"
        return 0
    fi
}

main