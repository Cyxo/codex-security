#!/bin/sh

set -eu

# Compose cannot expand one variable into several arguments, so extra flags
# arrive in one variable and are appended before any validation below. The
# unquoted expansion is the point: it splits on whitespace. Arguments
# containing spaces need `run --rm codex-security ARGS`, which bypasses this.
if [ -n "${CODEX_SECURITY_ARGS:-}" ]; then
    # shellcheck disable=SC2086
    set -- "$@" $CODEX_SECURITY_ARGS
fi

bulk_scan_command=
bulk_scan_input=
bulk_scan_metadata=
expects_option_value=

for argument do
    if [ "$argument" = -- ] && [ "$bulk_scan_command" = yes ]; then
        printf '%s\n' 'codex-security: bulk-scan does not support the -- option terminator.' >&2
        exit 2
    fi

    case "$argument" in
        --help|-h|--llms|--llms-full|--schema|--version)
            bulk_scan_metadata=yes
            continue
            ;;
    esac

    if [ "$expects_option_value" = yes ]; then
        expects_option_value=
        continue
    fi

    case "$argument" in
        --)
            break
            ;;
        bulk-scan)
            if [ "$bulk_scan_command" = yes ]; then
                bulk_scan_input=$argument
            else
                bulk_scan_command=yes
            fi
            ;;
        --config|-c|--output-dir|--workers|--mode|--model|--effort|--provider|\
            --knowledge-base|--max-attempts|--max-cost|--plugin-path|--python|\
            --codex|--filter-output|--format|\
            --scan-prompt-file|--post-scan-prompt-file|--validation-prompt-file|\
            --token-limit|--token-offset)
            expects_option_value=yes
            ;;
        -*)
            ;;
        *)
            if [ "$bulk_scan_command" != yes ]; then
                break
            fi
            bulk_scan_input=$argument
            ;;
    esac
done

if [ "$bulk_scan_command" = yes ] && [ "$bulk_scan_metadata" != yes ]; then
    case "$bulk_scan_input" in
        "")
            printf '%s\n' 'codex-security: bulk-scan requires a repository CSV; interactive discovery is not supported in this image.' >&2
            exit 2
            ;;
    esac
fi

if [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
    git_host=${CODEX_SECURITY_GIT_HOST:-github.com}

    case "$git_host" in
        ""|.*|*..*|*.|*[!A-Za-z0-9.-]*)
            printf '%s\n' 'codex-security: CODEX_SECURITY_GIT_HOST must be a valid hostname.' >&2
            exit 2
            ;;
    esac

    git_config_count=${GIT_CONFIG_COUNT:-0}

    case "$git_config_count" in
        *[!0-9]*|0?*)
            printf '%s\n' 'codex-security: GIT_CONFIG_COUNT must be a nonnegative decimal integer.' >&2
            exit 2
            ;;
    esac

    # Git accepts at most INT_MAX entries; leave room for the two appended below.
    if [ "${#git_config_count}" -gt 10 ] || [ "$git_config_count" -gt 2147483645 ]; then
        printf '%s\n' 'codex-security: GIT_CONFIG_COUNT leaves no room for two entries within the Git integer limit.' >&2
        exit 2
    fi

    export "GIT_CONFIG_KEY_${git_config_count}=credential.https://${git_host}.helper"
    export "GIT_CONFIG_VALUE_${git_config_count}=/usr/local/bin/codex-security-git-credential"
    git_config_count=$((git_config_count + 1))
    export "GIT_CONFIG_KEY_${git_config_count}=url.https://${git_host}/.insteadOf"
    export "GIT_CONFIG_VALUE_${git_config_count}=git@${git_host}:"
    export GIT_CONFIG_COUNT=$((git_config_count + 1))
fi

# An OpenAI-compatible endpoint needs its provider definition on the command
# line, which this image's callers cannot append themselves. The wrapper probes
# the endpoint and adds it. Without CS_COMPAT_BASE_URL nothing changes.
if [ -n "${CS_COMPAT_BASE_URL:-}" ]; then
    cs_compat_wrapper=${CS_COMPAT_WRAPPER:-/opt/codex-security-contrib/openai-compatible/bin/cs-compat.mjs}

    if [ ! -r "$cs_compat_wrapper" ]; then
        printf '%s\n' "codex-security: CS_COMPAT_BASE_URL is set but $cs_compat_wrapper is missing." >&2
        exit 2
    fi

    exec node "$cs_compat_wrapper" "$@"
fi

exec codex-security "$@"
