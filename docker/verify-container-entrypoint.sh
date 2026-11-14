#!/bin/sh
set -eu

command_directory=$(mktemp -d)
trap 'rm -rf "$command_directory"' EXIT
printf '%s\n' '#!/bin/sh' 'printf "%s\0" "$@"' > "$command_directory/codex-security"
chmod 755 "$command_directory/codex-security"

set -- bulk-scan /input/repositories.csv --output-dir /output
PATH="$command_directory:$PATH" /usr/local/bin/codex-security-entrypoint "$@" > "$command_directory/actual"
printf '%s\0' "$@" | cmp - "$command_directory/actual"

# An empty CS_COMPAT_BASE_URL leaves the command untouched.
CS_COMPAT_BASE_URL= PATH="$command_directory:$PATH" \
    /usr/local/bin/codex-security-entrypoint "$@" > "$command_directory/actual"
printf '%s\0' "$@" | cmp - "$command_directory/actual"

# A configured endpoint routes the same arguments through the wrapper. The stub
# stands in for it so this checks the entrypoint alone, not endpoint probing.
printf '%s\n' \
    'process.stdout.write(["wrapper", ...process.argv.slice(2)].map((a) => a + "\0").join(""));' \
    > "$command_directory/wrapper.mjs"
CS_COMPAT_BASE_URL=http://endpoint.invalid/v1 \
    CS_COMPAT_WRAPPER="$command_directory/wrapper.mjs" \
    PATH="$command_directory:$PATH" \
    /usr/local/bin/codex-security-entrypoint "$@" > "$command_directory/actual"
{ printf 'wrapper\0'; printf '%s\0' "$@"; } | cmp - "$command_directory/actual"

# The real wrapper ships in the image, so the default path resolves.
test -r /opt/codex-security-contrib/openai-compatible/bin/cs-compat.mjs

# A configured endpoint with no wrapper fails instead of scanning unprovided.
status=0
CS_COMPAT_BASE_URL=http://endpoint.invalid/v1 \
    CS_COMPAT_WRAPPER="$command_directory/absent.mjs" \
    PATH="$command_directory:$PATH" \
    /usr/local/bin/codex-security-entrypoint "$@" > "$command_directory/actual" 2>/dev/null || status=$?
test "$status" -eq 2
test ! -s "$command_directory/actual"
