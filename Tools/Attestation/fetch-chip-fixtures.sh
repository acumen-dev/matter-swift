#!/usr/bin/env bash
# fetch-chip-fixtures.sh
# Copyright 2026 Monagle Pty Ltd
#
# Reproduce Tests/Fixtures/Attestation from connectedhomeip v1.4.0.0.
#
# Takes a shallow, sparse checkout of the public connectedhomeip repository at the
# pinned tag into a temporary directory, copies the attestation fixtures byte for
# byte, checks that they fit together, and writes SOURCES.md with each file's
# upstream path and SHA-256. Tests never run this: it is the only networked step.
#
# Usage:
#   ./Tools/Attestation/fetch-chip-fixtures.sh
#
# Prerequisites: git, openssl, xxd.

set -euo pipefail

REPO_URL="https://github.com/project-chip/connectedhomeip.git"
TAG="v1.4.0.0"
COMMIT="43aa98c2d30ee547c6b587b9de7bbb794f175ece"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT="$PACKAGE_ROOT/Tests/Fixtures/Attestation"

for cmd in git openssl xxd; do
    command -v "$cmd" >/dev/null || { echo "error: $cmd is required" >&2; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
CHIP="$WORK/connectedhomeip"

# MARK: - Sparse checkout

echo "Cloning connectedhomeip $TAG (sparse)..."
git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$TAG" --filter=blob:none --sparse \
    "$REPO_URL" "$CHIP" \
    || { echo "error: could not clone $REPO_URL at $TAG" >&2; exit 1; }
git -C "$CHIP" sparse-checkout set --no-cone \
    /credentials/development/attestation/ \
    /credentials/development/paa-root-certs/ \
    /credentials/development/cd-certs/ \
    /credentials/development/commissioner_dut/ \
    /credentials/test/certification-declaration/ \
    /src/credentials/examples/ \
    /NOTICE
HEAD_COMMIT="$(git -C "$CHIP" rev-parse HEAD)"
if [ "$HEAD_COMMIT" != "$COMMIT" ]; then
    echo "error: $TAG resolved to $HEAD_COMMIT, expected $COMMIT" >&2
    exit 1
fi

# MARK: - Copy

rm -rf "$OUT/dev" "$OUT/cd" "$OUT/commissioner_dut" "$OUT/SOURCES.md"
mkdir -p "$OUT/dev" "$OUT/cd" "$OUT/commissioner_dut"

ROWS="$WORK/rows"
: > "$ROWS"

sha256() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }

# copy <upstream path> <fixture path relative to $OUT>
copy() {
    cp "$CHIP/$1" "$OUT/$2"
    echo "| \`$2\` | \`$1\` | \`$(sha256 "$OUT/$2")\` |" >> "$ROWS"
}

# Bytes of a C array in a connectedhomeip source file, starting on the line after the
# first line matching <start pattern> and ending at the array's closing "};".
c_array_bytes() {
    sed -n "/$2/,/};/p" "$CHIP/$1" | sed 1d | grep -oE '0x[0-9a-fA-F]{2}' | sed 's/0x//' | tr -d '\n' | xxd -r -p
}

A=credentials/development/attestation
copy "$A/Matter-Development-DAC-FFF1-8000-Cert.der" dev/Matter-Development-DAC-FFF1-8000-Cert.der
copy "$A/Matter-Development-DAC-FFF1-8000-Key.der" dev/Matter-Development-DAC-FFF1-8000-Key.der
copy "$A/Matter-Development-PAI-FFF1-noPID-Cert.der" dev/Matter-Development-PAI-FFF1-noPID-Cert.der
copy credentials/development/paa-root-certs/Chip-Test-PAA-FFF1-Cert.der dev/Chip-Test-PAA-FFF1-Cert.der
copy credentials/development/paa-root-certs/Chip-Test-PAA-NoVID-Cert.der dev/Chip-Test-PAA-NoVID-Cert.der

copy credentials/development/commissioner_dut/struct_dac_cert_version_v3/cd.der cd/Test-CD-FFF1-8000.der
copy credentials/development/cd-certs/Chip-Test-CD-Cert.der cd/Chip-Test-CD-Cert.der
copy credentials/test/certification-declaration/Chip-Test-CD-Signing-Key.pem cd/Chip-Test-CD-Signing-Key.pem
for n in 1 2 3 4 5; do
    copy "credentials/development/cd-certs/CSA_Matter_CD_Signing_Key_00$n.cert.der" \
        "cd/CSA_Matter_CD_Signing_Key_00$n.cert.der"
done

EXAMPLES=src/credentials/examples/DeviceAttestationCredsExample.cpp
c_array_bytes "$EXAMPLES" 'Fall back to the VID=0xFFF1 CD' > "$OUT/cd/Example-CD-FFF1.der"
echo "| \`cd/Example-CD-FFF1.der\` | \`$EXAMPLES\`, bytes of \`kCdForAllExamples\` in the \`#else /* Fall back to the VID=0xFFF1 CD */\` branch | \`$(sha256 "$OUT/cd/Example-CD-FFF1.der")\` |" >> "$ROWS"

# Every vector directory; within each, every file except a .pem whose .der sibling is copied.
DUT=credentials/development/commissioner_dut
for dir in "$CHIP/$DUT"/*/; do
    name="$(basename "$dir")"
    mkdir -p "$OUT/commissioner_dut/$name"
    for file in "$dir"*; do
        base="$(basename "$file")"
        if [[ "$base" == *.pem && -e "${file%.pem}.der" ]]; then
            continue
        fi
        copy "$DUT/$name/$base" "commissioner_dut/$name/$base"
    done
done

# MARK: - Checks

pem() { openssl x509 -inform der -in "$1" -out "$2"; }
pem "$OUT/dev/Chip-Test-PAA-FFF1-Cert.der" "$WORK/paa.pem"
pem "$OUT/dev/Matter-Development-PAI-FFF1-noPID-Cert.der" "$WORK/pai.pem"
pem "$OUT/dev/Matter-Development-DAC-FFF1-8000-Cert.der" "$WORK/dac.pem"
openssl verify -CAfile "$WORK/paa.pem" -untrusted "$WORK/pai.pem" "$WORK/dac.pem" >/dev/null \
    || { echo "error: the dev DAC does not chain to the test PAA through the dev PAI" >&2; exit 1; }

# The example apps present the fixtured DAC and PAI.
c_array_bytes src/credentials/examples/ExampleDACs.cpp 'kDevelopmentDAC_Cert_FFF1_8000\[' \
    | cmp -s - "$OUT/dev/Matter-Development-DAC-FFF1-8000-Cert.der" \
    || { echo "error: ExampleDACs.cpp FFF1/8000 DAC differs from the fixture" >&2; exit 1; }
c_array_bytes src/credentials/examples/ExamplePAI.cpp 'kDevelopmentPAI_Cert_FFF1\[' \
    | cmp -s - "$OUT/dev/Matter-Development-PAI-FFF1-noPID-Cert.der" \
    || { echo "error: ExamplePAI.cpp FFF1 PAI differs from the fixture" >&2; exit 1; }

# verify_cd <cd.der> <signing cert.der>: the CD carries no signed attributes, so its
# signature covers the eContent octets directly.
verify_cd() {
    local cd="$1" cert="$2" content_offset sig_offset
    content_offset="$(openssl asn1parse -inform der -in "$cd" | awk '/OCTET STRING/ { split($1, f, ":"); print f[1]; exit }')"
    sig_offset="$(openssl asn1parse -inform der -in "$cd" | awk '/OCTET STRING/ { split($1, f, ":"); last = f[1] } END { print last }')"
    openssl asn1parse -inform der -in "$cd" -strparse "$content_offset" -noout -out "$WORK/content.bin"
    openssl asn1parse -inform der -in "$cd" -strparse "$sig_offset" -noout -out "$WORK/sig.bin"
    openssl x509 -inform der -in "$cert" -pubkey -noout > "$WORK/pub.pem"
    openssl dgst -sha256 -verify "$WORK/pub.pem" -signature "$WORK/sig.bin" "$WORK/content.bin" >/dev/null
}
verify_cd "$OUT/cd/Test-CD-FFF1-8000.der" "$OUT/cd/Chip-Test-CD-Cert.der" \
    || { echo "error: the test CD does not verify against the test CD signing certificate" >&2; exit 1; }
verify_cd "$OUT/cd/Example-CD-FFF1.der" "$OUT/cd/CSA_Matter_CD_Signing_Key_001.cert.der" \
    || { echo "error: the example CD does not verify against CSA CD signing key 001" >&2; exit 1; }

# MARK: - SOURCES.md

{
    cat <<EOF
# Attestation fixture sources

Taken from [connectedhomeip]($REPO_URL) tag \`$TAG\`
(commit \`$COMMIT\`), Apache-2.0; see \`NOTICE\` at the package root.
Every file is a byte-for-byte copy of its upstream file, except \`cd/Example-CD-FFF1.der\`,
which holds the bytes of a C array in an upstream source file.
Regenerate with \`Tools/Attestation/fetch-chip-fixtures.sh\`; do not edit by hand.

## Notes

- The private keys here (\`dev/*-Key.der\`, \`cd/Chip-Test-CD-Signing-Key.pem\`, and the
  \`*-Key.der\` and \`paa-Key.pem\` files under \`commissioner_dut/\`) are public test keys
  published upstream for development and certification testing. They are not secrets and
  protect nothing.
- \`dev/\`: the development chain for VID 0xFFF1 / PID 0x8000. The DAC and PAI are the
  ones \`src/credentials/examples/ExampleDACs.cpp\` and \`ExamplePAI.cpp\` compile into the
  example apps (the script checks this). The PAA is \`Chip-Test-PAA-FFF1-Cert.der\` from
  \`paa-root-certs/\`; \`credentials/development/attestation/Chip-Development-PAA-Cert.der\`
  is a different PAA and does not issue the FFF1 PAI.
- \`dev/Chip-Test-PAA-NoVID-Cert.der\`: a test PAA without a VID. It issues the PAI of the
  commissioner DUT vector \`struct_cd_origin_pid_vid_correct\` (VID 0xFFF2), whose CD names a
  DAC origin other than the product's VID.
- \`cd/Test-CD-FFF1-8000.der\`: VID 0xFFF1, PID 0x8000, signed by the "Matter Test CD
  Signing Authority" (\`cd/Chip-Test-CD-Cert.der\`, key \`cd/Chip-Test-CD-Signing-Key.pem\`).
  Taken from the commissioner DUT success case \`struct_dac_cert_version_v3\`.
- \`cd/Example-CD-FFF1.der\`: the CD the example apps present for VID 0xFFF1 (PIDs
  0x8000 to 0x8063), extracted from a C array. It is signed by CSA "Certification
  Declaration Signing Key 001", whose private key is not public.
- \`cd/CSA_Matter_CD_Signing_Key_00{1..5}.cert.der\`: the CSA CD signing certificates. With
  the test CD signing key, these are the six keys \`gCdSigningKeys\` in
  \`src/credentials/attestation_verifier/DefaultDeviceAttestationVerifier.cpp\` trusts.
- \`commissioner_dut/\`: every vector directory. Each file is copied except a \`.pem\` whose
  \`.der\` sibling is copied. The set holds both success and failure cases
  (\`is_success_case\`).

## Files

| Fixture | Upstream path | SHA-256 |
|---|---|---|
EOF
    LC_ALL=C sort "$ROWS"
} > "$OUT/SOURCES.md"

# MARK: - NOTICE

# Apache-2.0 section 4(d): carry upstream's NOTICE. Everything from the heading down is
# regenerated; anything above it is left alone.
NOTICE_FILE="$PACKAGE_ROOT/NOTICE"
HEADING="connectedhomeip ($TAG)"
if [ -f "$NOTICE_FILE" ] && grep -qxF "$HEADING" "$NOTICE_FILE"; then
    KEEP="$(grep -nxF "$HEADING" "$NOTICE_FILE" | head -1 | cut -d: -f1)"
    head -n "$((KEEP - 1))" "$NOTICE_FILE" > "$WORK/NOTICE"
else
    cp "$NOTICE_FILE" "$WORK/NOTICE" 2>/dev/null || : > "$WORK/NOTICE"
    echo >> "$WORK/NOTICE"
fi
{
    cat "$WORK/NOTICE"
    echo "$HEADING"
    echo "$(printf '%*s' ${#HEADING} '' | tr ' ' '-')"
    echo
    cat "$CHIP/NOTICE"
} > "$NOTICE_FILE"

echo "Wrote $(wc -l < "$ROWS" | tr -d ' ') fixtures to $OUT"
