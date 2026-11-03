#!/usr/bin/env bash
# Sign a multi-platform container image pushed by `docker buildx build --push`
# with cosign keyless signing.
#
# Signs the index and each platform manifest by digest, never by tag, so a
# reference pinned to either one verifies. The attestation manifests (SBOM,
# provenance) are not signed on their own: the index signature covers them
# through their digests, and each extra signature costs several seconds of
# Sigstore and registry round trips.
#
# Keyless signing needs an OIDC identity, so this only works in GitHub Actions
# with `id-token: write`.
#
# Usage:
#   sign-image.sh IMAGE METADATA_FILE
#
# Arguments:
#   IMAGE          Image name without tag or digest (e.g. ghcr.io/tinkerbell/tinkerbell).
#   METADATA_FILE  The file `docker buildx build --metadata-file` wrote for the push.

set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 IMAGE METADATA_FILE" >&2
	exit 2
fi
image=$1
metadata_file=$2

digest=$(jq -r '."containerimage.digest"' "${metadata_file}")
if [[ ! "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
	echo "::error::no image digest in ${metadata_file}: ${digest}"
	exit 1
fi

index=$(docker buildx imagetools inspect --raw "${image}@${digest}")
# Not mapfile with process substitution: errexit would not see a jq failure.
platform_digests=$(jq -r '.manifests[] | select(.annotations["vnd.docker.reference.type"] != "attestation-manifest") | .digest' <<<"${index}")

refs=("${image}@${digest}")
for platform_digest in ${platform_digests}; do
	if [[ ! "${platform_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
		echo "::error::unexpected platform manifest digest in ${image}@${digest}: ${platform_digest}"
		exit 1
	fi
	refs+=("${image}@${platform_digest}")
done
if [[ ${#refs[@]} -lt 2 ]]; then
	echo "::error::no platform manifests in ${image}@${digest}"
	exit 1
fi

cosign sign --yes "${refs[@]}"
