# home-assistant-mcp
Another Fluffin HA MCP

## Verify the image

Releases publish `ghcr.io/hotpheex/home-assistant-mcp` for amd64 and arm64, tagged `X.Y.Z` and `X.Y` (there is no `latest`). Each image carries SLSA build provenance signed in the release workflow. Check it before you run a tag:

```sh
gh attestation verify oci://ghcr.io/hotpheex/home-assistant-mcp:0.1.0 \
  --repo hotpheex/home-assistant-mcp \
  --signer-workflow hotpheex/home-assistant-mcp/.github/workflows/release.yml
```

Then deploy by the digest it verified, not by the tag. The SBOM is attached to the image:

```sh
docker buildx imagetools inspect ghcr.io/hotpheex/home-assistant-mcp:0.1.0 --format '{{ json .SBOM }}'
```

The image runs as UID 65532 and works with a read-only root filesystem (`docker run --read-only`, or `readOnlyRootFilesystem: true` in Kubernetes).
