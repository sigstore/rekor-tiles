# Releasing rekor-tiles

## Publishing updated binary and container

This guide assumes that `upstream` references github.com/sigstore/rekor-tiles.

Create and push a new tag. Note that you can't create a tag without creating a release in the GitHub UI, so you'll need to do this locally.

```
git pull upstream main
export RELEASE_TAG=v1.2.3 # Specify version
git tag -s ${RELEASE_TAG} -m "${RELEASE_TAG}"
git push upstream ${RELEASE_TAG}
```

After the tag is pushed, two workflows will kick off:

* [Create release](https://github.com/sigstore/rekor-tiles/actions/workflows/release.yml)
* [Create and publish Docker image](https://github.com/sigstore/rekor-tiles/actions/workflows/build_container.yml)

Once "Create release" finishes, go to [Releases](https://github.com/sigstore/rekor-tiles/releases), select
the latest draft release, and publish it. If the release is pre-1.0, select "Set as a pre-release" before publishing.

## Updating the infrastructure

Update the [Helm chart](https://github.com/sigstore/helm-charts/tree/main/charts/rekor-tiles) to the latest version.
Follow [this example](https://github.com/sigstore/helm-charts/pull/989/).

Get the container digest:

```
crane digest ghcr.io/sigstore/rekor-tiles:v1.2.3 # Specify version
```

Update `charts/rekor-tiles/values.yaml` with the new container version and digest.

Update `charts/rekor-tiles/Chart.yaml`, bumping `version`, `appVersion`, and the image reference.

Run `helm-docs -g charts/rekor-tiles` to update the README.

Create a PR and wait for an oncall engineer to approve and merge. An oncall engineer also needs to
update the chart version on the PGI repo.
