#!/bin/bash -e

if [ -z "$1" ]; then
    echo "Please provide the release version"
fi

VERSION="$1"
TAG="v${VERSION}"

#Ensure the release is correct
git grep "version = \"${VERSION}\"" || (echo "version mismatch, check Cargo.toml" && false)

echo "Creating version tag"
git tag -s ${TAG} -m "Release \"${VERSION}\""

echo "Creating archives"
git archive --prefix kryoptic-${VERSION}/ -o kryoptic-${VERSION}.tar.xz ${TAG}
cargo vendor
tar --transform "s#^vendor#kryoptic-${VERSION}/vendor#" -czf kryoptic-vendor-${VERSION}.tar.xz vendor

echo "Signing archives"
gpg --armor --detach-sign kryoptic-${VERSION}.tar.xz
gpg --armor --detach-sign kryoptic-vendor-${VERSION}.tar.xz
