#!/bin/bash -e

SIGN=0
VERSION=

while getopts 'sh' opt; do
  case "$opt" in
    s) SIGN=1
      ;;

    ?|h)
      echo "Usage: $(basename $0) [-s] <version>"
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

if [ -z "$1" ]; then
    echo "Usage: $(basename $0) [-s] <version>"
    exit 1
fi

VERSION="$1"
TAG="v${VERSION}"

#Ensure the release is correct
git grep "version = \"${VERSION}\"" || (echo "version mismatch, check Cargo.toml" && false)

if [ "$SIGN" == "1" ]; then
    echo "Creating version tag"
    git tag -s ${TAG} -m "Release \"${VERSION}\""
fi

echo "Creating archives"
git archive --format=tar.gz --prefix kryoptic-${VERSION}/ -o kryoptic-${VERSION}.tar.gz ${TAG}
cargo vendor
tar -czf kryoptic-vendor-${VERSION}.tar.gz vendor

if [ "$SIGN" == "1" ]; then
    echo "Signing archives"
    gpg --armor --detach-sign kryoptic-${VERSION}.tar.gz
    gpg --armor --detach-sign kryoptic-vendor-${VERSION}.tar.gz
fi
