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

#Ensure the release is correct
git grep "version = \"${VERSION}\"" >/dev/null || (echo "version mismatch, check Cargo.toml" && false)
git grep "\[${VERSION}\]" CHANGELOG.md >/dev/null || (echo "missing version from CHANGELOG.md?" && false)
git grep "^Version:.*${VERSION}" packaging/kryoptic.spec >/dev/null|| (echo "version mismatch in packaging files" && false)

if [ "$SIGN" == "1" ]; then
    echo "Creating version tag"
    TAG="v${VERSION}"
    git tag -s ${TAG} -m "Release \"${VERSION}\""
else
    TAG="HEAD"
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
