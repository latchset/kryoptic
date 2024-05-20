#!/bin/bash

CODESPELL="codespell --ignore-words-list=sorce,clen,ot"

result=0
echo "Running codespell on source code..."
$CODESPELL --skip **/bindings.rs src || result=1

# assuming the main branch is there
for COMMIT in $(git rev-list main..); do
	echo "Running codespell on commit message of $COMMIT..."
	git show --format=%B -s "$COMMIT" | $CODESPELL - || result=1
done

exit $result
