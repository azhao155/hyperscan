#!/bin/bash

cd $CDP_USER_SOURCE_FOLDER_CONTAINER_PATH

go test -covermode=count -coverprofile=coverage.out azwaf/...
rc1=$?

echo
echo
echo Code coverage
echo =============
echo
go tool cover -func=coverage.out

if [[ $rc1 != 0 ]] ; then
    exit 1
fi

# This ensures that non-test code does not refer to code in _test.go files
go build azwaf/...
rc2=$?
if [[ $rc2 != 0 ]] ; then
    exit 1
fi

exit 0
