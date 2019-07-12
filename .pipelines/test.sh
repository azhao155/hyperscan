#!/bin/bash

cd $CDP_USER_SOURCE_FOLDER_CONTAINER_PATH

go test -covermode=count -coverprofile=coverage.out azwaf/... -v
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

exit 0
