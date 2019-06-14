#!/bin/bash

cd $CDP_USER_SOURCE_FOLDER_CONTAINER_PATH

go build -o build/azwaf azwaf/cmd/server
rc1=$?

golint -set_exit_status ./...
rc2=$?

if [[ $rc1 != 0 ]] || [[ $rc2 != 0 ]] ; then
    exit 1
fi

exit 0
