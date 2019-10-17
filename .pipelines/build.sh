#!/bin/bash

cd $CDP_USER_SOURCE_FOLDER_CONTAINER_PATH

./stylechecks.sh
rc1=$?

go build -o build/azwaf azwaf/cmd/server
rc2=$?

if [[ $rc1 != 0 ]] || [[ $rc2 != 0 ]] ; then
    exit 1
fi

exit 0
