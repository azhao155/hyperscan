#!/bin/bash

cd $CDP_USER_SOURCE_FOLDER_CONTAINER_PATH

go build -o build/azwaf azwaf/cmd/server

exit $?
