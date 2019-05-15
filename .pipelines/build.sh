#!/bin/bash

cd $CDP_USER_SOURCE_FOLDER_CONTAINER_PATH

go build -o build/server azwaf/cmd/server

exit $?
