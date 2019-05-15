#!/bin/bash

cd $CDP_USER_SOURCE_FOLDER_CONTAINER_PATH

go test azwaf/... -v

exit $?
