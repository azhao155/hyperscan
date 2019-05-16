#!/bin/bash

cd $CDP_USER_SOURCE_FOLDER_CONTAINER_PATH

go mod download 2>&1

exit $?
