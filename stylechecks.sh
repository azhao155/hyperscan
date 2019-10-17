#!/bin/bash

# Ensure all .go files are just LF line terminators
if find . -name "*.go" -type f -exec file {} \; | grep "CRLF line terminators" > /dev/null ; then
    echo "There are .go files with CRLF line terminators:"
    find . -name "*.go" -type f -exec file {} \; | grep "CRLF line terminators"
    exit 1
fi

golint -set_exit_status ./...
if [[ $? != 0 ]] ; then
    exit 1
fi

exit 0
