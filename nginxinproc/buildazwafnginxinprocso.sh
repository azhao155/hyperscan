#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: ./buildazwafnginxinprocso.sh /path/to/nginxsourcetree"
fi

rm -f /tmp/azwafnginx
ln -s $1 /tmp/azwafnginx
go build -tags=nginxinproc -buildmode=c-shared -o azwafnginxinproc.so azwaf/nginxinproc && echo "Built azwafnginxinproc.so"
rm -f /tmp/azwafnginx
rm -f azwafnginxinproc.h
