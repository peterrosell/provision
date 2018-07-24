#!/usr/bin/env bash

set -e
echo "mode: atomic" > coverage.txt

packages="github.com/digitalrebar/provision,\
github.com/digitalrebar/provision/models,\
github.com/digitalrebar/provision/backend,\
github.com/digitalrebar/provision/backend/index,\
github.com/digitalrebar/provision/midlayer,\
github.com/digitalrebar/provision/frontend,\
github.com/digitalrebar/provision/embedded,\
github.com/digitalrebar/provision/server,\
github.com/digitalrebar/provision/plugin,\
github.com/digitalrebar/provision/cli,\
github.com/digitalrebar/provision/api\
"

if [[ `uname -s` == Darwin ]] ; then
    PATH=`pwd`/bin/darwin/amd64:$PATH
else
    PATH=`pwd`/bin/linux/amd64:$PATH
fi

i=0
for d in $(go list ./... 2>/dev/null | grep -v cmds) ; do
    echo "----------- TESTING $d -----------"
    time go test -race -covermode=atomic -coverpkg=$packages -coverprofile="profile${i}.txt" "$d" || FAILED=true
    i=$((i+1))
done
go run tools/mergeProfiles.go profile*.txt >coverage.txt
rm profile*.txt
if [[ $FAILED ]]; then
    echo "FAILED"
    exit 1
fi
