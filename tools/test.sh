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
github.com/digitalrebar/provision/api,\
github.com/digitalrebar/provision/agent\
"

if [[ `uname -s` == Darwin ]] ; then
    PATH=`pwd`/bin/darwin/amd64:$PATH
else
    PATH=`pwd`/bin/linux/amd64:$PATH
fi

go install github.com/digitalrebar/provision/cmds/drbundler

# Move the files to make coverage better.
mv api/fake_api_server_test.go api/fake_api_server.go
mv midlayer/fake_midlayer_server_test.go midlayer/fake_midlayer_server.go
mv cli/fake_cli_server_test.go cli/fake_cli_server.go
mv agent/fake_agent_server_test.go agent/fake_agent_server.go

i=0
for d in $(go list ./... 2>/dev/null | grep -v cmds) ; do
    echo "----------- TESTING $d -----------"
    time go test -timeout 30m -race -covermode=atomic -coverpkg=$packages -coverprofile="profile${i}.txt" "$d" || FAILED=true
    i=$((i+1))
done
go run tools/mergeProfiles.go profile*.txt >coverage.txt
rm profile*.txt

mv api/fake_api_server.go api/fake_api_server_test.go
mv midlayer/fake_midlayer_server.go midlayer/fake_midlayer_server_test.go
mv cli/fake_cli_server.go cli/fake_cli_server_test.go
mv agent/fake_agent_server.go agent/fake_agent_server_test.go

if [[ $FAILED ]]; then
    echo "FAILED"
    exit 1
fi
