#!/usr/bin/env bash

set -e

[[ $GOPATH ]] || export GOPATH="$HOME/go"
fgrep -q "$GOPATH/bin" <<< "$PATH" || export PATH="$PATH:$GOPATH/bin"

[[ -d "$GOPATH/src/github.com/digitalrebar/provision" ]] || go get github.com/digitalrebar/provision

BLD="$GOPATH/src/github.com/digitalrebar/provision"
cd $BLD
if ! which go &>/dev/null; then
        echo "Must have go installed"
        exit 255
fi

# Work out the GO version we are working with:
GO_VERSION=$(go version | awk '{ print $3 }' | sed 's/go//')
WANTED_VER=(1 10)
if ! [[ "$GO_VERSION" =~ ([0-9]+)\.([0-9]+) ]]; then
    echo "Cannot figure out what version of Go is installed"
    exit 1
elif ! (( ${BASH_REMATCH[1]} > ${WANTED_VER[0]} || ${BASH_REMATCH[2]} >= ${WANTED_VER[1]} )); then
    echo "Go Version needs to be 1.10 or higher: currently $GO_VERSION"
    exit -1
fi

for tool in go-bindata swagger glide; do
    which "$tool" &>/dev/null && continue
    case $tool in
        go-bindata) go get -u github.com/jteeuwen/go-bindata/...;;
        swagger)    go get -u github.com/go-swagger/go-swagger/cmd/swagger;;
        glide)
            go get -v github.com/Masterminds/glide
            (cd "$GOPATH/src/github.com/Masterminds/glide" && git checkout tags/v0.12.3 && go install);;
        *) echo "Don't know how to install $tool"; exit 1;;
    esac
done

# FIX SWAGGER - this is still why we can't have nice things.
OLDPWD=`pwd`
cd ../../go-swagger/go-swagger
git fetch
git checkout 0.12.0
go install github.com/go-swagger/go-swagger/cmd/swagger
cd $OLDPWD

set +e
. tools/version.sh
set -e

export CGO_ENABLED=0

echo "Version = $Prepart$MajorV.$MinorV.$PatchV$Extra-$GITHASH"

export VERFLAGS="-s -w \
          -X github.com/digitalrebar/provision.RSMajorVersion=$MajorV \
          -X github.com/digitalrebar/provision.RSMinorVersion=$MinorV \
          -X github.com/digitalrebar/provision.RSPatchVersion=$PatchV \
          -X github.com/digitalrebar/provision.RSExtra=$Extra \
          -X github.com/digitalrebar/provision.RSPrePart=$Prepart \
          -X github.com/digitalrebar/provision.BuildStamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` \
          -X github.com/digitalrebar/provision.GitHash=$GITHASH"

glide install
rm -rf client genmodels embedded/assets/swagger.json
go generate embedded/assets.go

# Update cli docs if needed. - does change date.
go build -o drpcli-docs cmds/drpcli-docs/drpcli-docs.go

# Put the drbundler tool in place.
go install github.com/digitalrebar/provision/cmds/drbundler

# set our arch:os build pairs to compile for
builds="amd64:linux amd64:darwin amd64:windows arm64:linux arm:7:linux"

# anything on command line will override our pairs listed above
[[ $* ]] && builds="$*"

for build in ${builds}; do
  (
    os=${build##*:}
    arch=${build%:*}
    export GOARM=""

    if [[ "$arch" =~ ^arm:[567]$ ]]
    then
      ver=${arch##*:}
      arch=${arch%:*}
      export GOARM=$ver
      ver_part=" (v$ver)"
      binpath="bin/$os/${arch}_v${GOARM}"
    else
      ver_part=""
      binpath="bin/$os/$arch"
    fi

    if [[ "$os" == "windows" ]] ; then
        ext=".exe"
    else
        ext=""
    fi

    export GOOS="$os" GOARCH="$arch"
    echo "Building binaries for ${arch}${ver_part} ${os} (staging to: '$BLD/$binpath')"
    mkdir -p "$binpath"
    go build -ldflags "$VERFLAGS" -o "$binpath/drpcli${ext}" cmds/drpcli/drpcli.go
    go build -ldflags "$VERFLAGS" -o "$binpath/dr-provision${ext}" cmds/dr-provision/dr-provision.go
    go generate cmds/incrementer/incrementer.go
    go build -ldflags "$VERFLAGS" -o "$binpath/incrementer${ext}" cmds/incrementer/incrementer.go cmds/incrementer/content.go
    go build -ldflags "$VERFLAGS" -o "$binpath/drbundler${ext}" cmds/drbundler/drbundler.go

    cp tools/drpjoin "$binpath/drpjoin"
    chmod +x "$binpath/drpjoin"
  )
done

echo "To run tests, run: tools/test.sh"
