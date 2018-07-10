package api

var cmdHelper = []byte(`
#!/bin/bash

# To force dpkg on Debian-based distros to play nice.
export DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true

# Force everything to use the C locale to keep things sane
export LC_ALL=C LANGUAGE=C LANG=C

# Make sure we play nice with debugging
export PS4='${BASH_SOURCE}@${LINENO}(${FUNCNAME[0]}): '

# Make sure the scripts are somewhat typo-resistant
set -o pipefail -o errexit
shopt -s nullglob extglob globstar

# Make sure that $PATH is somewhat sane.
fix_path() {
    local -A pathparts
    local part
    local IFS=':'
    for part in $PATH; do
        pathparts["$part"]="true"
    done
    local wanted_pathparts=("/usr/local/bin" "/usr/local/sbin" "/bin" "/sbin" "/usr/bin" "/usr/sbin")
    for part in "${wanted_pathparts[@]}"; do
        [[ ${pathparts[$part]} ]] && continue
        PATH="$part:$PATH"
    done
}
fix_path
unset fix_path

# Figure out what Linux distro we are running on.
export OS_TYPE= OS_VER= OS_NAME=
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_TYPE=${ID,,}
    OS_VER=${VERSION_ID,,}
elif [[ -f /etc/lsb-release ]]; then
    . /etc/lsb-release
    OS_VER=${DISTRIB_RELEASE,,}
    OS_TYPE=${DISTRIB_ID,,}
elif [[ -f /etc/centos-release || -f /etc/fedora-release || -f /etc/redhat-release ]]; then
    for rel in centos-release fedora-release redhat-release; do
        [[ -f /etc/$rel ]] || continue
        OS_TYPE=${rel%%-*}
        OS_VER="$(egrep -o '[0-9.]+' "/etc/$rel")"
        break
    done
    if [[ ! $OS_TYPE ]]; then
        echo "Cannot determine Linux version we are running on!"
        exit 1
    fi
elif [[ -f /etc/debian_version ]]; then
    OS_TYPE=debian
    OS_VER=$(cat /etc/debian_version)
fi
OS_NAME="$OS_TYPE-$OS_VER"

case $OS_TYPE in
    centos|redhat|fedora|rhel|scientificlinux) OS_FAMILY="rhel";;
    debian|ubuntu) OS_FAMILY="debian";;
    *) OS_FAMILY=$OS_TYPE;;
esac

if_update_needed() {
    local timestampref=/tmp/pkg_cache_update
    if [[ ! -f $timestampref ]] || \
           (( ($(stat -c '%Y' "$timestampref") - $(date '+%s')) > 86400 )); then
        touch "$timestampref"
        "$@"
    fi
}

# Install a package
install() {
    local to_install=()
    local pkg
    for pkg in "$@"; do
        to_install+=("$pkg")
    done
    case $OS_FAMILY in
        rhel)
            if_update_needed yum -y makecache
            yum -y install "${to_install[@]}";;
        debian)
            if_update_needed apt-get -y update
            apt-get -y install "${to_install[@]}";;
        alpine)
            if_update_needed apk update
            apk add "${to_install[@]}";;
        *) echo "No idea how to install packages on $OS_NAME"
           exit 1;;
    esac
}

INITSTYLE="sysv"
if which systemctl &>/dev/null; then
    INITSTYLE="systemd"
elif which initctl &>/dev/null; then
    INITSTYLE="upstart"
fi

# Perform service actions.
service() {
    # $1 = service name
    # $2 = action to perform
    local svc="$1"
    shift
    if which systemctl &>/dev/null; then
        systemctl "$1" "$svc.service"
    elif which chkconfig &>/dev/null; then
        case $1 in
            enable) chkconfig "$svc" on;;
            disable) chkconfig "$svc" off;;
            *)  command service "$svc" "$@";;
        esac
    elif which initctl &>/dev/null && initctl version 2>/dev/null | grep -q upstart ; then
        /usr/sbin/service "$svc" "$1"
    elif [[ -f /etc/init/$svc.unit ]]; then
        initctl "$1" "$svc"
    elif which update-rc.d &>/dev/null; then
        case $1 in
            enable|disable) update-rc.d "$svc" "$1";;
            *) "/etc/init.d/$svc" "$1";;
        esac
    elif [[ -x /etc/init.d/$svc ]]; then
        "/etc/init.d/$svc" "$1"
    else
        echo "No idea how to manage services on $OS_NAME"
        exit 1
    fi
}

get_param() {
    # $1 attrib to get.  Attrib will be fetched in the context of the current machine
    local attr
    drpcli machines get "$RS_UUID" param "$1" --aggregate
}

set_param() {
    # $1 = name of the parameter to set
    # $2 = parameter to set.
    #      if $2 == "", then we will read from stdin
    local src="$2"
    if [[ ! $src ]]; then src="-"; fi
    drpcli machines set "$RS_UUID" param "$1" to "$src"
}

__sane_exit() {
    touch "$RS_TASK_DIR/.sane-exit-codes"
}

__exit() {
    __sane_exit
    exit $1
}

exit_incomplete() {
    __exit 128
}

exit_reboot() {
    __exit 64
}

exit_shutdown() {
    __exit 32
}

exit_stop() {
    __exit 16
}

exit_incomplete_reboot() {
    __exit 192
}

exit_incomplete_shutdown() {
    __exit 160
}

addr_port() {
    if [[ $1 =~ ':' ]]; then
        printf '[%s]:%d' "$1" "$2"
    else
        printf '%s:%d' "$1" "$2"
    fi
}

mount_chroot() {
    # $1 = path of chroot to populate with required sub filesystems
    if [[ $(uname -o) != 'GNU/Linux' ]]; then
        echo "Cannot fill out chroot on $(uname -o)"
        exit 1
    fi
    if ! [[ -d $1 ]]; then
        echo "$1 is not a directory!"
        exit 1
    fi
    # We have to have these populated in a chroot for even basic stuff to work.
    (cd "$1" && mkdir -p proc sys dev)
    local d fs
    for d in /proc /sys /dev /sys/firmware/efi/efivars /dev/pts; do
        [[ -d $d ]] || continue
        fs="$(readlink -m "$1$d")"
        fgrep -q " $fs " /proc/self/mounts && continue
        mount --bind "$d" "$1$d"
    done
    # If the chroot is a real root directory, try to mount the filesystems it wants as well.
    if [[ -f $1/etc/fstab ]]; then
        for fs in $(awk '/^(\/dev|UUID=|LABEL=)/ { print length($2), $2, $3 }' "$1/etc/fstab" |sort -n |cut -f2- -d' ' |grep -v ' swap' |cut -f1 -d' '); do
            [[ $fs = / ]] && continue
            fgrep -q "$(readlink -m "$1$fs")" /proc/self/mounts && continue
            chroot "$1" mount "$fs"
        done
    fi
    # Finally, bind-mount the runner dir into the chroot as well.
    fs="$(readlink -m "$1$RS_RUNNER_DIR")"
    fgrep -q " $fs " /proc/self/mounts && return 0
    mkdir -p "$fs"
    mount --bind "$RS_RUNNER_DIR" "$fs"
}

# Unmount all mountpoints in a chroot, possibly including the
# chroot itself.
umount_chroot() {
    # $1 = path of chroot to umount
    if ! [[ -d $1 ]]; then
        echo "$1 is not a directory!"
        exit 1
    fi
    local d
    for d in $(tac /proc/self/mounts |awk "/ \\$1/ {print \$2}"); do
        umount -d -l "$d"
    done
}
`)
