#!/bin/bash

set -e

if ! [[ -d $1 ]]; then
    echo "Cannot find target directory $1"
    exit 1
fi

if ! [[ -f $1/../backend/dataTracker.go ]]; then
    echo "$1 is not in a DigitalRebar Provision checkout"
    exit 1
fi

cd "$1"
mkdir -p assets
cd assets

if [[ -d provisioner ]]; then
    mv provisioner/* .
    rm -rf provisioner
fi

for f in ipxe.efi ipxe.pxe jq bootx64.efi lpxelinux.0 esxi.0 wimboot; do
    [[ -f $f ]] && continue
    echo "Downloading asset for $f"
    case $f in
        ipxe.efi) curl -sfgL http://boot.ipxe.org/ipxe.efi -o ipxe.efi;;
        ipxe.pxe) curl -sfgL http://boot.ipxe.org/undionly.kpxe -o ipxe.pxe;;
        jq)
            curl -sfgL https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64 -o jq
            chmod 755 jq;;
        bootx64.efi)
            curl -sfgL https://rackn-sledgehammer.s3.amazonaws.com/provisioner/elilo-3.16-all.tar.gz -o elilo.tar.gz
            tar xzf elilo.tar.gz ./elilo-3.16-x86_64.efi
            tar xzf elilo.tar.gz ./elilo-3.16-ia32.efi
            tar xzf elilo.tar.gz ./elilo-3.16-ia64.efi
            mv elilo-3.16-ia32.efi bootia32.efi
            mv elilo-3.16-ia64.efi bootia64.efi
            mv elilo-3.16-x86_64.efi bootx64.efi
            rm elilo.tar.gz;;
        lpxelinux.0)
            curl -sfgL https://rackn-sledgehammer.s3.amazonaws.com/provisioner/syslinux-6.03.tar.xz -o syslinux-6.03.tar.xz
            for s in syslinux-6.03/bios/com32/elflink/ldlinux/ldlinux.c32 \
                         syslinux-6.03/bios/core/lpxelinux.0 \
                         syslinux-6.03/bios/com32/modules/pxechn.c32 \
                         syslinux-6.03/bios/com32/lib/libcom32.c32 \
                         syslinux-6.03/bios/com32/libutil/libutil.c32 \
                         syslinux-6.03/bios/com32/chain/chain.c32; do
                tar xOJf syslinux-6.03.tar.xz "$s">"${s##*/}"
            done
            rm -rf syslinux-6.03.tar.xz syslinux-6.03;;
        esxi.0)
            curl -sfgL https://rackn-sledgehammer.s3.amazonaws.com/provisioner/syslinux-3.86.tar.xz -o syslinux-3.86.tar.xz
            tar xOJf syslinux-3.86.tar.xz syslinux-3.86/core/pxelinux.0 > esxi.0.tmp
            mv esxi.0.tmp esxi.0
            rm -rf syslinux-3.86.tar.xz syslinux-3.86;;
        wimboot)
            curl -sfgL https://git.ipxe.org/releases/wimboot/wimboot-2.5.2.tar.bz2 -o wimboot-2.5.2.tar.bz2
            tar xOf wimboot-2.5.2.tar.bz2 wimboot-2.5.2/wimboot > wimboot.tmp
            mv wimboot.tmp wimboot
            rm -rf wimboot-2.5.2.tar.bz2 wimboot-2.5.2;;
        *)
            echo "Unknown provisioner file to test for: $f"
            exit 1;;
    esac
done
