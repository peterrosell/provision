#!/bin/bash
MODS=(normal configfile chain gzio serial http tftp echo sleep test)
case "$1" in
    grubamd64.efi)
        MODS+=(net efinet efi_gop)
        FORMAT=x86_64-efi;;
    grubarm64.efi)
        MODS+=(net efinet efi_gop)
        FORMAT=arm64-efi;;
esac
grub2-mkimage --format=$FORMAT \
              --output=/target/grub2/$1 \
              --prefix=/ \
              --config=/working/grub.cfg \
              "${MODS[@]}"
