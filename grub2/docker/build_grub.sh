#!/bin/bash
case "$1" in
    grubamd64.efi)
        grub2-mkimage --format=x86_64-efi \
                      --output=/target/grub2/$1 \
                      --prefix=/grub \
                      net efinet normal configfile search chain gzio;;
    grubarm64.efi)
        grub2-mkimage --format=arm64-efi \
                      --output=/target/grub2/$1 \
                      --prefix=/grub \
                      net efinet normal configfile search chain gzio;;
esac
