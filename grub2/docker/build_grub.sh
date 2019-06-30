#!/bin/bash
MODS=(normal
      cat
      configfile
      chain
      gzio
      serial
      http
      tftp
      echo
      sleep
      test
      part_msdos
      part_gpt
      fat
      ext2
      xfs
      search
      regexp
      reboot
      all_video
      net)
case "$1" in
    grubamd64.efi)
        MODS+=(efinet)
        FORMAT=x86_64-efi;;
    grubarm64.efi)
        MODS+=(efinet)
        FORMAT=arm64-efi;;
    grubpc.bin)
        MODS+=(pxe pxechain)
        FORMAT=i386-pc;;
esac
grub2-mkimage --format=$FORMAT \
              --output=/target/grub2/$1 \
              --prefix=/ \
              --config=/working/grub.cfg \
              "${MODS[@]}"
