FROM centos:latest
MAINTAINER Rackn Team <eng@rackn.com>
ENV LC_ALL=C
WORKDIR /working
ADD http://mirror.centos.org/altarch/7/os/aarch64/Packages/grub2-efi-aa64-2.02-0.65.el7.centos.2.aarch64.rpm .
ADD http://mirror.centos.org/altarch/7/os/aarch64/Packages/grub2-efi-aa64-modules-2.02-0.65.el7.centos.2.noarch.rpm .
ADD http://mirror.centos.org/centos/7/os/x86_64/Packages/grub2-efi-x64-2.02-0.65.el7.centos.2.x86_64.rpm .
ADD http://mirror.centos.org/centos/7/os/x86_64/Packages/grub2-efi-x64-modules-2.02-0.65.el7.centos.2.noarch.rpm .
RUN yum -y install rpm2cpio grub2-tools-extra
RUN for r in *.rpm; do rpm2cpio < "$r" |(cd /; cpio -idum); done
COPY build_grub.sh /bin/build_grub.sh
COPY grub.cfg grub.cfg
RUN chmod 755 /bin/build_grub.sh
