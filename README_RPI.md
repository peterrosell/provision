# Install Digital Rebar on a Raspberry Pi

Follow raspbian's standard guide to install it on a SD card.

## Change default password

``` bash
passwd pi
```

## Install docker

Run the following commands as `root`

``` bash
echo "deb [arch=armhf] https://download.docker.com/linux/raspbian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list
apt update
apt-get install     apt-transport-https     ca-certificates     curl     gnupg2     software-properties-common
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
apt-key fingerprint 0EBFCD88
apt-get install docker-ce docker-ce-cli containerd.io
docker version
```

## Start container

1. Provide key and cert for this servers web server.

2. Update the static-ip to match the host's IP.

Start the docker container.

``` bash
sudo docker run -it --rm \
    --name drp \
    --read-only \
    -p 8080:8080 \
    -p 8091:8091 \
    -p 8092:8092 \
    -p 69:1069/udp \
    -p 67:1067/udp \
    -p 4011:4011 \
    -v $PWD/drp-data:/provision/drp-data:z \
    -v $PWD/drp-data/server.key:/server.key:ro \
    -v $PWD/drp-data/server.crt:/server.crt:ro \
    provision:latest-armv7 \
        --tftp-port=1069 \
        --dhcp-port=1067 \
        --static-ip=192.168.1.10 \
        --force-static

```
