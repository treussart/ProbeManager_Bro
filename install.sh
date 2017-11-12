#!/usr/bin/env bash

echo '## Install Bro ##'
# Get args
if [ -z $1 ] || [ $1 == 'dev' ]; then
    arg="dev"
    dest=""
elif [ $1 == 'prod' ]; then
    arg=$1
    if [ -z $2 ]; then
        dest='/usr/local/share'
    else
        dest=$2
    fi
else
    echo 'Bad argument'
    exit 1
fi

config=""
# OSX with brew
if [[ $OSTYPE == *"darwin"* ]]; then
    if brew --version | grep -qw Homebrew ; then
        if ! brew list | grep -qw bro ; then
            brew install bro
        fi
        config="/usr/local/bin/"
    fi
fi
# Debian
if [ -f /etc/debian_version ]; then
    if ! type bro ; then
        apt-get install curl ca-certificates build-essential tcpdump cmake make gcc g++ flex bison libpcap-dev  python-dev swig zlib1g-dev screen tshark apache2 libssl1.0-dev libgeoip-dev wget git
        wget -P /opt https://www.bro.org/downloads/bro-2.5.2.tar.gz
        tar xvf /opt/bro-2.5.2.tar.gz -C /opt
        ( cd /opt/bro-2.5.2 && ./configure )
        ( cd /opt/bro-2.5.2 && make )
        ( cd /opt/bro-2.5.2 && make install )
        export PATH=/usr/local/bro/bin:$PATH
        export LD_LIBRARY_PATH=/usr/local/bro/lib/
        ( cd /usr/local/bin && ln -s /usr/local/bro/bin/bro bro )
        ( cd /usr/local/bin && ln -s /usr/local/bro/bin/broctl broctl )
        # Activer af_packet :
        git clone https://github.com/J-Gras/bro-af_packet-plugin.git /opt/bro-af_packet-plugin/
        ( cd /opt/bro-af_packet-plugin/ && ./configure --bro-dist=/opt/bro-2.5.2 )
        ( cd /opt/bro-af_packet-plugin/ && make )
        ( cd /opt/bro-af_packet-plugin/ && make install )
    fi
    config="/usr/local/bro/bin/"
fi
if [ $arg == 'prod' ]; then
    touch /var/log/suricata/suricata.log
    chmod a+w  /var/log/suricata/suricata.log
    chmod a+r  /var/log/suricata/suricata.log
    echo "[BRO]" >> "$dest"conf.ini
    echo "BRO_BINARY =  $( which bro )" >> "$dest"conf.ini
else
    echo "[BRO]" >> conf.ini
    echo "BRO_BINARY =  $( which bro )" >> conf.ini
fi