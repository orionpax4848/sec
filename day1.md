Network Recon -
Weaponozaton -
Delivery -
Exploitation -
Installation -XX
Command and Control - 
Actin on Objectives -
- ssh -MS /tmp/jump student@10.50.37.30 # multi plexing
- ssh -S /tmp/jump dummy
- ssh -S /tmp/jump -O forward -D 9050 dummy # sets up forward
for i in {1..254}; do (ping -c 1 192.168.28.$i | grep "bytes from" &); done
sudo proxychains nmap -Pn -sT -T4 -p1-10000 ip 2>/dev/null

sudo apt install nikto -y
