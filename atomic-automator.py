#Tool to help sys admins
#author - Name Here

#Import our modules
import sys
import os
import subprocess
import time

#Create a banner
banner = """
====================================================================================================================================================================

     ___   .___________.  ______   .___  ___.  __    ______           ___      __    __  .___________.  ______   .___  ___.      ___   .___________.  ______   .______      
    /   \  |           | /  __  \  |   \/   | |  |  /      |         /   \    |  |  |  | |           | /  __  \  |   \/   |     /   \  |           | /  __  \  |   _  \     
   /  ^  \ `---|  |----`|  |  |  | |  \  /  | |  | |  ,----' ______ /  ^  \   |  |  |  | `---|  |----`|  |  |  | |  \  /  |    /  ^  \ `---|  |----`|  |  |  | |  |_)  |    
  /  /_\  \    |  |     |  |  |  | |  |\/|  | |  | |  |     |______/  /_\  \  |  |  |  |     |  |     |  |  |  | |  |\/|  |   /  /_\  \    |  |     |  |  |  | |      /     
 /  _____  \   |  |     |  `--'  | |  |  |  | |  | |  `----.      /  _____  \ |  `--'  |     |  |     |  `--'  | |  |  |  |  /  _____  \   |  |     |  `--'  | |  |\  \----.
/__/     \__\  |__|      \______/  |__|  |__| |__|  \______|     /__/     \__\ \______/      |__|      \______/  |__|  |__| /__/     \__\  |__|      \______/  | _| `._____|
                                                                                                                                                                            

================================================================================================================================================================================

================== A Tool for Adversarial Emulation on Linux ========================
Please Select An ATT&CK Tactic & Technique
======================================================================================
[1] Exection
[2] Persistance
[3] Privilege-Escalation
[4] Defense-Evasion
[5] Credential-Access
[6] Discovery
[7] Exfiltration
[8] Command & Control
[9] Be a Bad Mother (Run them all)
[10] Clean this bad mother up (Remove all atrifacts)
[99] Exit
======================================================================================
"""
loop=True
while loop:
    print(banner)
    x = input ("Select An Option:")
 #Exection   
    if x == 1:
        os.system("echo So long, and thanks for all the fish! >> /tmp/art-fish.txt")
        time.sleep(1)
        print "Execting T1059 - Command Line Interface"
        os.system("echo Hello from Atomic Red Team >> /tmp/atomic.log")
        print "Exectuing T1168 - Local Job Scheduling"
        time.sleep(1)
        print "Executing T1064 - Create & Execute Bash Script"
        os.system("echo echo Hello from the Atomic Red Team >> /tmp/art.sh")
        os.system ("echo ping -c 4 8.8.8.8 >> /tmp/art.sh")
        os.system("chmod +x /tmp/art.sh")
        os.system("bash /tmp/art.sh")
        time.sleep(1)
        os.system("clear")
        time.sleep(1)
        print "Executing - T1153 - Execute Script using Source"
        os.system("echo echo Hello from the Atomic Red Team >> /tmp/art1.sh")
        os.system("chmod +x /tmp/art1.sh")
        os.system("source /tmp/art1.sh")
        time.sleep(1)
        print "ALL DONE Execution - RETURNING TO MAIN MENU"
        time.sleep(2)
#Persistance 
    elif x == 2:
        print "Executing T1156 - BashRC"
        os.system("echo Hello Atomic-Test >> ~/.bashrc")
        time.sleep(1)
        print "Executing - T1136 - Create Account"
        os.system("useradd -M -N -r -s /bin/bash atomicred")
        time.sleep(1)
        print "Executing T1158 - Hidden Files & Directories"
        os.system("mkdir .hidden-directory")
        os.system("echo 'this file is hidden' >> .hidden-directory/.hidden-file")
        time.sleep(1)
        print "Executing T1168 - Local Job Scheduling"
        os.system("echo 'ATOMICTEST' >> /etc/cron.daily/atomicdaily")
        print "Executing T1501 - Systemd Service"
        os.system("/bin/touch /tmp/art-systemd-execstart-marker")
        os.system("clear")
        print "ALL DONE Persistance - RETURNING TO MAIN MENU"
        time.sleep(1)
#PrivEscalation  
    elif x == 3:
        print "Executing T1166 - Setuid and Setgid"
        os.system("wget -P /tmp/ https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1166/hello.c")
        #Modify downloaded hello demo to only sleep for 5 Seconds
        with open('/tmp/hello.c', 'r') as file :
            filedata = file.read()
            filedata = filedata.replace ('60', '5')
        with open ('/tmp/hello.c', 'w') as file:
            file.write(filedata)
        os.system("gcc /tmp/hello.c -o /tmp/hello")
        os.system("sudo chown root /tmp/hello")
        os.system("sudo chmod u+s /tmp/hello")
        os.system("/tmp/./hello")
        time.sleep(1)
        os.system("clear")
        print "ALL DONE Privilege Escalation - RETURNING TO MAIN MENU"
        time.sleep(2)
        os.system("clear")
 #Defense Evasion
    elif x == 4:
        print "Executing T1009 - Binary Padding"
        os.system("touch /tmp/pad.txt")
        os.system("dd if=/dev/zero bs=1 count=1 >> /tmp/pad.txt")
        time.sleep(1)
        print ("Executing T1146 - Clear Command History")
        os.system("rm ~/.bash_history")
        time.sleep(1)
        print ("Executing T1089 - Disabling Security Tools")
        print ("Stopping IPTables")
        os.system("service iptables stop")
        time.sleep(1)
        print ("Executing T1107 - File Deletion")
        os.system("rm -rf /tmp/art1.sh")
#CredAccess
    elif x == 5:
        print ("Executing T1040 - Network Sniffing")
        os.system("tcpdump -c 5 -i en0 >> /tmp/loot.txt")
        #You will need to edit the NIC according toyour OS
        time.sleep(1)
        print "Executing T1139 - Bash History"
        os.system("cat ~/.bash_history | grep -e '-p ' -e 'pass' -e 'ssh' >> /tmp/loot.txt")
        time.sleep(1)
        print ("Executing T1145 - Private Keys")
        os.system("find / -name id_rsa >> /tmp/loot.txt")
        os.system("find / -name id_dsa >> /tmp/loottxt")
        time.sleep(1)
#Discovery
    elif x == 6:
        print ("Executing T1087 - Account Discovery")
        os.system("cat /etc/passwd >> /tmp/loot.txt")
        os.system("cat /etc/sudoers >> /tmp/loot.txt")
        os.system("grep 'x:0:' /etc/passwd >> /tmp/loot.txt")
        os.system("username=$(echo $HOME | awk -F'/' '{print $3}') && lsof -u $username >> /tmp/users.txt")
        print "Executing T1139 - Bash History"
        os.system("cat ~/.bash_history | grep -e '-p ' -e 'pass' -e 'ssh' >> /tmp/loot.txt")
        os.system("find / -name id_rsa >> /tmp/rsa.txt")
        os.system("find / -name id_dsa >> /tmp/dsa.txt")
        os.system("id >> /tmp/loot.txt")
        time.sleep(1)
        print ("Executing T1217 - Browser Bookmark Discovery")
        os.system("find / -path *.mozilla/firefox/*/places.sqlite -exec echo {} >> /tmp/firefox-bookmarks.txt \;")
        print ("Executing T1083 - File and Directory Discovery")
        os.system("cat /etc/mtab >> /tmp/loot.txt")
        time.sleep(1)
        print ("Executing T1046 - Network Service Scanning")
        os.system("nc -nv 192.168.11.1 80 >> /tmp/loot.txt")
        print("Executing T1201 - Password Policy Discovery")
        os.system("cat /etc/security/pwquality.conf >> /tmp/loot.txt")
        os.system("cat /etc/login.defs >> /tmp/loot.txt")
        time.sleep(1)
        print ("Executing T1069 - Permission Groups Discovery")
        os.system("groups >> /tmp/loot.txt")
        time.sleep(1)
        print("Executing T1057 - Process Discovery")
        os.system("ps >> /tmp/loot.txt")
        os.system("ps aux >> /tmp/loot.txt")
        time.sleep(1)
        print("Executing T1018 - Remote System Discovery")
        os.system("arp -a | grep -v '^?' >> /tmp/loot.txt")
        time.sleep(1)
        #You can edit this to match your IP address and how many host you wish to scan
        os.system ("for ip in $(seq 1 10); do ping -c 1 192.168.11.$ip -o; [ $? -eq 0 ] && echo 192.168.11.$ip UP || : ; done >> /tmp/loot.txt")
        time.sleep(1)
        print("Executing T1082 - System Information Discovery")
        os.system("uname -a >> /tmp/loot.txt")
        os.system("cat /etc/redhat-release >> /tmp/loot.txt")
        time.sleep(1)
        print("Executing T1016 - System Network Configuration Discovery")
        os.system("arp -a >> /tmp/loot.txt")
        os.system("ifconfig >> /tmp/loot.txt")
        time.sleep(1)
        print("Executing T1049 - System Network Connections Discovery")
        os.system("who -a >> /tmp/loot.txt")
        time.sleep(1)
        print("Executing T1033 - System Owner/User Discovery")
        os.system("users >> /tmp/loot.txt")
        time.sleep(2)
#Exfil
    elif x == 7:
        print ("Executing T1002 - Data Compressed")
        os.system("gzip -f /tmp/loot.txt")
        time.sleep(1)
        print("Executing T1022 - Data Encrypted")
        os.system("zip --password demopass /tmp/victim-files.zip /tmp/loot.txt)
        time.sleep(1)
        print("Executing T1030 - Data Transfer Size Limits")
        os.system("cd /tmp/")
        os.system("dd if=/dev/urandom of=/tmp/victim-whole-file bs=25M count=1")
        os.system("split -b 5000000 /tmp/victim-whole-file")
        time.sleep(2)
#c&c
    elif x == 8
        print ("Executing T1132 - Data Encoding")
        os.system("echo -n 555-555-5555 | base64 >> loot.txt")
        time.sleep(1)
#atomicbomb
    elif x == 9
        os.system("echo So long, and thanks for all the fish! >> /tmp/art-fish.txt")
        time.sleep(1)
        print "Execting T1059 - Command Line Interface"
        os.system("echo Hello from Atomic Red Team >> /tmp/atomic.log")
        print "Exectuing T1168 - Local Job Scheduling"
        time.sleep(1)
        print "Executing T1064 - Create & Execute Bash Script"
        os.system("echo echo Hello from the Atomic Red Team >> /tmp/art.sh")
        os.system ("echo ping -c 4 8.8.8.8 >> /tmp/art.sh")
        os.system("chmod +x /tmp/art.sh")
        os.system("bash /tmp/art.sh")
        time.sleep(1)
        os.system("clear")
        time.sleep(1)
        print "Executing - T1153 - Execute Script using Source"
        os.system("echo echo Hello from the Atomic Red Team >> /tmp/art1.sh")
        os.system("chmod +x /tmp/art1.sh")
        os.system("source /tmp/art1.sh")
        time.sleep(1)
        print "ALL DONE - RETURNING TO MAIN MENU"
        time.sleep(3)
        print "Executing T1156 - BashRC"
        os.system("echo Hello Atomic-Test >> ~/.bashrc")
        time.sleep(1)
        print "Executing - T1136 - Create Account"
        os.system("useradd -M -N -r -s /bin/bash atomicred")
        time.sleep(1)
        print "Executing T1158 - Hidden Files & Directories"
        os.system("mkdir .hidden-directory")
        os.system("echo 'this file is hidden' >> .hidden-directory/.hidden-file")
        time.sleep(1)
        print "Executing T1168 - Local Job Scheduling"
        os.system("echo 'ATOMICTEST' >> /etc/cron.daily/atomicdaily")
        print "Executing T1501 - Systemd Service"
        os.system("/bin/touch /tmp/art-systemd-execstart-marker")
        os.system("clear")
        print "Executing T1166 - Setuid and Setgid"
        os.system("wget -P /tmp/ https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1166/hello.c")
        #Modify downloaded hello demo to only sleep for 5 Seconds
            with open('/tmp/hello.c', 'r') as file :
            filedata = file.read()
            filedata = filedata.replace ('60', '5')
            with open ('/tmp/hello.c', 'w') as file:
            file.write(filedata)
        os.system("gcc /tmp/hello.c -o /tmp/hello")
        os.system("sudo chown root /tmp/hello")
        os.system("sudo chmod u+s /tmp/hello")
        os.system("/tmp/./hello")
        time.sleep(1)
        os.system("clear")
        print "ALL DONE Privilege Escalation - RETURNING TO MAIN MENU"
        time.sleep(2)
        os.system("clear")
        print "Executing T1009 - Binary Padding"
        os.system("touch /tmp/pad.txt")
        os.system("dd if=/dev/zero bs=1 count=1 >> /tmp/pad.txt")
        time.sleep(1)
        print ("Executing T1146 - Clear Command History")
        os.system("rm ~/.bash_history")
        time.sleep(1)
        print ("Executing T1089 - Disabling Security Tools")
        print ("Stopping IPTables")
        os.system("service iptables stop")
        time.sleep(1)
        print ("Executing T1107 - File Deletion")
        os.system("rm -rf /tmp/art1.sh")
        print ("Executing T1040 - Network Sniffing")
        os.system("tcpdump -c 5 -i en0 >> /tmp/loot.txt")
        #You will need to edit the NIC according toyour OS
        time.sleep(1)
        print "Executing T1139 - Bash History"
        os.system("cat ~/.bash_history | grep -e '-p ' -e 'pass' -e 'ssh' >> /tmp/loot.txt")
        time.sleep(1)
        print ("Executing T1145 - Private Keys")
        os.system("find / -name id_rsa >> /tmp/loot.txt")
        os.system("find / -name id_dsa >> /tmp/loottxt")
        time.sleep(1)
        print ("Executing T1087 - Account Discovery")
        os.system("cat /etc/passwd >> /tmp/loot.txt")
        os.system("cat /etc/sudoers >> /tmp/loot.txt")
        os.system("grep 'x:0:' /etc/passwd >> /tmp/loot.txt")
        os.system("username=$(echo $HOME | awk -F'/' '{print $3}') && lsof -u $username >> /tmp/users.txt")
        print "Executing T1139 - Bash History"
        os.system("cat ~/.bash_history | grep -e '-p ' -e 'pass' -e 'ssh' >> /tmp/loot.txt")
        os.system("find / -name id_rsa >> /tmp/rsa.txt")
        os.system("find / -name id_dsa >> /tmp/dsa.txt")
        os.system("id >> /tmp/loot.txt")
        time.sleep(1)
        print ("Executing T1217 - Browser Bookmark Discovery")
        os.system("find / -path *.mozilla/firefox/*/places.sqlite -exec echo {} >> /tmp/firefox-bookmarks.txt \;")
        print ("Executing T1083 - File and Directory Discovery")
        os.system("cat /etc/mtab >> /tmp/loot.txt")
        time.sleep(1)
        print ("Executing T1046 - Network Service Scanning")
        os.system("nc -nv 192.168.11.1 80 >> /tmp/loot.txt")
        print("Executing T1201 - Password Policy Discovery")
        os.system("cat /etc/security/pwquality.conf >> /tmp/loot.txt")
        os.system("cat /etc/login.defs >> /tmp/loot.txt")
        time.sleep(1)
        print ("Executing T1069 - Permission Groups Discovery")
        os.system("groups >> /tmp/loot.txt")
        time.sleep(1)
        print("Executing T1057 - Process Discovery")
        os.system("ps >> /tmp/loot.txt")
        os.system("ps aux >> /tmp/loot.txt")
        time.sleep(1)
        print("Executing T1018 - Remote System Discovery")
        os.system("arp -a | grep -v '^?' >> /tmp/loot.txt")
        time.sleep(1)
        #You can edit this to match your IP address and how many host you wish to scan
        os.system ("for ip in $(seq 1 10); do ping -c 1 192.168.11.$ip -o; [ $? -eq 0 ] && echo 192.168.11.$ip UP || : ; done >> /tmp/loot.txt")
        time.sleep(1)
        print("Executing T1082 - System Information Discovery")
        os.system("uname -a >> /tmp/loot.txt")
        os.system("cat /etc/redhat-release >> /tmp/loot.txt")
        time.sleep(1)
        print("Executing T1016 - System Network Configuration Discovery")
        os.system("arp -a >> /tmp/loot.txt")
        os.system("ifconfig >> /tmp/loot.txt")
        time.sleep(1)
        print("Executing T1049 - System Network Connections Discovery")
        os.system("who -a >> /tmp/loot.txt")
        time.sleep(1)
        print("Executing T1033 - System Owner/User Discovery")
        os.system("users >> /tmp/loot.txt")
        time.sleep(2)
        print ("Executing T1002 - Data Compressed")
        os.system("gzip -f /tmp/loot.txt")
        time.sleep(1)
        print("Executing T1022 - Data Encrypted")
        os.system("zip --password demopass /tmp/victim-files.zip /tmp/loot.txt)
        time.sleep(1)
        print("Executing T1030 - Data Transfer Size Limits")
        os.system("cd /tmp/")
        os.system("dd if=/dev/urandom of=/tmp/victim-whole-file bs=25M count=1")
        os.system("split -b 5000000 /tmp/victim-whole-file")
        time.sleep(2)
        print ("Executing T1132 - Data Encoding")
        os.system("echo -n 555-555-5555 | base64 >> loot.txt")
        time.sleep(1)
