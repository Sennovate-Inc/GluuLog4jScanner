#!/usr/bin/env python
import os
import time
import datetime
import sys
from colorama import init
from termcolor import colored
import argparse

parser = argparse.ArgumentParser(usage='''python log4jscanner.py \n
Description:
Python tool to scan the Gluu container for vulnerable log4j files, and patch the vulnerable files using the official Gluu log4j patch script.\n
Note: 
Run the script inside the Gluu container only.\n''')
parser.add_argument("-r","--revert",action="store_true",help="Use to revert back the changes made by script")
args = parser.parse_args()



patched_versions=["2.3.2", "2.12.4", "2.17.1", "2.17.0", "2.12.3", "2.3.1"]
patched_files=0
vulnerable_files=0
def check_services(): 
    oxauth=(os.popen("systemctl is-active oxauth").read()).replace("\n","")
    identity=(os.popen("systemctl is-active identity").read()).replace("\n","")
    idp=(os.popen("systemctl is-active idp").read()).replace("\n","")
    casa=(os.popen("systemctl is-active casa").read()).replace("\n","")
    fido=(os.popen("systemctl is-active fido2").read()).replace("\n","")
    scim=(os.popen("systemctl is-active scim").read()).replace("\n","")
    return oxauth,identity,idp,casa,fido,scim

def scan_oxauth():
    oxauth_log4j_version=(os.popen("jar tf /opt/gluu/jetty/oxauth/webapps/oxauth.war| grep WEB-INF/lib/log4j").read())
    list_oxauth_log4j_version = list(oxauth_log4j_version.split("\n"))
    for i in range(len(list_oxauth_log4j_version)-1):
        os.popen("jar xvf /opt/gluu/jetty/oxauth/webapps/oxauth.war " + list_oxauth_log4j_version[i]+" ")
        time.sleep(0.5)
        version=((os.popen("unzip -p "+list_oxauth_log4j_version[i]+" META-INF/MANIFEST.MF| sed -n -e 's/^.*Log4jReleaseVersion://p'").read()).replace(" ","")).replace("\n","")
        
        if bool(version):
            for j in range(len(patched_versions)):   
                if version == patched_versions[j]:
                    result="NOT VULNERABLE"
                    text_color="green"
                    bg_color="on_grey"
                    break
                else:
                    result="VULNERABLE" 
                    text_color="white"
                    bg_color="on_red"
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+" /opt/gluu/jetty/oxauth/webapps/oxauth.war ==> "+list_oxauth_log4j_version[i]+" | "+colored(result, text_color, bg_color))
            if result =="NOT VULNERABLE":
                global patched_files
                patched_files=patched_files+1
            if result =="VULNERABLE":
                global vulnerable_files
                vulnerable_files=vulnerable_files+1
    os.popen("rm -rf WEB-INF")

def scan_identity():
    identity_log4j_version=(os.popen("jar tf /opt/gluu/jetty/identity/webapps/identity.war| grep WEB-INF/lib/log4j").read())
    list_identity_log4j_version = list(identity_log4j_version.split("\n"))
    for i in range(len(list_identity_log4j_version)-1):
        os.popen("jar xvf /opt/gluu/jetty/identity/webapps/identity.war " + list_identity_log4j_version[i]+" ")
        time.sleep(0.5)
        version=((os.popen("unzip -p "+list_identity_log4j_version[i]+" META-INF/MANIFEST.MF| sed -n -e 's/^.*Log4jReleaseVersion://p'").read()).replace(" ","")).replace("\n","")
        if bool(version):
            for j in range(len(patched_versions)):   
                if version == patched_versions[j]:
                    result="NOT VULNERABLE"
                    text_color="green"
                    bg_color="on_grey"
                    break
                else:
                    result="VULNERABLE" 
                    text_color="white"
                    bg_color="on_red"
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+" /opt/gluu/jetty/identity/webapps/identity.war ==> "+list_identity_log4j_version[i]+" | "+colored(result, text_color, bg_color))
            if result =="NOT VULNERABLE":
                global patched_files
                patched_files=patched_files+1
            if result =="VULNERABLE":
                global vulnerable_files
                vulnerable_files=vulnerable_files+1
    os.popen("rm -rf WEB-INF")

def scan_idp():
    idp_log4j_version=(os.popen("jar tf /opt/gluu/jetty/idp/webapps/idp.war| grep WEB-INF/lib/log4j").read())
    list_idp_log4j_version = list(idp_log4j_version.split("\n"))
    for i in range(len(list_idp_log4j_version)-1):
        os.popen("jar xvf /opt/gluu/jetty/idp/webapps/idp.war " + list_idp_log4j_version[i]+" ")
        time.sleep(0.5)
        version=((os.popen("unzip -p "+list_idp_log4j_version[i]+" META-INF/MANIFEST.MF| sed -n -e 's/^.*Log4jReleaseVersion://p'").read()).replace(" ","")).replace("\n","")
        if bool(version):
            for j in range(len(patched_versions)):   
                if version == patched_versions[j]:
                    result="NOT VULNERABLE"
                    text_color="green"
                    bg_color="on_grey"
                    break
                else:
                    result="VULNERABLE" 
                    text_color="white"
                    bg_color="on_red"
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+" /opt/gluu/jetty/ipd/webapps/idp.war ==> "+list_idp_log4j_version[i]+" | "+colored(result, text_color, bg_color))
            if result =="NOT VULNERABLE":
                global patched_files
                patched_files=patched_files+1
            if result =="VULNERABLE":
                global vulnerable_files
                vulnerable_files=vulnerable_files+1
    os.popen("rm -rf WEB-INF")

def scan_casa():
    casa_log4j_version=(os.popen("jar tf /opt/gluu/jetty/casa/webapps/casa.war| grep WEB-INF/lib/log4j").read())
    list_casa_log4j_version = list(casa_log4j_version.split("\n"))
    for i in range(len(list_casa_log4j_version)-1):
        os.popen("jar xvf /opt/gluu/jetty/casa/webapps/casa.war " + list_casa_log4j_version[i]+" ")
        time.sleep(0.5)
        version=((os.popen("unzip -p "+list_casa_log4j_version[i]+" META-INF/MANIFEST.MF| sed -n -e 's/^.*Log4jReleaseVersion://p'").read()).replace(" ","")).replace("\n","")
        if bool(version):
            for j in range(len(patched_versions)):   
                if version == patched_versions[j]:
                    result="NOT VULNERABLE"
                    text_color="green"
                    bg_color="on_grey"
                    break
                else:
                    result="VULNERABLE" 
                    text_color="white"
                    bg_color="on_red"
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+" /opt/gluu/jetty/casa/webapps/casa.war ==> "+list_casa_log4j_version[i]+" | "+colored(result, text_color, bg_color))    
            if result =="NOT VULNERABLE":
                global patched_files
                patched_files=patched_files+1
            if result =="VULNERABLE":
                global vulnerable_files
                vulnerable_files=vulnerable_files+1
    os.popen("rm -rf WEB-INF")

def scan_fido():
    fido_log4j_version=(os.popen("jar tf /opt/gluu/jetty/fido2/webapps/fido2.war| grep WEB-INF/lib/log4j").read())
    list_fido_log4j_version = list(fido_log4j_version.split("\n"))
    for i in range(len(list_fido_log4j_version)-1):
        os.popen("jar xvf /opt/gluu/jetty/fido2/webapps/fido2.war " + list_fido_log4j_version[i]+" ")
        time.sleep(0.5)
        version=((os.popen("unzip -p "+list_fido_log4j_version[i]+" META-INF/MANIFEST.MF| sed -n -e 's/^.*Log4jReleaseVersion://p'").read()).replace(" ","")).replace("\n","")
        if bool(version):
            for j in range(len(patched_versions)):    
                if version == patched_versions[j]:
                    result="NOT VULNERABLE"
                    text_color="green"
                    bg_color="on_grey"
                    break
                else:
                    result="VULNERABLE"
                    text_color="white"
                    bg_color="on_red" 
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+" /opt/gluu/jetty/fido2/webapps/fido2.war ==> "+list_fido_log4j_version[i]+" | "+colored(result, text_color, bg_color)) 
            if result =="NOT VULNERABLE":
                global patched_files
                patched_files=patched_files+1
            if result =="VULNERABLE":
                global vulnerable_files
                vulnerable_files=vulnerable_files+1   
    os.popen("rm -rf WEB-INF")

def scan_scim():
    scim_log4j_version=(os.popen("jar tf /opt/gluu/jetty/scim/webapps/scim.war| grep WEB-INF/lib/log4j").read())
    list_scim_log4j_version = list(scim_log4j_version.split("\n"))
    for i in range(len(list_scim_log4j_version)-1):
        os.popen("jar xvf /opt/gluu/jetty/scim/webapps/scim.war " + list_scim_log4j_version[i]+" ")
        time.sleep(0.5)
        version=((os.popen("unzip -p "+list_scim_log4j_version[i]+" META-INF/MANIFEST.MF| sed -n -e 's/^.*Log4jReleaseVersion://p'").read()).replace(" ","")).replace("\n","")
        if bool(version):
            for j in range(len(patched_versions)):  
                if version == patched_versions[j]:
                    result="NOT VULNERABLE"
                    text_color="green"
                    bg_color="on_grey"
                    break
                else:
                    result="VULNERABLE" 
                    text_color="white"
                    bg_color="on_red"
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+" /opt/gluu/jetty/scim/webapps/scim.war ==> "+list_scim_log4j_version[i]+" | "+colored(result, text_color, bg_color))    
            if result =="NOT VULNERABLE":
                global patched_files
                patched_files=patched_files+1
            if result =="VULNERABLE":
                global vulnerable_files
                vulnerable_files=vulnerable_files+1
    os.popen("rm -rf WEB-INF")

def backup_oxauth():
    check_backup_dir= os.path.isdir("/opt/gluu/jetty/oxauth/webapps/backup_log4jscanner") 
    print("Taking backup of oxauth service.")
    if not check_backup_dir:
        os.popen("mkdir /opt/gluu/jetty/oxauth/webapps/backup_log4jscanner")
    time.sleep(0.5)
    os.popen("cp -a /opt/gluu/jetty/oxauth/webapps/oxauth.war /opt/gluu/jetty/oxauth/webapps/backup_log4jscanner/oxauth.war")

def backup_identity():
    check_backup_dir=os.path.isdir("/opt/gluu/jetty/identity/webapps/backup_log4jscanner")
    print("Taking backup of identity service.")
    if not check_backup_dir:
        os.popen("mkdir /opt/gluu/jetty/identity/webapps/backup_log4jscanner")
    time.sleep(0.5)
    os.popen("cp -a /opt/gluu/jetty/identity/webapps/identity.war /opt/gluu/jetty/identity/webapps/backup_log4jscanner/identity.war")

def backup_idp():
    check_backup_dir= os.path.isdir("/opt/gluu/jetty/idp/webapps/backup_log4jscanner")
    print("Taking backup of idp service.")
    if not check_backup_dir :
        os.popen("mkdir /opt/gluu/jetty/idp/webapps/backup_log4jscanner")
    os.popen("cp -a /opt/gluu/jetty/idp/webapps/idp.war /opt/gluu/jetty/idp/webapps/backup_log4jscanner/idp.war")

def backup_casa():
    check_backup_dir= os.path.isdir("/opt/gluu/jetty/casa/webapps/backup_log4jscanner")
    print("Taking backup of casa service.")
    if not check_backup_dir :
        os.popen("mkdir /opt/gluu/jetty/casa/webapps/backup_log4jscanner")
    time.sleep(0.5)
    os.popen("cp -a /opt/gluu/jetty/casa/webapps/casa.war /opt/gluu/jetty/casa/webapps/backup_log4jscanner/casa.war")

def backup_fido():
    check_backup_dir= os.path.isdir("/opt/gluu/jetty/fido2/webapps/backup_log4jscanner")
    print("Taking backup of fido service.")
    if not check_backup_dir :
        os.popen("mkdir /opt/gluu/jetty/fido2/webapps/backup_log4jscanner")
    time.sleep(0.5)
    os.popen("cp -a /opt/gluu/jetty/fido2/webapps/fido2.war /opt/gluu/jetty/fido2/webapps/backup_log4jscanner/fido2.war")

def backup_scim():
    check_backup_dir= os.path.isdir("/opt/gluu/jetty/scim/webapps/backup_log4jscanner")
    print("Taking backup of scim service.")
    if not check_backup_dir :
        os.popen("mkdir /opt/gluu/jetty/scim/webapps/backup_log4jscanner")
    time.sleep(0.5)
    os.popen("cp -a /opt/gluu/jetty/scim/webapps/scim.war /opt/gluu/jetty/scim/webapps/backup_log4jscanner/scim.war")

def revert_back(oxauth_s,identity_s,idp_s,casa_s,fido_s,scim_s):
    print("Reverting back to the point before the patch was applied")
    time.sleep(1)
    if oxauth_s =="active":
        if os.path.isfile("/opt/gluu/jetty/oxauth/webapps/backup_log4jscanner/oxauth.war"):
            os.popen("rm -rf /opt/gluu/jetty/oxauth/webapps/oxauth.war")
            time.sleep(0.5)
            os.popen("cp -a /opt/gluu/jetty/oxauth/webapps/backup_log4jscanner/oxauth.war /opt/gluu/jetty/oxauth/webapps/oxauth.war")
    if identity_s =="active":
        if os.path.isfile("/opt/gluu/jetty/identity/webapps/backup_log4jscanner/identity.war"):
            os.popen("rm -rf /opt/gluu/jetty/identity/webapps/identity.war")
            time.sleep(0.5)
            os.popen("cp -a /opt/gluu/jetty/identity/webapps/backup_log4jscanner/identity.war /opt/gluu/jetty/identity/webapps/identity.war")
    if idp_s =="active":
        if os.path.isfile("/opt/gluu/jetty/idp/webapps/backup_log4jscanner/idp.war"):
            os.popen("rm -rf /opt/gluu/jetty/idp/webapps/idp.war")
            time.sleep(0.5)
            os.popen("cp -a /opt/gluu/jetty/idp/webapps/backup_log4jscanner/idp.war /opt/gluu/jetty/idp/webapps/idp.war")
    if casa_s =="active":
        if os.path.isfile("/opt/gluu/jetty/casa/webapps/backup_log4jscanner/casa.war"):
            os.popen("rm -rf /opt/gluu/jetty/casa/webapps/casa.war")
            time.sleep(0.5)
            os.popen("cp -a /opt/gluu/jetty/casa/webapps/backup_log4jscanner/casa.war /opt/gluu/jetty/casa/webapps/casa.war")
    if fido_s =="active":
        if os.path.isfile("/opt/gluu/jetty/fido2/webapps/backup_log4jscanner/fido2.war"):
            os.popen("rm -rf /opt/gluu/jetty/fido2/webapps/fido2.war")
            time.sleep(0.5)
            os.popen("cp -a /opt/gluu/jetty/fido2/webapps/backup_log4jscanner/fido2.war /opt/gluu/jetty/fido2/webapps/fido2.war")
    if scim_s =="active":
        if os.path.isfile("/opt/gluu/jetty/scim/webapps/backup_log4jscanner/scim.war"):
            os.popen("rm -rf /opt/gluu/jetty/scim/webapps/scim.war")
            time.sleep(0.5)
            os.popen("cp -a /opt/gluu/jetty/scim/webapps/backup_log4jscanner/scim.war /opt/gluu/jetty/scim/webapps/scim.war")

def main():

    oxauth_status,identity_status,idp_status,casa_status,fido_status,scim_status=check_services()
    if args.revert:
        revert_back(oxauth_status,identity_status,idp_status,casa_status,fido_status,scim_status)
        sys.exit("All the services are reverted back to the state before the patch was applied.")

    

    FIGLET = f"""
   ___   _                 _                   _ _      _   ___                                       
  / __| | |  _  _   _  _  | |     ___   __ _  | | |    (_) / __|  __   __ _   _ _    _ _    ___   _ _ 
 | (_ | | | | || | | || | | |__  / _ \ / _` | |_  _|   | | \__ \ / _| / _` | | ' \  | ' \  / -_) | '_|
  \___| |_|  \_,_|  \_,_| |____| \___/ \__, |   |_|   _/ | |___/ \__| \__,_| |_||_| |_||_| \___| |_|  
                                       |___/         |__/                                             
                                                                --By Sennovate
    """
    print(FIGLET)
    #begining of script
    print("Executing Scanner....\n")
    #checking all the running services in Gluu container
    print("Checking for the services in the Gluu container:\n")
    
    print("Status of oxauth service:",oxauth_status)
    print("Status of identity service:",identity_status)
    print("Status of idp service:",idp_status)
    print("Status of casa service:",casa_status)
    print("Status of fido service:",fido_status)  
    print("Status of scim service:",scim_status)      
    # Scanning Oxauth service for log4j
    if oxauth_status == "active":
        print("\n")
        print("Scanning Oxauth service for log4j version:\n")
        scan_oxauth()
    # Scanning identity service for log4j
    if identity_status == "active":
        print("\n")
        print("Scanning Identiy service for log4j version:\n")
        scan_identity()
    # Scanning idp service for log4j
    if idp_status == "active":
        print("\n")
        print("Scanning idp service for log4j version:\n")
        scan_idp()
    # Scanning casa service for log4j
    if casa_status == "active":
        print("\n")
        print("Scanning Casa service for log4j version:\n")
        scan_casa()
    # Scanning fido service for log4j
    if fido_status == "active":
        print("\n")
        print("Scanning Fido service for log4j version:\n")
        scan_fido()
    # Scanning scim service for log4j
    if scim_status == "active":
        print("\n")
        print("Scanning Scim service for log4j version:\n")
        scan_scim()
    #Result
    print("\n")
    print("Total files scanned:",vulnerable_files+patched_files)
    print("Out of "+str(vulnerable_files+patched_files)+" files, "+str(vulnerable_files)+" files are VULNERABLE")

    if vulnerable_files >= 0:
        print("Do you want to patch the system? (y|n)")
        ch=input("")
        if ch =="y":
            print("Following Actions will be performed:\n")
            print("1.Backup\n")
            print("2.Patch\n")
            print("Do you want to continue (y|n)?")
            ch_2=input("")
            if ch_2=="n":
                sys.exit("Exiting the script. Thanks for using log4jscanner.")
            os.popen("wget -c https://repo.gluu.org/upd/update_log4j.run")
            time.sleep(4)
            print("Taking backup of all the essential files, so you can revert back after the patch is been applied")
            if oxauth_status=="active":
                backup_oxauth()
            if identity_status=="active":
                backup_identity()
            if idp_status=="active":
                backup_idp()
            if casa_status=="active":
                backup_casa()
            if fido_status=="active":
                backup_fido()
            if scim_status=="active":
                backup_scim()
            os.popen("chmod +x update_log4j.run")
            patch=os.popen("sh update_log4j.run").read()
            print(patch)
            time.sleep(2)
            os.popen("rm -f update_log4j.run")

        if ch=="n":
            sys.exit("Thanks for using GluuLog4j Scanner")


if __name__ == "__main__":
    main()

