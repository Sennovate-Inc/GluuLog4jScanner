#!/usr/bin/env python
import os
import time
import datetime
import sys
from colorama import init
from termcolor import colored


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
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+" /opt/gluu/jetty/oxauth/identity/oxauth.war ==> "+list_identity_log4j_version[i]+" | "+colored(result, text_color, bg_color))
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
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+" /opt/gluu/jetty/ipd/webapps/oxauth.war ==> "+list_idp_log4j_version[i]+" | "+colored(result, text_color, bg_color))
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
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+" /opt/gluu/jetty/casa/webapps/oxauth.war ==> "+list_casa_log4j_version[i]+" | "+colored(result, text_color, bg_color))    
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
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+" /opt/gluu/jetty/fido2/webapps/oxauth.war ==> "+list_fido_log4j_version[i]+" | "+colored(result, text_color, bg_color)) 
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
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+" /opt/gluu/jetty/scim/webapps/oxauth.war ==> "+list_scim_log4j_version[i]+" | "+colored(result, text_color, bg_color))    
            if result =="NOT VULNERABLE":
                global patched_files
                patched_files=patched_files+1
            if result =="VULNERABLE":
                global vulnerable_files
                vulnerable_files=vulnerable_files+1
    os.popen("rm -rf WEB-INF")

def main():
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
    oxauth_status,identity_status,idp_status,casa_status,fido_status,scim_status=check_services()
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

    if vulnerable_files > 0:
        print("Do you want to patch the system? (y|n)")
        ch=input("")
        if ch =="y":
            os.popen("wget -c https://repo.gluu.org/upd/update_log4j.run")
            os.popen("chmod +x update_log4j.run")
            patch=os.popen("sh update_log4j.run").read()
            print(patch)
        if ch=="n":
            sys.exit("Thanks for using GluuLog4j Scanner")


if __name__ == "__main__":
    main()

