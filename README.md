# GluuLog4jScanner
Python tool to scan the Gluu container for vulnerable log4j files

## **Overview:**
On the 9th of December 2021, a vulnerability, CVE-2021-44228, was disclosed concerning Apache Log4j, a popular open-source library. The vulnerability allows remote code execution and has been assigned a severity of 10.0, the highest possible, this vulnerability also affected the Gluu servers.

## **How to install**
Clone the repository and then using the below command install all the required modules <br/>
                ``pip install -r /path/to/requirements.txt``

After the module are installed run the log4jscanner.py script <br/>
                ``python log4jscanner.py``

