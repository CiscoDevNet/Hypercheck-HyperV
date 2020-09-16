This Hypercheck Tool is for ONLY for HyperV Hyperflex Cluster

Supported HX Versions
: 
3.0, 
3.5.
Supported HX Clusters
: Hyperflex Standard Cluster, Hyperflex Edge Cluster (3N and 4N ROBO), Only supported on Hyperflex cluster on Hyper-V Server.


When to use?
    
* Before an Hyperflex upgrade
.
* Health Check before and after Maintenance Windows
. 
* When working with TAC and/or Opening a TAC case
.    
* Recommended that you provide the output from the tool while opening a TAC case.



Pre-requisite to use the tool:  
1) The Windows Remote Management (WS-Managemnet) should be enabled on each Hyper-V Server.
2) Script needs Hyper-V Admin Username and Password, and HX root password information to check all conditions


How to run the tool?
Steps:
1) Download the tool(VHXTool.tar) and upload to any one of the controller VM.
2) Untar the file using below command:
	> tar -xvf VHXTool.tar
	> cd VHXTool
3) Now run the python script file with below command:
      	> python VHXTool.py

4) Enter the Hyper-V Admin Username.
5) Enter the Hyper-V Admin password.
6) Enter the HX-Cluster Root Password
7) Is the Active Directory installed on Physical (bare metal) in your Environment (Enter Yes/No).
8) Script will display the result on the console and also creates each node report(VHX Report 10.197.252.79.txt) and main report txt file(VHX Tool Main Report.txt) in the VHX_Report_<timestamp> folder.



