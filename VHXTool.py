# -*- coding: utf-8 -*-
"""
VHXTool v1.0
Created on 12-Mar-2020
Updated on 4-Sep-2020
@author: Kiranraj(kjogleka), Afroj(afrahmad), Himanshu(hsardana), Komal(kpanzade), Avinash(avshukla)
"""
import warnings
warnings.filterwarnings("ignore")
import subprocess
import threading
import paramiko
import time
import datetime
import logging
import sys
import os
import json
import shutil
import getpass
import re
import tarfile
from prettytable import PrettyTable, ALL
from collections import OrderedDict
from progressbar import ProgressBarThread
from winrm.protocol import Protocol
from base64 import b64encode

########################       Logger        #################################
INFO = logging.INFO
DEBUG = logging.DEBUG
ERROR = logging.ERROR

# Global Variable
toolversion = 1.0
builddate = "2020-9-4"


def get_date_time():
    return (datetime.datetime.now().strftime("%Y-%m-%d_%I-%M-%S"))


def log_start(log_file, log_name, lvl):
    # Create a folder
    cdate = datetime.datetime.now()
    global dir_name
    dir_name = "VHX_Report_" + str(cdate.strftime("%Y_%m_%d_%H_%M_%S"))
    try:
        os.makedirs(dir_name)
    except FileExistsError:
        shutil.rmtree(dir_name)
        os.makedirs(dir_name)
    os.chdir(dir_name)
    # Configure logger file handler
    global logger
    log_level = lvl
    logger = logging.getLogger(log_name)
    logger.setLevel(log_level)

    # Create a file handler
    handler = logging.FileHandler(log_file)
    handler.setLevel(log_level)

    # Create a logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', '%Y-%m-%d %I:%M:%S')
    handler.setFormatter(formatter)

    # Add the handlers to the logger
    logger.addHandler(handler)
    msg = "VHX Checkup Tool Started at Date/Time :" + get_date_time().replace("_", "/")
    global start_time
    start_time = datetime.datetime.now()
    logger.info(msg)
    # log_msg("", msg)
    logger.info("Logger Initialized")


def log_stop():
    # Exit the logger and stop the script, used for traceback error handling
    log_msg(INFO, "Closing logger and exiting the application")
    msg = "VHX Checkup Tool Stopped at Date/Time :" + get_date_time().replace("_", "/")
    log_msg(INFO, msg)
    end_time = datetime.datetime.now()
    time_diff = end_time - start_time
    msg = "Test duration: " + str(time_diff.seconds) + " seconds"
    log_msg(INFO, msg)
    logging.shutdown()


def log_entry(cmd_name):
    # Each function will call this in the beginning to enter any DEBUG info
    logger.log(DEBUG, 'Entered command :' + cmd_name)


def log_exit(cmd_name):
    # Each function will call this in the end, to enter any DEBUG info
    logger.log(DEBUG, 'Exited command :' + cmd_name)


def log_msg(lvl, *msgs):
    # Each function will call this to enter any INFO msg
    msg = ""
    if len(msgs) > 1:
        for i in msgs:
            msg = msg + str(i) + "\n"
        msg.rstrip("\n")
    else:
        for i in msgs:
            msg = msg + str(i)
    # Print on Console & log
    for line in msg.split("\n"):
        if lvl == "" and line != "":
            print(line)
        elif line != "":
            logger.log(lvl, line)


def sys_exit(val):
    # End the script
    try:
        log_stop()
    except Exception:
        pass
    sys.exit(val)


def check(l):
    # ASCII Error handler
    return "".join(filter(lambda x: ord(x)<128, l))

####################           COMMANDS            #####################


def runcmd(cmd):
    # Execute local shell command
    log_entry(cmd)
    log_msg(INFO, "$" * 61)
    log_msg(INFO, "\nExecuting Shell command: " + cmd)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    cmdoutput, err = p.communicate()
    p_status = p.wait()
    output = cmdoutput.split("\n")
    log_msg(INFO, "*" * 24 + " CMD OUTPUT " + "*" * 24)
    for line in output:
        log_msg(INFO, str(line))
    log_msg(INFO, "*" * 61)
    return cmdoutput


def execmd(cmd):
    # Execute SSH command
    log_entry(cmd)
    log_msg(INFO, "#" * 61)
    log_msg(INFO, "\nExecuting command: " + cmd)
    stdin, stdout, stderr = client.exec_command(cmd)
    while not stdout.channel.exit_status_ready():
        time.sleep(1)
    response = stdout.channel.exit_status
    output = []
    if response == 0:
        for line in stdout:
            output.append(line.strip())
    else:
        for line in stderr:
            output.append(line.strip())
        output.insert(0, "Not able to run the command")
    log_msg(INFO, "*" * 24 + " CMD OUTPUT " + "*" * 24)
    for line in output:
        try:
            log_msg(INFO, line)
        except Exception:
            log_msg(INFO, check(line))
    log_msg(INFO, "*" * 61)
    log_exit(cmd)
    return output


def rpscmd(cmd):
    # Execute remote Power shell command
    log_msg(INFO, "\n" + "*" * 25 + "  EXE RPS CMD  " + "*" * 25)
    log_msg(INFO, "> " + cmd)
    output = []
    shell_id = psClient.open_shell()
    enc_cmd = b64encode(cmd.encode('utf_16_le')).decode('ascii')
    ps_cmd = 'powershell -encodedcommand {0}'.format(enc_cmd)
    command_id = psClient.run_command(shell_id, ps_cmd)
    std_out, std_err, status_code = psClient.get_command_output(shell_id, command_id)
    # status_code 0 for success
    if status_code == 0:
        sop = std_out.decode("utf-8").strip()
        output = sop.split("\r\n")
        output = map(str, output)
        log_msg(INFO, "\n" + "*" * 25 + "  CMD OUTPUT   " + "*" * 25)
        for ln in output:
            log_msg(INFO, str(ln))
        log_msg(INFO, "*" * 65)
    else:
        log_msg(INFO, "\n" + "*" * 25 + "  CMD OUTPUT   " + "*" * 25)
        log_msg(INFO, "Error")
        log_msg(INFO, "*" * 65)
    psClient.cleanup_command(shell_id, command_id)
    psClient.close_shell(shell_id)
    return output

########################################################################


def check_hyperv_psd(hostiplist, wdusername, wdpassword):
    log_msg(INFO, "\nChecking HyperV Password")
    rsList = []
    for hostip in hostiplist:
        try:
            url = "https://" + hostip + ":5986/wsman"
            global psClient
            psClient = Protocol(endpoint=url, transport="ntlm", username=wdusername, password=wdpassword, server_cert_validation="ignore")
            cmd = "hostname"
            op = rpscmd(cmd)
            if op:
                log_msg(INFO, "Host Name: " + str(op[0]))
            log_msg(INFO, "\nValid HyperV password")
            rsList.append("PASS")
            break
        except Exception as e:
            log_msg(INFO, "Not able to connect remote Hyper-V host: " + str(hostip))
            log_msg("", "\nNot able to connect remote Hyper-V host: " + str(hostip))
            log_msg(INFO, "Invalid Hyper-V password or enable remote powershell")
            log_msg(INFO, "Restart the Windows Remote management service(WinRM) and Re-run the script. Also make sure the Domain and username used is correct")
            #log_msg("", "\nInvalid Hyper-V password or enable remote powershell")
            log_msg("", "\nRestart the Windows Remote management service(WinRM) and Re-run the script. Also make sure the Domain and username used is correct")
            log_msg(ERROR, str(e))
            rsList.append("FAIL")
            continue
    if "PASS" not in rsList:
        sys_exit(0)

def check_hx_psd(ip, hxusername, hxpassword, time_out):
    log_msg(INFO, "\nChecking the HX root password")
    try:
        # Initiate SSH Connection
        client.connect(hostname=ip, username=hxusername, password=hxpassword, timeout=time_out)
        msg = "\nSSH connection established to HX Node: " + ip
        log_msg(INFO, msg)
        cmd = "hostname"
        op = execmd(cmd)
        log_msg(INFO, "\nValid HX root password")
    except Exception as e:
        msg = "\nNot able to establish SSH connection to HX Node: " + ip
        log_msg(INFO, msg)
        log_msg("", msg)
        log_msg(INFO, "\nInvalid HX root password")
        log_msg("", "\nInvalid HX root password")
        log_msg(ERROR, str(e))
        sys.exit(0)


def thread_geteth0ip(ip, hxusername, hxpassword, time_out):
    try:
        # Initiate SSH Connection
        client.connect(hostname=ip, username=hxusername, password=hxpassword, timeout=time_out)
        msg = "\nSSH connection established to HX Node: " + ip
        log_msg(INFO, msg)
        cmd = "ifconfig eth0 | grep 'inet addr:' | cut -d: -f2| cut -d' ' -f1"
        hxip = execmd(cmd)
        hxips.extend(hxip)
        client.close()
    except Exception as e:
        msg = "\nNot able to establish SSH connection to HX Node: " + ip
        log_msg(INFO, msg)
        log_msg("", msg)
        log_msg(ERROR, str(e))


def thread_sshconnect(ip, hxusername, hxpassword, time_out):
    hostd[str(ip)] = dict.fromkeys(
        ["hostname", "date", "ntp source", "package & versions", "check package & versions", "eth0", "eth1", "eth1mtu",
         "iptables count", "cmip", "cdip", "crmaster", "check iptables"], "")
    try:
        # Initiate SSH Connection
        client.connect(hostname=ip, username=hxusername, password=hxpassword, timeout=time_out)
        msg = "\nSSH connection established to HX Node: " + ip
        log_msg(INFO, msg)
        log_msg("", msg)
        # Check hostname
        try:
            cmd = "hostname"
            hname = execmd(cmd)
            hostd[ip]["hostname"] = ("".join(hname)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e))
        # Check NTP source
        try:
            cmd = "stcli services ntp show"
            hntp = execmd(cmd)
            hntp = [i for i in hntp if "-" not in i]
            hostd[ip]["ntp source"] = ("".join(hntp)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e))
        # check package and versions
        try:
            cmd = "dpkg -l | grep -i springpath | cut -d' ' -f3,4-"
            op = execmd(cmd)
            pkgl = []
            for s in op:
                pkgl.append(s[:65])
            hostd[ip]["package & versions"] = pkgl
        except Exception as e:
            log_msg(ERROR, str(e))
        # Get eth0 IP Address
        try:
            cmd = "ifconfig eth0 | grep 'inet addr:' | cut -d: -f2| cut -d' ' -f1"
            eth1ip = execmd(cmd)
            hostd[ip]["eth0"] = ("".join(eth1ip)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e))
        # Get eth1 IP Address
        try:
            cmd = "ifconfig eth1 | grep 'inet addr:' | cut -d: -f2| cut -d' ' -f1"
            eth1ip = execmd(cmd)
            hostd[ip]["eth1"] = ("".join(eth1ip)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e))
        # Get eth1 MTU
        try:
            cmd = "ifconfig eth1 | grep 'MTU:' | cut -d: -f2| cut -d' ' -f1"
            eth1ip = execmd(cmd)
            hostd[ip]["eth1mtu"] = ("".join(eth1ip)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e))
        # check Iptables count
        try:
            cmd = "iptables -L -n | wc -l"
            ipt = execmd(cmd)
            hostd[ip]["iptables count"] = ("".join(ipt)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e))
        # Get CMIP & CDIP
        try:
            cmd = """grep -oP '"clustermanagementip":\".+\","managementsubnetmask"' /etc/springpath/secure/hxinstall_inventory.json"""
            op = execmd(cmd)
            cmip = ""
            cdip = ""
            for line in op:
                m1 = re.search(r"clustermanagementip\":\"(.+)\",\"c", line)
                if m1:
                    cmip = str(m1.group(1))
                m2 = re.search(r"clusterdataip\":\"(.+)\",", line)
                if m2:
                    cdip = str(m2.group(1))
            hostd[ip]["cmip"] = str(cmip)
            hostd[ip]["cdip"] = str(cdip)
        except Exception as e:
            log_msg(ERROR, str(e))
        # Get CRM Master IP address
        try:
            cmd = "sysmtool --ns node --cmd list |grep -i crm -B 7"
            op = execmd(cmd)
            crmip = ""
            cip = ""
            for line in op:
                if "Name:" in line:
                    ln = str(line).split(":")
                    if len(ln) == 2:
                        cip = ln[1].strip()
                    continue
                elif "CRM Master:" in line and "YES" in line:
                    crmip = cip
                    break
            hostd[ip]["crmaster"] = str(crmip)
        except Exception as e:
            log_msg(ERROR, str(e))
    except Exception as e:
        msg = "\nNot able to establish SSH connection to HX Node: " + ip
        log_msg(INFO, msg)
        log_msg("", msg)
        log_msg(ERROR, str(e))
    finally:
        client.close()


def thread_timestamp(ip, hxusername, hxpassword, time_out):
    try:
        # Initiate SSH Connection
        client.connect(hostname=ip, username=hxusername, password=hxpassword, timeout=time_out)
        msg = "\nSSH connection established to HX Node: " + ip
        log_msg(INFO, msg)
        # log_msg("", msg)
        # Check date
        try:
            cmd = 'date "+%D %T"'
            hdate = execmd(cmd)
            hostd[ip]["date"] = ("".join(hdate)).encode("ascii", "ignore")
        except Exception as e:
            log_msg(ERROR, str(e))
    except Exception as e:
        msg = "\r\nNot able to establish SSH connection to HX Node: " + ip
        log_msg(INFO, msg)
        # log_msg("", msg)
        log_msg(ERROR, str(e))
    finally:
        client.close()


def get_vmk1(ip, hxusername, esxpassword, time_out):
    esxip = hostd[ip].get("esxip", "")
    if esxip != "":
        try:
            # Initiate SSH Connection
            client.connect(hostname=esxip, username=hxusername, password=esxpassword, timeout=time_out)
            msg = "\r\nSSH connection established to ESX Host: " + esxip + "\r"
            log_msg(INFO, msg)
            log_msg("", msg)
            vmknode = ""
            # Check vMotion Enabled
            try:
                cmd = "vim-cmd hostsvc/vmotion/netconfig_get | grep -i selectedVnic"
                op = execmd(cmd)
                vmst = "FAIL"
                for line in op:
                    if "unset" in line:
                        vmst = "FAIL"
                    elif "VMotionConfig" in line:
                        vmst = "PASS"
                        v = re.search(r"vmk\d", line)
                        if v:
                            vmknode = v.group()
                esx_vmotion[esxip]["vmotion"] = vmst
                esx_vmotion[esxip]["vmknode"] = vmknode

            except Exception as e:
                log_msg(ERROR, str(e) + "\r")
            # Get vmk0 and vmk1 IP Address
            try:
                cmd = "esxcfg-vmknic -l"
                op = execmd(cmd)
                for line in op:
                    if "vmk0" in line and "IPv4" in line:
                        m1 = re.search(r"([\d]{1,3}(.[\d]{1,3}){3})", line)
                        if m1:
                            hostd[ip]["vmk0"] = str(m1.group(1))
                    elif "vmk1" in line and "IPv4" in line:
                        m2 = re.search(r"([\d]{1,3}(.[\d]{1,3}){3})", line)
                        if m2:
                            hostd[ip]["vmk1"] = str(m2.group(1))
                    # checking vmotion ip address
                    if vmknode != "":
                        if vmknode in line and "IPv4" in line:
                            m3 = re.search(r"([\d]{1,3}(.[\d]{1,3}){3})", line)
                            if m3:
                                esx_vmotion[esxip]["vmkip"] = str(m3.group(1))
                                if " 1500 " in line:
                                    esx_vmotion[esxip]["mtu"] = "1472"
                                elif " 9000 " in line:
                                    esx_vmotion[esxip]["mtu"] = "8972"
            except Exception as e:
                log_msg(ERROR, str(e) + "\r")
        except Exception as e:
            msg = "\r\nNot able to establish SSH connection to ESX Host: " + esxip + "\r"
            log_msg(INFO, msg)
            log_msg("", msg)
            log_msg(ERROR, str(e) + "\r")
        finally:
            client.close()


def pingstatus(op):
    pgst = "PASS"
    for line in op:
        if "Not able to run the command" in line or "Network is unreachable" in line:
            pgst = "FAIL"
        elif "0 packets received" in line or "100% packet loss" in line or " 0 received" in line:
            pgst = "FAIL"
        elif ", 0% packet loss" in line:
            pgst = "PASS"
    return pgst


def cluster_services_check(ip):
    # 1) Get State & Healthstate
    cldict = {}
    cmd = "sysmtool --ns cluster --cmd healthdetail"
    cl_health = execmd(cmd)
    cl_health_reason = []
    flag2 = flag3 = flag4 = 0
    for line in cl_health:
        if line.startswith("Cluster Health Detail:"):
            flag2 = 1
            continue
        if flag2 == 1 and line.startswith("State:"):
            s = str(line.split(": ")[-1]).lower()
            cldict["State"] = s
            continue
        if flag2 == 1 and "HealthState:" in line:
            h = str(line.split(": ")[-1]).lower()
            cldict["HealthState"] = h
            if not "healthy" in h.lower():
                flag3 = 1
        if flag3 == 1 and "Health State Reason:" in line:
            flag4 = 1
            continue
        if flag4 == 1:
            if not line.startswith("#"):
                break
            else:
                cl_health_reason.append(line)
    log_msg(INFO, str(cldict) + "\r")
    hostd[ip].update(cldict)

    # 2) Check service_status.sh
    cmd = "service_status.sh"
    cl_service = execmd(cmd)
    # pidof storfs
    cmd = "pidof storfs"
    op = execmd(cmd)
    for line in op:
        s = line.strip()
        if s.isdigit():
            cl_service.append("storfs {:>44}".format("... Running"))
        else:
            cl_service.append("storfs {:>44}".format("... Not Running"))
            # pidof stMgr
    cmd = "pidof stMgr"
    op = execmd(cmd)
    for line in op:
        s = line.strip()
        if s.isdigit():
            cl_service.append("stMgr {:>45}".format("... Running"))
        else:
            cl_service.append("stMgr {:>45}".format("... Not Running"))
    # pidof stNodeMgr
    cmd = "pidof stNodeMgr"
    op = execmd(cmd)
    for line in op:
        s = line.strip()
        if s.isdigit():
            cl_service.append("stNodeMgr {:>41}".format("... Running"))
        else:
            cl_service.append("stNodeMgr {:>41}".format("... Not Running"))

    # 3) Check Space State & Enospc State
    cmd = "sysmtool --ns cluster --cmd enospcinfo"
    cl_space = execmd(cmd)
    free_capacity = ""
    ENOSPC_warning = ""
    space_state = ""
    enospc_state = ""
    enospc_state_check = "FAIL"
    for line in cl_space:
        if "Free capacity:" in line:
            free_capacity = line.strip().split(": ")[1]
        if "ENOSPC warning:" in line:
            ENOSPC_warning = line.strip().split(": ")[1]
    if free_capacity[-1] == ENOSPC_warning[-1]:
        if float(free_capacity[:-1]) >= float(ENOSPC_warning[:-1]):
            space_state = "healthy"
        else:
            space_state = "unhealthy"
    elif free_capacity[-1] == "T":
        if (float(free_capacity[:-1]) * 1024) >= float(ENOSPC_warning[:-1]):
            space_state = "healthy"
        else:
            space_state = "unhealthy"
    elif free_capacity[-1] == "G":
        if (float(free_capacity[:-1]) * 1024) >= float(ENOSPC_warning[:-1]):
            space_state = "healthy"
        else:
            space_state = "unhealthy"
    elif free_capacity[-1] == "M":
        if (float(free_capacity[:-1]) * 1024 * 1024) >= float(ENOSPC_warning[:-1]):
            space_state = "healthy"
        else:
            space_state = "unhealthy"
    for line in cl_space:
        if "Enospc state:" in line:
            l = line.split(": ")
            if len(l) == 2:
                enospc_state = l[1]
                if "ENOSPACE_CLEAR" in enospc_state.strip():
                    enospc_state_check = "PASS"
            break

    # 4) Check Cleaner Info
    cmd = "sysmtool --ns cleaner --cmd status | cut -d: -f2"
    op = execmd(cmd)
    cl_cleaner_state = ""
    if op:
        cl_cleaner_state = ("".join(op)).strip()

    # 5) Check Data Replication Factor
    cmd = "sysmtool --ns cluster --cmd info | grep 'Replication Factor:' | tail -1 | cut -d: -f2"
    op = execmd(cmd)
    rf = ""
    if op:
        rf = op[0].strip()

    # Update Test Detail info
    testdetail[ip]["Cluster services check"] = OrderedDict()
    # State
    testdetail[ip]["Cluster services check"]["State"] = cldict["State"]
    # HealthState
    testdetail[ip]["Cluster services check"]["HealthState"] = {"Status": cldict["HealthState"],
                                                               "Result": "\n".join(cl_health_reason)}
    # Services
    testdetail[ip]["Cluster services check"]["Services"] = cl_service
    # Space state
    testdetail[ip]["Cluster services check"]["Space State"] = space_state
    # Enospc state
    testdetail[ip]["Cluster services check"]["Enospc State"] = enospc_state
    # Cleaner state
    testdetail[ip]["Cluster services check"]["Cleaner Info"] = cl_cleaner_state
    # Data Replication Factor
    testdetail[ip]["Cluster services check"]["Replication Factor"] = rf

    # Update Test summary
    cluster_service_chk = "FAIL"
    if cldict["State"].lower() == "online":
        cluster_service_chk = "PASS"
    if cldict["HealthState"].lower() == "healthy":
        cluster_service_chk = "PASS"
    for line in cl_service:
        if "Springpath File System" in line and "Not" in line:
            cluster_service_chk = "FAIL"
            break
        elif "SCVM Client" in line and "Not" in line:
            cluster_service_chk = "FAIL"
            break
        elif "System Management Service" in line and "Not" in line:
            cluster_service_chk = "FAIL"
            break
        elif line.startswith("Cluster IP Monitor") and "Not" in line:
            cluster_service_chk = "FAIL"
            break
    testsum[ip]["Cluster services check"] = {"Status": cluster_service_chk,
                                             "Result": "Checks storfs, stMgr, sstNodeMgr service running on each node."}
    testsum[ip]["Enospc state check"] = {"Status": enospc_state_check,
                                         "Result": "Checks if the cluster storage utilization is above threshold."}


def zookeeper_check(ip):
    # ZooKeeper and Exhibitor check
    # 1) Mode
    # echo srvr | nc localhost 2181
    cmd = "echo srvr | nc localhost 2181"
    zkl = execmd(cmd)
    mode = ""
    for line in zkl:
        if "Mode:" in line:
            mode = line.split(": ")[1]

    # Current ensemble size
    nodes = ""
    cmd = "sysmtool --ns cluster --cmd healthdetail | grep -i 'Current ensemble size:' | cut -d: -f2"
    op = execmd(cmd)
    if op:
        nodes = op[0]

    # 2) Services
    # pidof exhibitor
    cmd = "pidof exhibitor"
    exhl = execmd(cmd)
    exh_service = ""
    exh_comm = []
    zcond1 = 0
    for line in exhl:
        s = line.strip()
        if s.isdigit():
            exh_service = "exhibitor {:>32}".format("... Running")
        else:
            exh_service = "exhibitor {:>32}".format("... Not Running")
            zcond1 = 1
    if zcond1 == 1:
        cmd = "ls /etc/springpath/*"
        op = execmd(cmd)
        exh_comm.append("Files in the path[/etc/springpath/*]")
        for line in op:
            exh_comm.append(line.strip())
        cmd = "ls /opt/springpath/config/*"
        op = execmd(cmd)
        exh_comm.append("\nFiles in the path[/opt/springpath/config/*]")
        for line in op:
            exh_comm.append(line.strip())

    # 3) Check exhibitor.properties file exists
    cmd = "ls /etc/exhibitor/exhibitor.properties"
    op = execmd(cmd)
    prop_file = ""
    for line in op:
        if "exhibitor.properties" in line:
            prop_file = "Exists"
        else:
            prop_file = "Not Exists"

    # Epoch Issue
    # 4) Accepted Epoch value
    # 5) Current Epoch value
    cmd = 'grep -m1 "" /var/zookeeper/version-2/acceptedEpoch'
    op = execmd(cmd)
    accepoch = "".join(op)
    cmd = 'grep -m1 "" /var/zookeeper/version-2/currentEpoch'
    op = execmd(cmd)
    curepoch = "".join(op)

    # 6) Disk usage
    # Each should be less than 80%
    cmd = "df -h | grep -i '/var/stv\|/var/zookeeper\|/sda1'"
    diskop = execmd(cmd)
    zdiskchk = "PASS"
    zdisk = ""
    for line in diskop:
        if "Not able to run the command" in line:
            zdiskchk = "NA"
            break
        elif "/sda1" in line:
            m1 = re.search(r"(\d+)%", line)
            if m1:
                if int(m1.group(1)) > 80:
                    zdiskchk = "FAIL"
                    zdisk = "/sda1"
                    break
        elif "/var/stv" in line:
            m2 = re.search(r"(\d+)%", line)
            if m2:
                if int(m2.group(1)) > 80:
                    zdiskchk = "FAIL"
                    zdisk = "/var/stv"
                    break
        elif "/var/zookeeper" in line:
            m3 = re.search(r"(\d+)%", line)
            if m3:
                if int(m3.group(1)) > 80:
                    zdiskchk = "FAIL"
                    zdisk = "/var/zookeeper"
                    break

    # Update Test Detail info
    testdetail[ip]["ZooKeeper and Exhibitor check"] = OrderedDict()
    # Mode
    testdetail[ip]["ZooKeeper and Exhibitor check"]["Mode"] = mode
    # Current ensemble size
    testdetail[ip]["ZooKeeper and Exhibitor check"]["Current ensemble size"] = nodes
    # Services
    testdetail[ip]["ZooKeeper and Exhibitor check"]["Services"] = exh_service
    # exhibitor.properties file
    testdetail[ip]["ZooKeeper and Exhibitor check"]["exhibitor.properties file"] = prop_file
    # Accepted Epoch value
    testdetail[ip]["ZooKeeper and Exhibitor check"]["Accepted Epoch value"] = accepoch
    # Current Epoch value
    testdetail[ip]["ZooKeeper and Exhibitor check"]["Current Epoch value"] = curepoch
    # Disk Usage
    testdetail[ip]["ZooKeeper and Exhibitor check"]["System Disks Usage"] = {"Status": zdiskchk, "Result": zdisk}

    # Update Test summary
    zoo_chk = "FAIL"
    exh_chk = "FAIL"
    if mode == "follower" or mode == "leader" or mode == "standalone":
        zoo_chk = "PASS"
    if "running" in exh_service.lower():
        exh_chk = "PASS"
    testsum[ip]["Zookeeper check"] = {"Status": zoo_chk, "Result": "Checks if Zookeeper service is running."}
    testsum[ip]["Exhibitor check"] = {"Status": exh_chk, "Result": "Checks if Exhibitor in running."}
    testsum[ip]["System Disks Usage"] = {"Status": zdiskchk,
                                         "Result": "Checks if /sda1, var/stv and /var/zookeeper is less than 80%."}


def hdd_check(ip):
    # HDD health check
    # Claimed Disks
    cmd = "sysmtool --ns disk --cmd list | grep -i claimed | wc -l"
    op = execmd(cmd)
    cdsk = ""
    for line in op:
        cdsk = line.strip()

    # Blacklisted Disks
    cmd = "sysmtool --ns disk --cmd list | grep -i blacklisted | wc -l"
    op = execmd(cmd)
    bdsk = ""
    bdisklist = []
    for line in op:
        bdsk = line.strip()
    if bdsk != "":
        cmd = "sysmtool --ns disk --cmd list"
        opl = execmd(cmd)
        flg1 = flg2 = 0
        for line in opl:
            if "UUID:" in line:
                flg1 = 1
                flg2 = 0
                continue
            if flg1 == 1 and "State:" in line and "BLACKLISTED" in line:
                flg2 = 1
                flg1 = 0
                continue
            if flg2 == 1 and "Path:" in line:
                ln = line.split(": ")
                if len(ln) == 2:
                    bdisklist.append(ln[1])
        logger.info("Blacklisted Disks: " + ",".join(bdisklist) + "\r")

    # Ignored Disks
    cmd = "sysmtool --ns disk --cmd list | grep -i ignored | wc -l"
    op = execmd(cmd)
    idsk = ""
    for line in op:
        idsk = line.strip()

    # Update Test Detail info
    testdetail[ip]["HDD health check"] = OrderedDict()
    # Claimed
    testdetail[ip]["HDD health check"]["Claimed"] = cdsk
    # Blacklisted
    testdetail[ip]["HDD health check"]["Blacklisted"] = {"Status": bdsk, "Result": "\n".join(bdisklist)}
    # Ignored
    testdetail[ip]["HDD health check"]["Ignored"] = idsk

    # Update Test summary
    hd_chk = "PASS"
    if int(bdsk) > 0:
        hd_chk = "FAIL"
    testsum[ip]["HDD health check"] = {"Status": hd_chk, "Result": "Checks if any drive is in blacklisted state."}


# Pre-Upgrade Check
def pre_upgrade_check(ip):
    # 1) Check HX Cluster version
    cmd = "stcli about"
    hxvs = execmd(cmd)
    vflag = False
    for line in hxvs:
        if "Not able to run the command" in line:
            hostd[ip]["version"] = ""
            break
        elif "display_version" in line:
            l = line.split(": ")
            if len(l) == 2:
                version = l[1]
                version = version.replace(",", "")
                version = version.replace("'", "")
                hostd[ip]["version"] = version.strip()
                if l[1].startswith("1.8"):
                    vflag = True

    # 2) NTP deamon running check
    ntp_deamon_check = "FAIL"
    cmd = "ps aux | grep ntp"
    ntp_deamon = ""
    op = execmd(cmd)
    for line in op:
        match = re.search(r"^ntp \s+\d+", line)
        if match:
            ntp_deamon = match.group()
            ntp_deamon_check = "PASS"
            msg = "\r\nNTP deamon running check: " + str(ntp_deamon) + "\r"
            log_msg(INFO, msg)

    # 3) NTP Sync Check
    cmd = "ntpq -p -4 | grep '^*'"
    ntpsl = execmd(cmd)
    ntp_sync_check = "FAIL"
    ntp_sync_line = ""
    flag1 = 0
    for line in ntpsl:
        if "Not able to run the command" in line:
            ntp_sync_check = "FAIL"
        elif line.startswith("*"):
            l = line.split()
            ntp_sync_line = l[0]
            ntp_sync_check = "PASS"
            break

    # 3) DNS check
    cmd = "stcli services dns show"
    op = execmd(cmd)
    dnsip = ""
    dns_check = "FAIL"
    digop = []
    for line in op:
        match = re.search(r"(?:\d{1,3}.){3}\d{1,3}", line)
        if match:
            dnsip = match.group()
            msg = "\r\nDNS IP Address: " + str(dnsip) + "\r"
            log_msg(INFO, msg)
            break
    if dnsip:
        # cmd = "ping {} -c 3 -i 0.01".format(dnsip)
        cmd = "dig @{}".format(dnsip)
        dns_check = "FAIL"
        digop = execmd(cmd)
        for line in digop:
            if "HEADER" in line and "status: NOERROR" in line:
                dns_check = "PASS"
                break
            elif "OPT PSEUDOSECTION:" in line:
                break
        digop = [(str(l).rstrip()).replace("\t", " " * 5) for l in digop]
    # Update Test summary
    if dns_check == "PASS":
        testsum[ip]["DNS check"] = {"Status": "PASS", "Result": "Checks if configured DNS is reachable."}
    else:
        testsum[ip]["DNS check"] = {"Status": "FAIL", "Result": "Please verify DNS resolution and connectivity."}

    # 4) Hyper-V Manager IP Check


    # Update Test summary
    testsum[ip]["Timestamp check"] = {"Status": str(hostd[ip]["date check"]),
                                      "Result": "Checks if the timestamp is same across all Nodes."}
    if ntp_deamon_check == "PASS" and hostd[ip]["ntp source check"] == "PASS" and ntp_sync_check == "PASS":
        testsum[ip]["NTP sync check"] = {"Status": "PASS", "Result": "Checks if the NTP is synced with NTP server."}
    else:
        testsum[ip]["NTP sync check"] = {"Status": "FAIL", "Result": "Checks if the NTP is synced with NTP server."}
    testsum[ip]["Check package & versions"] = {"Status": str(hostd[ip]["check package & versions"]),
                                               "Result": "Checks for count and version of HX packages on each node."}
    testsum[ip]["Check Iptables count"] = {"Status": str(hostd[ip]["check iptables"]),
                                           "Result": "Checks if the IP Table count matches on all nodes."}

    # 5) Check cluster usage
    # Node failures tolerable
    cmd = "sysmtool --ns cluster --cmd info | grep -i 'Node failures tolerable' | cut -d: -f2"
    nop = execmd(cmd)
    if nop:
        NFT = nop[0].strip()
    else:
        NFT = "NA"
    # Caching device failures tolerable
    cmd = "sysmtool --ns cluster --cmd info | grep -i 'Caching device failures tolerable' | cut -d: -f2"
    hop = execmd(cmd)
    if hop:
        HFT = hop[0].strip()
    else:
        HFT = "NA"
    # Persistent device failures tolerable
    cmd = "sysmtool --ns cluster --cmd info | grep -i 'Persistent device failures tolerable' | cut -d: -f2"
    sop = execmd(cmd)
    if sop:
        SFT = sop[0].strip()
    else:
        SFT = "NA"

    # 6) Check cache disk usage is spread across all controller
    cmd = "nfstool -- -m | sort -u -k2"
    cachl = []
    op = execmd(cmd)
    for line in op:
        m = re.search(r"^\d+\s+([\d]{1,3}(.[\d]{1,3}){3})", line)
        if m:
            cachl.append(str(m.group(1)))

    # 7) Check any extra number of pnodes
    # cmd = "stcli cluster info | grep -i  pnode -n2 | grep -i name | wc -l"
    cmd = "sysmtool --ns node --cmd list | grep -i PNODE -n2| grep -i name | wc -l "
    op = execmd(cmd)
    op = "".join(op)
    pnodes = int(op)
    check_cache_vnodes = ""
    if cachl:
        if pnodes == len(cachl):
            check_cache_vnodes = "PASS"
        else:
            check_cache_vnodes = "FAIL"
    testsum[ip]["Cache Disks check"] = {"Status": check_cache_vnodes, "Result": "Checks the number of Cache Disks."}
    snodes = len(hxeth1_list)
    nodecheck = "FAIL"
    if pnodes == snodes:
        nodecheck = "PASS"
    testsum[ip]["Extra pnodes check"] = {"Status": nodecheck, "Result": "Checks for any stale Node entry."}

    # 8)check memory
    # cmd = "free -m"
    cmd = "free -m | grep Mem:"
    op = execmd(cmd)
    check_memory = "NA"
    if op:
        for line in op:
            l = line.split()
            frmem = int(l[-1])
            if int(frmem) >= 2048:
                check_memory = "PASS"
            else:
                check_memory = "FAIL"
    if check_memory == "FAIL":
        testsum[ip]["Memory usage check"] = {"Status": "FAIL", "Result": "Contact TAC"}
    else:
        testsum[ip]["Memory usage check"] = {"Status": check_memory,
                                             "Result": "Checks for available memory more than 2GB."}

    # 9) check CPU
    cmd = "top -b -n 1 | grep -B7 KiB"
    check_cpu = execmd(cmd)
    if not check_cpu:
        cmd = "top -b -n 1 | grep Cpu"
        check_cpu = execmd(cmd)

    # 10) check Out of memory
    cmd = "grep -i 'out of memory' -A5 /var/log/kern.log"
    op = execmd(cmd)
    if op:
        if "Not able to run the command" in op:
            check_oom = ["No issue"]
            testsum[ip]["Incidence of OOM in the log file"] = {"Status": "PASS",
                                                               "Result": "Checks for any previous incidence of Out Of Memory Condition."}
        else:
            check_oom = op
            testsum[ip]["Incidence of OOM in the log file"] = {"Status": "FAIL",
                                                               "Result": "Checks for any previous incidence of Out Of Memory Condition."}
    else:
        check_oom = ["No issue"]
        testsum[ip]["Incidence of OOM in the log file"] = {"Status": "PASS",
                                                           "Result": "Checks for any previous incidence of Out Of Memory Condition."}

    # 11) Check permissions for /tmp
    cmd = "ls -ld /tmp"
    op = execmd(cmd)
    tmprcheck = ""
    for line in op:
        if line.startswith("drwxr-xrwx") or line.startswith("drwxrwxrwx"):
            tmprcheck = "PASS"
        else:
            tmprcheck = "FAIL"
    testsum[ip]["Check permissions for /tmp"] = {"Status": tmprcheck,
                                                 "Result": "Checks if the /tmp permissions are set correctly."}

    # 12) Cluster Access Policy (Lenient/Strict) check
    clPolicy = ""
    cmd = 'hxcli cluster info | egrep "Cluster Access Policy"'
    op = execmd(cmd)
    for line in op:
        if ":" in line:
            l = line.split(":")
            if l:
                clPolicy = l[1].strip()

    if "strict" in clPolicy.lower():
        testsum[ip]["Check Cluster Access Policy"] = {"Status": "Strict",
                                                      "Result": "Please refer - https://tinyurl.com/yadvhd84"}
    else:
        testsum[ip]["Check Cluster Access Policy"] = {"Status": clPolicy,
                                                      "Result": "Checks the Configured Cluster Access Policy"}

    # 13) Check CMIP hostname
    cmd = """grep -oP '"clustermanagementip":\".+\","clusterdataip"' /etc/springpath/secure/hxinstall_inventory.json"""
    op = execmd(cmd)
    cmip = ""
    for line in op:
        if "clustermanagementip" in line:
            m = re.search(r"([\d]{1,3}(\.[\d]{1,3}){3})", line)
            if m:
                cmip = "FAIL"
                break
            else:
                cmip = "PASS"
                break
    testsum[ip]["Check CMIP Hostname"] = {"Status": cmip,
                                          "Result": "Check if the clustermanagementip has hostname defined."}

    # 14) Check domain join health
    cmd = "domainjoin-cli query"
    dmhlist = execmd(cmd)
    testsum[ip]["Domain join health"] = {"Status": str("\n".join(dmhlist)), "Result": "Checking domain join health of the Node."}

    ######################
    # Update Test Detail info
    testdetail[ip]["Pre-Upgrade check"] = OrderedDict()
    # HX Cluster version
    testdetail[ip]["Pre-Upgrade check"]["HX Cluster version"] = hostd[ip]["version"]
    # NTP deamon running
    testdetail[ip]["Pre-Upgrade check"]["NTP deamon running"] = {"Status": ntp_deamon, "Result": ntp_deamon_check}
    # NTP sync check
    testdetail[ip]["Pre-Upgrade check"]["NTP sync check"] = {"Status": ntp_sync_line, "Result": ntp_sync_check}
    # DNS check
    testdetail[ip]["Pre-Upgrade check"]["DNS check"] = {"Status": str("\n".join(digop)), "Result": dns_check}
    # Timestamp check
    allhostdt = []
    for i in sorted(hostd.keys()):
        allhostdt.append(str(i) + " - " + str(hostd[i]["date"]))
    testdetail[ip]["Pre-Upgrade check"]["Timestamp check"] = {"Status": str("\n".join(allhostdt)),
                                                              "Result": str(hostd[ip]["date check"])}
    # Primary NTP Source check
    allntpsrc = []
    for p in sorted(hostd.keys()):
        allntpsrc.append(str(p) + " : NTP IP - " + str(hostd[p]["ntp source"]))
    testdetail[ip]["Pre-Upgrade check"]["Primary NTP Source check"] = {"Status": str("\n".join(allntpsrc)),
                                                                       "Result": str(hostd[ip]["ntp source check"])}
    # Cluster usage
    testdetail[ip]["Pre-Upgrade check"]["Cluster Fault Tolerance"] = "Node Failures Tolerable:" + str(
        NFT) + "\nHDD Failures Tolerable:" + str(HFT) + "\nSSD Failures Tolerable:" + str(SFT)
    # Cache Disks usage
    testdetail[ip]["Pre-Upgrade check"]["Cache Disks check"] = {"Status": str("\n".join(cachl)),
                                                                "Result": check_cache_vnodes}
    # No extra pnodes
    testdetail[ip]["Pre-Upgrade check"]["No extra pnodes"] = nodecheck
    # Check package & versions
    testdetail[ip]["Pre-Upgrade check"]["Check package & versions"] = {
        "Status": str("\n".join(hostd[ip]["package & versions"])), "Result": str(hostd[ip]["check package & versions"])}
    # Check Iptables count
    testdetail[ip]["Pre-Upgrade check"]["Check Iptables count"] = {"Status": str(hostd[ip]["iptables count"]),
                                                                   "Result": str(hostd[ip]["check iptables"])}
    # Check memory
    testdetail[ip]["Pre-Upgrade check"]["Check Memory usage"] = str(check_memory)
    # Check CPU
    testdetail[ip]["Pre-Upgrade check"]["Check CPU"] = str("\n".join(check_cpu))
    # Check Out of memory
    testdetail[ip]["Pre-Upgrade check"]["Incidence of OOM in the log file"] = str("\n".join(check_oom))
    # Check permissions for /tmp
    testdetail[ip]["Pre-Upgrade check"]["Check permissions for /tmp"] = tmprcheck
    # Cluster Policy (Lenient/Strict) check
    if "strict" in clPolicy.lower():
        testdetail[ip]["Pre-Upgrade check"]["Cluster Access Policy check"] = {"Status": "Strict",
                                                                       "Result": "Please refer - https://tinyurl.com/yadvhd84"}
    else:
        testdetail[ip]["Pre-Upgrade check"]["Cluster Access Policy check"] = clPolicy
    # Check CMIP Hostname
    testdetail[ip]["Pre-Upgrade check"]["Check CMIP Hostname"] = cmip
    # Check domain join health
    testdetail[ip]["Pre-Upgrade check"]["Domain join health"] = {"Status": str("\n".join(dmhlist)),
                                                                 "Result": "Checking domain join health of the Node."}


def hyperv_check(ip):
    """
    Check Remote HyperV Server
    """
    hostip = hostd[ip]["hyperv"]
    log_msg(INFO, "Remote HyperV Check: " + str(hostip))
    if hostip not in hvdict.keys():
        hvdict[hostip] = {}
    try:
        url = "https://" + hostip + ":5986/wsman"
        global psClient
        psClient = Protocol(endpoint=url, transport="ntlm", username=wdusername, password=wdpassword, server_cert_validation="ignore")
        # Get the hostname
        cmd = "hostname"
        op = rpscmd(cmd)
        hostname = ""
        for line in op:
            hostname = line.strip()
        log_msg(INFO, "Host Name: " + str(hostname))
        hvdict[hostip]["HostName"] = {"Status": str(hostname), "Result": "Check if the hostname is defined."}

        # 1) Failover cluster manager role is enabled
        cmd = "Get-WindowsFeature Failover*"
        op = rpscmd(cmd)
        flchk = ""
        for line in op:
            if "Installed" in line:
                flchk = "Installed"
            elif "Not Installed" in line:
                flchk = "Not Installed"
        hvdict[hostip]["Cluster Failover"] = {"Status": flchk,
                                              "Result": "Check if the Failover Cluster Manager feature is installed."}

        # 2) Hyper-V Manager role / feature enabled
        cmd = "Get-WindowsFeature Hyper-V"
        op = rpscmd(cmd)
        fechk = ""
        for line in op:
            if "Installed" in line:
                fechk = "Installed"
            elif "Not Installed" in line:
                fechk = "Not Installed"
        hvdict[hostip]["Hyper-V Role"] = {"Status": fechk,
                                          "Result": "Check if the Hyper-V Manager feature is installed."}

        # 3) Check Node State
        cmd = "Get-ClusterNode"
        op = rpscmd(cmd)
        ndstate = ""
        for line in op:
            if hostname in line:
                if "up" in line.lower():
                    ndstate = "PASS"
                elif "down" in line.lower():
                    ndstate = "Fail"
        if ndstate == "PASS":
            hvdict[hostip]["Node State"] = {"Status": "PASS", "Result": "Check the Node State."}
        else:
            hvdict[hostip]["Node State"] = {"Status": ndstate,
                                            "Result": "Please check the Cluster Failover status."}

        # 4) Check network interfaces state
        cmd = "Get-ClusterNetwork"
        op = rpscmd(cmd)
        nwstate = "PASS"
        for line in op:
            if "down" in line.lower():
                nwstate = "FAIL"
                break
        hvdict[hostip]["Network Interfaces State"] = {"Status": nwstate,
                                                      "Result": "Check the Network Interfaces State."}

        # 5) Check Remote Management is enabled
        cmd = "Get-Service WinRM"
        op = rpscmd(cmd)
        rmstate = ""
        for line in op:
            if "running" in line.lower() and "winrm" in line.lower():
                rmstate = "PASS"
                break
        hvdict[hostip]["Remote Management Enabled"] = {"Status": nwstate,
                                                       "Result": "Check if the Remote Management is enabled on the node."}

        # 6) Check the Domain and forest details
        cmd = """Get-WmiObject Win32_NTDomain -Filter \"DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'\""""
        op = rpscmd(cmd)
        fdetails = []
        for line in op:
            if "Description" in line:
                fdetails.append(line.strip())
            elif "DnsForestName" in line:
                fdetails.append(line.strip())
            elif "DomainControllerAddress" in line:
                fdetails.append(line.strip())
            elif "DomainControllerName" in line:
                fdetails.append(line.strip())
            elif "DomainName" in line:
                fdetails.append(line.strip())
            elif "Status" in line:
                fdetails.append(line.strip())
        hvdict[hostip]["Check the Domain and forest details"] = {"Status": "\n".join(fdetails),
                                                                 "Result": "Check the Domain and forest details of the cluster."}

        # 7) Check host file entries
        cmd = "Get-Content $env:SystemRoot\System32\Drivers\etc\hosts"
        op = rpscmd(cmd)
        hdetails = []
        for line in op:
            if not line.startswith("#"):
                hdetails.append(line.strip())
        hvdict[hostip]["Check host file entries"] = {"Status": "\n".join(hdetails),
                                                     "Result": "Check if the host file have correct entries."}

        # 8) Check Adapter details
        cmd = "Get-NetIPConfiguration | Format-Table InterfaceAlias, InterfaceDescription, IPv4Address -auto"
        adetails = rpscmd(cmd)
        hvdict[hostip]["Check Adapter details"] = {"Status": "\n".join(adetails),
                                                   "Result": "Check Adapter details of the node."}

        # 9) Check MTU for Storage Data Network
        cmd = "Get-NetIPInterface -AddressFamily IPv4 -InterfaceAlias vswitch-hx-storage-data | select NlMtu*"
        op = rpscmd(cmd)
        mtu = ""
        for line in op:
            if (line.strip()).isdigit():
                mtu = line.strip()
        hvdict[hostip]["MTU for Storage Data Network"] = {"Status": str(mtu),
                                                          "Result": "Check MTU for the Storage Data Network."}

        # 10) Check the status minifilter driver
        cmd = "fltmc"
        drivertails = rpscmd(cmd)
        hvdict[hostip]["Drivers test"] = {"Status": "\n".join(drivertails),
                                          "Result": "Check the status of minifilter drivers."}

        # 11) Virtual Machine Management service check
        vmmCheck = ""
        con = 0
        cmd = "Get-Process vmms | Format-list Name, Id, Responding"
        op = rpscmd(cmd)
        for line in op:
            if "Id" in line:
                m = re.search(r":\s(\d+)", line)
                if m:
                    con = 1
            elif "Responding" in line:
                if "True" in line and con:
                    vmmCheck = "PASS"
                else:
                    vmmCheck = "FAIL"
        if vmmCheck == "FAIL":
            hvdict[hostip]["Virtual Machine Management service check"] = {"Status": "FAIL",
                                                                          "Result": "Please manually verify the status of  VMMS service."}
        else:
            hvdict[hostip]["Virtual Machine Management service check"] = {"Status": vmmCheck,
                                                                          "Result": "Checking if VMMS service is Up and Running."}

        # 12) SMB Test
        smbtest = []
        smbfqdn = ""
        smbResult = []
        if hdetails:
            for line in hdetails:
                l = line.split()
                if len(l) == 2:
                    smbfqdn = l[1].strip()
                    break
        if smbfqdn:
            try:
                psClient = Protocol(endpoint=url, transport="ntlm", username=wdusername, password=wdpassword, server_cert_validation="ignore")
                for ds in datastorelist:
                    cmd = r"test-path \\{}\{}".format(smbfqdn, ds)
                    op = rpscmd(cmd)
                    if op:
                        smbResult.append(str(op[0]))
                        rs = cmd + "  " + str(op[0])
                        smbtest.append(rs)
            except Exception as eps:
                log_msg(ERROR, str(eps))
        log_msg(INFO, "SMB Test:" + str(smbResult))
        if smbResult:
            if "False" in smbResult:
                hvdict[hostip]["SMB Test"] = {"Status": "FAIL", "Result": "\n".join(smbtest)}
            else:
                hvdict[hostip]["SMB Test"] = {"Status": "PASS", "Result": "Checking SMB reachability of node."}
        else:
            hvdict[hostip]["SMB Test"] = {"Status": "", "Result": "Checking SMB reachability of node."}

        log_msg(INFO, "Remote HyperV Check Complete:" + str(hostip))

    except Exception as er:
        log_msg(INFO, "Not able to connect remote Hyper-V host: " + str(hostip))
        log_msg(INFO, "\r\nInvalid Hyper-V password\r")
        log_msg(ERROR, str(er))


def create_sub_report(ip):
    log_msg(INFO, "Create HX Report files")
    # create HX controller report file
    global subreportfiles
    filename = "VHX_Report_" + str(ip) + ".txt"
    subreportfiles.append(filename)
    with open(filename, "w") as fh:
        fh.write("\t\t\tVHX Tool " + str(toolversion))
        fh.write("\n")
        fh.write("\t\t\tHX Controller: " + ip)
        fh.write("\n")
        fh.write("\t\t\tHX Hostname: " + hostd[ip].get("hostname", ""))
        fh.write("\n")
        fh.write("#" * 80)
        fh.write("\n")
        n = 1
        for cname in testdetail[ip].keys():
            fh.write("\n" + str(n) + ") " + cname + ":")
            fh.write("\n")
            tw = PrettyTable(hrules=ALL)
            tw.field_names = ["Name", "Status", "Comments"]
            tw.align = "l"
            for k, v in testdetail[ip][cname].items():
                if type(v) == list:
                    tw.add_row([k, "\n".join(v), ""])
                elif type(v) == dict:
                    tw.add_row([k, v["Status"], v["Result"]])
                else:
                    tw.add_row([k, v, ""])
            fh.write((str(tw)))
            fh.write("\n")
            n += 1

    # print("\r\nSub Report File: " + filename)
    log_msg(INFO, "Sub Report File: " + filename)


def display_hx_result():
    log_msg(INFO, "Print the HX Report")
    # Display the test Summary results
    print("")
    for ip in testsum.keys():
        print("\nHX Controller: " + ip)
        print("Test Summary:")
        ts = PrettyTable(hrules=ALL)
        ts.field_names = ["Name", "Result", "Comments"]
        ts.align = "l"
        for k, v in testsum[ip].items():
            if type(v) == list:
                ts.add_row([k, "\n".join(v), ""])
            elif type(v) == dict:
                ts.add_row([k, v["Status"], v["Result"]])
            else:
                ts.add_row([k, v, ""])
        print(ts)
        time.sleep(5)


def display_hyperv_result():
    log_msg(INFO, "Print the Hyper-V Report")
    # Display the detail test results
    # Test Detail
    for hip in sorted(hvdict.keys()):
        print("\nHyper-V Host: " + hip)
        hct = PrettyTable(hrules=ALL)
        hct.field_names = ["Name", "Status", "Comments"]
        hct.align = "l"
        keys = ["HostName", "Cluster Failover", "Hyper-V Role", "Node State", "Network Interfaces State",
                "Remote Management Enabled", "MTU for Storage Data Network", "Check the Domain and forest details",
                "Check host file entries", "Check Adapter details", "Drivers test",
                "Virtual Machine Management service check", "SMB Test"]
        for k in keys:
            try:
                if type(hvdict[hip][k]) == list:
                    hct.add_row([k, "\n".join(hvdict[hip][k]), ""])
                elif type(hvdict[hip][k]) == dict:
                    hct.add_row([k, hvdict[hip][k]["Status"], hvdict[hip][k]["Result"]])
                else:
                    hct.add_row([k, hvdict[hip].get(k, ""), ""])
            except Exception:
                continue
        print(hct)
        time.sleep(5)


def create_main_report(clustername):
    log_msg(INFO, "Create the Main Report file")
    # create main report file
    if clustername.strip() != "":
        filename = "VHX_Tool_Main_Report_" + get_date_time() + "_" + str(clustername.strip()) + ".txt"
    else:
        filename = "VHX_Tool_Main_Report_" + get_date_time() + ".txt"
    with open(filename, "w") as fh:
        fh.write("\t\t\tVHX Tool " + str(toolversion))
        fh.write("\n")
        fh.write("\t\t\tVHX Tool Main Report:")
        fh.write("\n")
        fh.write("#" * 80)
        fh.write("\n")
        fh.write("\nActive Directory installed on Physical (bare metal) in your Environment: " + str(adInfo))
        fh.write("\n")
        fh.write("\nSMB Share Name: " + smbName)
        fh.write("\n")
        fh.write("\nHX Cluster Nodes:")
        fh.write("\n")
        fh.write((str(ht)))
        fh.write("\n\n")

    for sfile in subreportfiles:
        with open(sfile, "r") as fh:
            content = fh.read()
        with open(filename, "a") as fh:
            fh.write("\n")
            fh.write("#" * 80)
            fh.write("\n")
            fh.write(content)
    with open(filename, "a") as fh:
        fh.write("\n")
        fh.write("#" * 80)
        fh.write("\n\t\t\t Network check:")
        fh.write("\n")
        fh.write("#" * 80)
        fh.write("\n")
        fh.write("Hyper-V Clusters: " + ", ".join(hypervlist))
        fh.write("\n")
        for hip in sorted(hvdict.keys()):
            fh.write("\nHyper-V Host: " + hip)
            hct = PrettyTable(hrules=ALL)
            hct.field_names = ["Name", "Status", "Comments"]
            hct.align = "l"
            keys = ["HostName", "Cluster Failover", "Hyper-V Role", "SMB1 Enabled", "SMB2 Enabled", "Check Node State",
                    "Check Network Interfaces State", "Remote Management Enabled", "Check MTU for Storage Data Network",
                    "Check the Domain and forest details", "Check host file entries", "Check Adapter details",
                    "Check the status minifilter driver", "Virtual Machine Management service check", "SMB Test"]
            for k in keys:
                try:
                    if type(hvdict[hip][k]) == list:
                        hct.add_row([k, "\n".join(hvdict[hip][k]), ""])
                    elif type(hvdict[hip][k]) == dict:
                        hct.add_row([k, hvdict[hip][k]["Status"], hvdict[hip][k]["Result"]])
                    else:
                        hct.add_row([k, hvdict[hip].get(k, ""), ""])
                except Exception:
                    continue
            fh.write("\n")
            fh.write(str(hct))
            fh.write("\n")
        fh.write("\n")
        fh.write("\nRelease Notes:")
        fh.write("\nhttps://www.cisco.com/c/en/us/support/hyperconverged-systems/hyperflex-hx-data-platform-software/products-release-notes-list.html")
        fh.write("\n\nUpgrade Guides:")
        fh.write("\nhttps://www.cisco.com/c/en/us/support/hyperconverged-systems/hyperflex-hx-data-platform-software/products-installation-guides-list.html")
        fh.write("\n\nNote:")
        fh.write("\n1) Hypercheck doesnot perform FAILOVER TEST, so please ensure that the upstream is configured for network connectivity for JUMBO or NORMAL MTU size as needed.")
        fh.write("\n")

    log_msg(INFO, "Main Report file: " + filename)
    print("\nMain Report File: " + filename)
    log_stop()
    create_tar_file()
    print("\nRelease Notes:")
    print("https://www.cisco.com/c/en/us/support/hyperconverged-systems/hyperflex-hx-data-platform-software/products-release-notes-list.html")
    print("\nUpgrade Guides:")
    print("https://www.cisco.com/c/en/us/support/hyperconverged-systems/hyperflex-hx-data-platform-software/products-installation-guides-list.html")
    print("\nNote:")
    print("1) Hypercheck doesnot perform FAILOVER TEST, so please ensure that the upstream is configured for network connectivity for JUMBO or NORMAL MTU size as needed.")
    print("\n")


def create_tar_file():
    file = dir_name + ".tar"
    try:
        os.chdir("..")
        tar = tarfile.open(file, "w")
        tar.add(dir_name)
        tar.close()
        print("Report tar file: " + str(file))
        # Copy file to /var/log/springpath
        path = r"/var/log/springpath/"
        shutil.copy(file, path)
        print("Report file copied to path: /var/log/springpath")
    except Exception as e:
        print("Not able to create the Report tar file")
        log_msg(INFO, str(e))
        print(e)


###############################################################################
# Main Starts here
###############################################################################
if __name__ == "__main__":
    # VHXTool
    # Arguments passed
    arg = ""
    if len(sys.argv) > 1:
        try:
            arg = (sys.argv[1]).lower()
        except Exception:
            pass
    if arg == "-h" or arg == "--help" or arg == "help":
        print("\n\t\t VHX Tool " + str(toolversion))
        print("\nSupported HX Versions: 3.0, 3.5, 4.0")
        print("\nPre-requisite: Script needs Hyper-V Admin username and password and HX root password information to check all conditions.")
        print("\nVHX Health Check script will do below checks on each cluster nodes:")
        print("\t 1) HX Cluster services check")
        print("\t 2) HX ZooKeeper & Exhibitor check")
        print("\t 3) HX HDD health check")
        print("\t 4) HX Pre-Upgrade Check")
        print("\t 5) Hyper-V check ")
        print("\nFor Test Summary report run as below:")
        print("\t python VHXTool.py")
        sys.exit(0)

    # Log file declaration
    log_file = "VHXTool_" + get_date_time() + ".log"
    log_name = "VHXTOOL"
    log_start(log_file, log_name, INFO)

    print("\n\t\t VHX Tool " + str(toolversion))
    log_msg(INFO, "VHX Tool version: " + str(toolversion))
    log_msg(INFO, "VHX Tool Build Date: " + str(builddate))

    # HX Controller parameter
    print("\nPlease enter below info of Hyper-V Cluster:")
    wdusername = raw_input("\nEnter the Hyper-V Username(Ex: Domain\Username): ")
    log_msg(INFO, "Hyper-V Username: " + wdusername)
    wdpassword = getpass.getpass("Enter the Hyper-V Password: ")
    hxusername = "root"
    log_msg(INFO, "HX Username: " + hxusername)
    hxpassword = getpass.getpass("\nEnter the HX-Cluster Root Password: ")
    port = 22
    log_msg(INFO, "Port: " + str(port))
    time_out = 30  # Number of seconds for timeout
    log_msg(INFO, "Timeout: " + str(time_out))

    # Ask Active Directory info
    adInfo = raw_input("\nIs the Active Directory installed on Physical (bare metal) in your Environment (Enter Yes/No): ")
    print("Note: Please be aware that all Active Directory Servers/ DNS Servers should not be nested in Hyperflex datastore virtual machines. There should always be physical (bare metal) ADs in your environment.")

    # Get Host IP Address of eth1
    # cmd = "hostname -i"
    cmd = "ifconfig eth1 | grep 'inet addr:' | cut -d: -f2| cut -d' ' -f1"
    op = runcmd(cmd)
    hostip = op.strip()
    log_msg(INFO, "Host IP Address: " + str(hostip) + "\r")
    # Get Host Path
    cmd = "pwd"
    op = runcmd(cmd)
    hostpath = op.strip()
    log_msg(INFO, "Host Path: " + str(hostpath) + "\r")
    log_msg(INFO, "Argument: " + str(arg) + "\r")
    if arg == "detail":
        print("Option: " + str(arg))

    # Get Cluster Name
    print("")
    clustername = ""
    #cmd = "stcli cluster storage-summary --detail | grep -i name | cut -d: -f2"
    cmd = """stcli cluster storage-summary --detail | egrep  '"name":' | cut -d: -f2"""
    op = runcmd(cmd)
    if op:
        m = re.search(r"\"(.+)\"", op)
        if m:
            clustername = m.group(1)
    log_msg(INFO, "Cluster Name: " + str(clustername) + "\r")
    #log_msg("", "Cluster Name: " + str(clustername) + "\r")

    # Get Cluster Type
    clusterType = ""
    cmd = "sysmtool --ns cluster --cmd info | grep -i 'Cluster Type:'"
    cop = runcmd(cmd)
    if cop:
        if ":" in cop:
            m = cop.strip().split(":")
            try:
                clusterType = m[1].strip()
            except KeyError:
                pass
    log_msg(INFO, "Cluster Type: " + str(clusterType) + "\r")
    #log_msg("", "Cluster Type: " + str(clusterType) + "\r")

    smbName = ""
    hvdict = {}
    hostd = {}
    hxips = []
    hxhv = {}
    hxeth1_list = []
    hypervlist = []
    datastorelist = []
    subreportfiles = []

    print("")
    # Get Controller Mgmnt IP Addresses
    # Get eth1 ips
    # eth0: managementip
    # eth1: dataip
    cmd = "sysmtool --ns cluster --cmd info | grep -i uuid"
    op = runcmd(cmd)
    ips = []
    if op:
        ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", op)
    if not ips:
        print("HX Nodes IP Addresses are not found, quitting.")
        sys_exit(0)
    ips.sort(key=lambda ip: map(int, reversed(ip.split('.'))))
    log_msg(INFO, "Eth1 IP Adresses: " + ", ".join(ips) + "\r")
    hxeth1_list = list(set(ips))
    hxeth1_list.sort(key=lambda ip: map(int, reversed(ip.split('.'))))
    log_msg(INFO, "HX IP Adresses: " + ", ".join(hxeth1_list))

    # Get DataStore List
    cmd = "hxcli datastore list"
    op = runcmd(cmd)
    opl = op.split("\n")
    for line in opl:
        line = check(line)
        if "+---" in line or "NAME" in line:
            continue
        elif "|" in line:
            l = line.split("|")
            if l:
                d = l[1].strip()
                datastorelist.append(str(d))
    log_msg(INFO, "Datastore List: " + str(datastorelist))

    # Get SMB Name or Cluster Name
    cmd = 'hxcli cluster info | egrep "Cluster Name"'
    op = runcmd(cmd)
    if op:
        if ":" in op:
            m = op.strip().split(":")
            if m:
                try:
                    smbName = m[1].strip()
                except KeyError:
                    pass
    log_msg(INFO, "SMB Name: " + str(smbName))
    log_msg("", "SMB Name: " + str(smbName))

    # Get Hyper-V IP Addresses
    try:
        with open("/etc/springpath/secure/hxinstall_inventory.json", "r") as fh:
            jdata = json.load(fh)
        for d in jdata["hxvms"]:
            ip = str(d.get("managementip", ""))
            huid = str(d.get("hostuuid", ""))
            if ip:
                hxhv[ip] = {}
                hxhv[ip]["uuid"] = huid
        for d in jdata['hosts']:
            ip = str(d.get("managementip", ""))
            uid = str(d.get("uuid", ""))
            hypervlist.append(ip)
            for k in hxhv.keys():
                if hxhv[k]["uuid"] == uid:
                    hxhv[k]["hyperv"] = ip
    except Exception:
        pass
    hypervlist = map(str, hypervlist)
    hypervlist.sort(key=lambda ip: map(int, reversed(ip.split('.'))))
    log_msg(INFO, "Hyper-V IP Adresses: " + ", ".join(hypervlist))

    # Verify Hyper-V Password
    if hypervlist:
        check_hyperv_psd(hypervlist, wdusername, wdpassword)

    print("")
    #############################################################
    # Create instance of SSHClient object
    client = paramiko.SSHClient()

    # Automatically add untrusted hosts (Handle SSH Exception for unknown host)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Verify HX root Password
    check_hx_psd(hxeth1_list[0], hxusername, hxpassword, time_out)

    # Get all hostnames and HX IP address using threads
    # <hostname -i> cmd is not working
    try:
        ipthreads = []
        for ip in hxeth1_list:
            th = threading.Thread(target=thread_geteth0ip, args=(ip, hxusername, hxpassword, time_out,))
            th.start()
            time.sleep(12)
            ipthreads.append(th)

        for t in ipthreads:
            t.join()

        hxips.sort(key=lambda ip: map(int, reversed(ip.split('.'))))
    except Exception:
        hxips = hxeth1_list

    log_msg(INFO, "HX IP Adresses: " + ", ".join(hxips))

    # Get hostname, eth1, esxip using threads
    threads = []
    for ip in hxips:
        th = threading.Thread(target=thread_sshconnect, args=(ip, hxusername, hxpassword, time_out,))
        th.start()
        time.sleep(30)
        threads.append(th)

    for t in threads:
        t.join()

    # Update Hyper-V IP Address
    for k in hostd.keys():
        if k in hxhv.keys():
            hostd[k]["hyperv"] = hxhv[k]["hyperv"]

    # Get all timestamp using threads
    tsthreads = []
    tsstart = datetime.datetime.now().replace(microsecond=0)
    for ip in hxips:
        th = threading.Thread(target=thread_timestamp, args=(ip, hxusername, hxpassword, time_out,))
        th.start()
        time.sleep(5)
        tsthreads.append(th)

    for t in tsthreads:
        t.join()
    tsend = datetime.datetime.now().replace(microsecond=0)
    timedelay = (tsend - tsstart).seconds
    log_msg(INFO, "Time delay for Timestamp check: " + str(timedelay))

    # Print the Nodes Table
    ht = PrettyTable(hrules=ALL)
    ht.field_names = ["Nodes", "Eth0 IP Address", "HostName", "Eth1 IP Address", "Eth1 MTU", "Cluster Mgmt IP", "Cluster Data IP", "CRM Master"]
    ht.align = "l"
    for i, ip in enumerate(hxips):
        ht.add_row([i + 1, ip, hostd[ip].get("hostname", ""), hostd[ip].get("eth1", ""), hostd[ip].get("eth1mtu", ""), hostd[ip].get("cmip", ""), hostd[ip].get("cdip", ""), hostd[ip].get("crmaster", "")])
    print("\nHX Cluster Nodes:")
    print(ht)
    print("")

    # NTP Date check
    # timestamp should be same on all storage controllers
    dtresult = ""
    for ip in hostd.keys():
        hostd[ip]["date check"] = dtresult
        try:
            d = hostd[ip]["date"]
            if d == "":
                dtresult = "FAIL"
            else:
                ipdt = datetime.datetime.strptime(d, "%m/%d/%y %H:%M:%S")
                for jp in hostd.keys():
                    if ip == jp:
                        continue
                    else:
                        jd = hostd[jp]["date"]
                        if jd == "":
                            dtresult = "FAIL"
                            continue
                        else:
                            jpdt = datetime.datetime.strptime(jd, "%m/%d/%y %H:%M:%S")
                            if ipdt == jpdt:
                                dtresult = "PASS"
                                continue
                            elif ipdt > jpdt:
                                t = (ipdt - jpdt).seconds
                            else:
                                t = (jpdt - ipdt).seconds
                            if t > timedelay:
                                dtresult = "FAIL"
                                break
                            else:
                                dtresult = "PASS"
            hostd[ip]["date check"] = dtresult
        except Exception:
            continue

    # NTP source ip address check
    # it should be same on all storage controllers
    ntpsrccheck = ""
    for ip in hostd.keys():
        ipntp = hostd[ip]["ntp source"]
        if ipntp == "":
            ntpsrccheck = "FAIL"
        else:
            for jp in hostd.keys():
                if ip == jp:
                    continue
                elif ipntp == hostd[jp]["ntp source"]:
                    ntpsrccheck = "PASS"
                else:
                    ntpsrccheck = "FAIL"
                    break
        hostd[ip].update({"ntp source check": ntpsrccheck})

    # Check package & versions on each controller
    packagecheck = ""
    # First will count no of packages on each controller
    for ip in hostd.keys():
        ipkgl = hostd[ip]["package & versions"]
        if ipkgl:
            cnt = len(ipkgl)
            for jp in hostd.keys():
                if ip == jp:
                    continue
                elif cnt == len(hostd[jp]["package & versions"]):
                    packagecheck = "PASS"
                else:
                    packagecheck = "FAIL"
                    break
            break
        else:
            packagecheck = "FAIL"
            break
    # Now will check package and version on each controller
    if packagecheck == "PASS":
        for ip in hostd.keys():
            ipkgl = hostd[ip]["package & versions"]
            for pk in ipkgl:
                pkg = ""
                ver = ""
                l = pk.split()
                try:
                    pkg = l[0]
                    ver = l[1]
                except Exception:
                    pass
                for jp in hostd.keys():
                    if ip == jp:
                        continue
                    elif packagecheck == "FAIL":
                        break
                    else:
                        jpkgl = hostd[jp]["package & versions"]
                        for line in jpkgl:
                            if pkg in line:
                                if ver in line:
                                    packagecheck = "PASS"
                                else:
                                    packagecheck = "FAIL"
                                    break
                if packagecheck == "FAIL":
                    break
            if packagecheck == "FAIL":
                break
    for ip in hostd.keys():
        hostd[ip]["check package & versions"] = packagecheck
    # check Iptables count
    # check for at least 44 and same across all nodes
    iptst = ""
    for ip in hostd.keys():
        try:
            ipcnt = int(hostd[ip]["iptables count"])
        except Exception:
            continue
        if ipcnt < 44:
            iptst = "FAIL"
            break
        elif iptst == "FAIL":
            break
        else:
            for jp in hostd.keys():
                try:
                    jpcnt = int(hostd[jp]["iptables count"])
                except Exception:
                    continue
                if jpcnt < 44:
                    iptst = "FAIL"
                    break
                elif ip == jp:
                    continue
                elif ipcnt == jpcnt:
                    iptst = "PASS"
                else:
                    iptst = "FAIL"
                    break
    for ip in hostd.keys():
        hostd[ip]["check iptables"] = iptst

    # Check the below things on each controller
    nwdetail = OrderedDict()
    cvm = {}
    testsum = OrderedDict()
    testdetail = OrderedDict()
    nwtestsum = OrderedDict()
    nwtestdetail = OrderedDict()

    #############################################################
    # Check on all HX Controller
    # Create instance of SSHClient object
    for ip in hxips:
        try:
            print("\nHX Controller: " + str(ip))
            # Initiate SSH Connection
            client.connect(hostname=ip, username=hxusername, password=hxpassword, timeout=time_out)
            msg = "\nSSH connection established to HX Node: " + ip
            log_msg(INFO, msg)
            # log_msg("", msg)
            testsum[ip] = OrderedDict()
            testdetail[ip] = OrderedDict()

            # 1. Cluster services check
            # Progressbar
            pbar = ProgressBarThread()
            pbar.start("Cluster services check     ")
            log_msg(INFO, "Progressbar Started")
            cluster_services_check(ip)
            # stop progressbar
            pbar.stop("COMPLETE")
            log_msg(INFO, "Progressbar Stopped")

            # 2. ZooKeeper and Exhibitor check
            # Progressbar
            pbar = ProgressBarThread()
            pbar.start("ZooKeeper & Exhibitor check")
            log_msg(INFO, "Progressbar Started")
            zookeeper_check(ip)
            # stop progressbar
            pbar.stop("COMPLETE")
            log_msg(INFO, "Progressbar Stopped")

            # 3. HDD health check
            # Progressbar
            pbar = ProgressBarThread()
            pbar.start("HDD health check           ")
            log_msg(INFO, "Progressbar Started")
            hdd_check(ip)
            # stop progressbar
            pbar.stop("COMPLETE")
            log_msg(INFO, "Progressbar Stopped")

            # 4. Pre-Upgrade Check
            # Progressbar
            pbar = ProgressBarThread()
            pbar.start("Pre-Upgrade Check          ")
            log_msg(INFO, "Progressbar Started")
            pre_upgrade_check(ip)
            # stop progressbar
            pbar.stop("COMPLETE")
            log_msg(INFO, "Progressbar Stopped")

            # 5. HyperV check
            # Progressbar
            pbar = ProgressBarThread()
            pbar.start("Hyper-V check              ")
            log_msg(INFO, "Progressbar Started" + "\r")
            hyperv_check(ip)
            # stop progressbar
            pbar.stop("COMPLETE")
            log_msg(INFO, "Progressbar Stopped" + "\r")

            # Close connection
            client.close()

            # Create report file
            create_sub_report(ip)

        except KeyboardInterrupt:
            sys_exit(0)

        except Exception as e:
            msg = "\nNot able to establish SSH connection to HX Node: " + ip
            log_msg(INFO, msg)
            # log_msg("", msg)
            log_msg(ERROR, str(e))
            # sys_exit(0)
            # stop progressbar
            pbar.stop("INCOMPLETE")
            log_msg(INFO, "Progressbar Stopped")
            continue

    ###############################################################
    # Display the HX test result
    display_hx_result()

    # Hyper-V Check
    print("")
    print("\n" + "#" * 80)
    print("\t\t\tHyper-V check:")
    print("\r" + "#" * 80)
    print("\nHyper-V Clusters: " + ", ".join(hypervlist))
    print("")

    # Display the Hyper-V test result
    display_hyperv_result()

    # Print Report to file
    create_main_report(clustername)

    # End
    sys.exit(0)