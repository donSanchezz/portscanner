# Donovan Saunches - 1804379

import sys
import os
import time
from queue import Queue
import socket
import threading
import subprocess
import struct
import paramiko

from typing import List, Any

target = "127.0.0.1"
queue = Queue()
open_ports = []
closed_ports = []


def menu():
    print("************Welcome to Portscanner Demo**************")
    print()

    choice = input("""
                      A: TCP Port Scan
                      B: UDP Port Scan
                      C: Remote Shutdown
                      D: OS Detection
                      E: Wake on LAN
                      Q: Exit

                      Please enter your choice: """)

    if choice == "A" or choice == "a":
        subMenuTCP()
    elif choice == "B" or choice == "b":
        subMenuUDP()
    elif choice == "C" or choice == "c":
        remShutdown()
    elif choice == "D" or choice == "d":
        OS_info()
    elif choice == "E" or choice == "e":
        wake_on_lan()
    elif choice == "Q" or choice == "q":
        print("Thanks for using Portscanner demo")
        sys.exit
    else:
        print("You must only select either A,B,C or D")
        print("Please try again")
        menu()


def subMenuTCP():
    print("************Welcome to Portscanner Demo**************")
    print("***************Mode Selection **************")
    print()

    choice = input("""
                         A: Scan the 1023 standardized ports
                         B: Scan the 48,128 reserved ports 
                         C: Scan the important ports only
                         D: Enter your own port(s)

                         Please enter a mode: """)

    if choice == "A" or choice == "a":
        run_scannerTCP(10, 1)
    elif choice == "B" or choice == "b":
        run_scannerTCP(10, 2)
    elif choice == "C" or choice == "c":
        run_scannerTCP(10, 3)
    elif choice == "D" or choice == "d":
        run_scannerTCP(10, 4)
    else:
        print("You must only select either A,B,C or D")
        print("Please try again")
        subMenuTCP()


def subMenuUDP():
    print("************Welcome to Portscanner Demo**************")
    print("***************Mode Selection **************")
    print()

    choice = input("""
                         A: Scan the 1023 standardized ports
                         B: Scan the 48,128 reserved ports 
                         C: Scan the important ports only
                         D: Enter your own port(s)

                         Please enter a mode: """)

    if choice == "A" or choice == "a":
        run_scannerUDP(2, 1)
    elif choice == "B" or choice == "b":
        run_scannerUDP(2, 2)
    elif choice == "C" or choice == "c":
        run_scannerUDP(2, 3)
    elif choice == "D" or choice == "d":
        run_scannerUDP(2, 4)
    else:
        print("You must only select either A,B,C or D")
        print("Please try again")
        subMenuUDP()


def portscanTCP(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        return True
    except:
        return False


def portscanUDP(port):
    try:
        message = 'ping'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)  # setting timeout of the code if it didn't receive any data
        sock.sendto(message.encode(), (target, port))  # sending a sample data to the server
        data, addr = sock.recvfrom(
            1024)  # if it receives a data with in a 3 second then it works. otherwise, it will return false
        return True
    except:
        return False


def get_ports(mode):
    # scans the 1023 standardized ports
    if mode == 1:
        for port in range(1, 1024):
            queue.put(port)
    # Add the 48,128 reserved ports to the scan
    elif mode == 2:
        for port in range(1, 49152):
            queue.put(port)
    # Important ports only
    elif mode == 3:
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 443]
        for port in ports:
            queue.put(port)
    # Enter your own port
    elif mode == 4:
        ports = input("Enter your ports (seperate by blank):")
        ports = ports.split()
        ports = list(map(int, ports))
        for port in ports:
            queue.put(port)


def workerTCP():
    while not queue.empty():
        port = queue.get()
        if portscanTCP(port):
            print("Port {} is open!".format(port))
            open_ports.append(port)
        else:
            print("Port {} is closed!".format(port))
            closed_ports.append(port)


def workerUDP():
    while not queue.empty():
        port = queue.get()
        if portscanUDP(port):
            print("Port {} is open!".format(port))
            open_ports.append(port)
        else:
            print("Port {} is closed!".format(port))
            closed_ports.append(port)


def run_scannerTCP(threads, mode):
    get_ports(mode)
    thread_list = []

    for t in range(threads):
        thread = threading.Thread(target=workerTCP)
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()

    choice = input("Do you want to output the data to a text document? (Y/N)")
    if choice == 'Y' or choice == 'y':
        with open("openports.txt", 'w') as filehandle:
            for openports in open_ports:
                filehandle.write('%s\n' % openports)
    else:
        menu()

    # print("Open ports are:", open_ports)


def run_scannerUDP(threads, mode):
    get_ports(mode)
    thread_list = []

    for t in range(threads):
        thread = threading.Thread(target=workerUDP)
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()

    choice = input("Do you want to output the data to a text document? (Y/N)")
    if choice == 'Y' or choice == 'y':
        with open("openports.txt", 'w') as filehandle:
            for openports in open_ports:
                filehandle.write('%s\n' % openports)
    else:
        menu()

    print("Open ports are:", open_ports)


def remShutdown():
    choice = input("""
                             A: Windows
                             B: Linux
                             Q: Exit

                             Please enter the machine type: """)

    if choice == "A" or choice == "a":
        machine = input("Enter the ip of the machine you'd want to shut down:")
        print(r'shutdown -s -t 0 -m \\%s' % machine)
        try:
            os.system(r'shutdown -s -t 0 -m \\%s' % machine)
            print("Machine was shut down successfully.")
        except:
            print("An error was encountered, the machine could not be shut downed.")
        menu()
    elif choice == "B" or choice == "b":
        port = 22
        host = input("Enter the ip of the machine you'd want to shut down:")
        username = input("Enter the username for the machine:")
        password = input("Enter the password for the machine:")
        try:
            cmd = "shutdown -h now"

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, port, username, password)

            stdin, stdout, stderr = ssh.exec_command(cmd)
            print("Machine was shutdown successfully")
        except:
            print("This machine could not be shut downed")
        menu()
    elif choice == "Q" or choice == 'q':
        menu()
    else:
        print("You must only select either A,B,or Q")
        print("Please try again")
        remShutdown()


def OS_info():
    ip = input("Please enter the IP of the machine you'd want to obtain the information from:")
    output = subprocess.getoutput('ping %s' % ip)

    val = output[-191] + output[-190]
    if val == '64':
        port = 22
        username = input("Enter the username for the machine:")
        password = input("Enter the password for the machine:")

        cmd = "lsb_release -a"

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port, username, password)

        stdin, stdout, stderr = ssh.exec_command(cmd)

        info = stdout.readlines()
        print(info)

        choice = input("Do you want to output the data to a text document? (Y/N)")
        if choice == 'Y' or choice == 'y':
            with open("OSinfo.txt", 'w+') as file:
                file.write(str(info))
        else:
            menu()


    # 128 is for Windows machine
    elif val == '28':
        print("This machine is of type Windows")

    else:
        print("The machine type is not recognized")
        menu()
    menu()


def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 0))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def wake_on_lan():
    # print(os.system("arp -a"))
    mac_address = input('Enter the mac address of the computer you want to wake up ')
    if len(mac_address) == 17:
        mac_address_fmt = mac_address.replace('-', '').replace(':', '')
        host_ip = get_host_ip()
        host = (host_ip[: host_ip.rindex('.') + 1] + '255', 9)
        data = ''.join(['FFFFFFFFFFFF', mac_address_fmt * 16])
        send_data = b''
        for i in range(0, len(data), 2):
            send_data = b''.join([send_data, struct.pack('B', int(data[i: i + 2], 16))])

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(send_data, host)
    else:
        print("Incorrect value for mac address, try again")
        time.sleep(5)
        wake_on_lan()
    menu()


menu()
