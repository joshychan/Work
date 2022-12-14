import pexpect
import re
import os
ip_address = '192.168.56.101'
username = 'prne'
password = 'cisco123!'
password_enable = 'class123!'
# Function for making an insecure remote connection to a device using Telnet
def device_connect_insecure(ip_address, username, password):
    # Connect to the device using Telnet
    session = pexpect.spawn('telnet ' + ip_address)
    session.expect('Username:')
    session.sendline(username)
    session.expect('Password:')
    session.sendline(password)
    
    # Return the pexpect session object
    return session

# Function for making a secure remote connection to a device using SSH
def device_connect_secure(ip_address, username, password, password_enable):
    # Connect to the device using SSH
    session = pexpect.spawn('ssh ' + username + '@' + ip_address)
    session.expect('password:')
    session.sendline(password)
    
    # Enter privileged mode on the device
    session.sendline('enable')
    session.expect('password:')
    session.sendline(password_enable)
    
    # Return the pexpect session object
    return session

def backup_config(ip_address, username, password, password_enable, remote_host, remote_path):
    # Connect to the device and the remote host using SSH
    device_session = device_connect_secure(ip_address, username, password, password_enable)
    remote_session = pexpect.spawn('ssh ' + username + '@' + remote_host)
    remote_session.expect('password:')
    remote_session.sendline(password)

    # Use pexpect to retrieve the current running configuration
    device_session.sendline('show running-config')
    device_session.expect('#')
    running_config = device_session.before

    # Use the os module to write the configuration output to a text file on the remote host
    remote_file = open(remote_path + 'config_backup.txt', 'w')
    remote_file.write(running_config)
    remote_file.close() 

def compare_running_startup(ip_address, username, password, password_enable):
    session = device_connect_secure(ip_address, username, password, password_enable)
    session.sendline('show running-config')
    session.expect('#')
    running_config = session.before

    # Use pexpect to retrieve the startup configuration
    session.sendline('show startup-config')
    session.expect('#')
    startup_config = session.before

    # Use the re module to parse the running and startup configuration outputs
    # and extract the relevant information
    running_config_lines = re.findall(r'^\S+', running_config, re.MULTILINE)
    startup_config_lines = re.findall(r'^\S+', startup_config, re.MULTILINE)

    # Compare the current running configuration with the startup configuration
    # and print the differences
    differences = set(running_config_lines) - set(startup_config_lines)
    print('Differences between running and startup configuration:')
    for line in differences:
        print(line)
def compare_running_offline(ip_address, username, password, password_enable, remote_host, remote_path):
    # Connect to the device using SSH and enter privileged mode
    session = device_connect_secure(ip_address, username, password, password_enable)

    # Use pexpect to retrieve the current running configuration
    session.sendline('show running-config')
    session.expect('#')
    running_config = session.before

    # Use pexpect to retrieve the local offline version from the remote host
    session.sendline('cat ' + remote_path)
    session.expect('#')
    offline_config = session.before

    # Use the re module to parse the running and offline configuration outputs
    # and extract the relevant information
    running_config_lines = re.findall(r'^\S+', running_config, re.MULTILINE)
    offline_config_lines = re.findall(r'^\S+', offline_config, re.MULTILINE)

    # Compare the current running configuration with the local offline version
    # and print the differences
    differences = set(running_config_lines) - set(offline_config_lines)
    print('Differences between running and offline configuration:')
    for line in differences:
        print(line)

def configure_loopback(ip_address, username, password, password_enable, loopback_ip, loopback_mask):

    session = device_connect_secure(ip_address, username, password, password_enable)
    session.sendline('configure terminal')
    session.expect('#')

    # Create a loopback interface on the router
    session.sendline('interface loopback 0')
    session.expect('#')

    # Assign an IP address to the loopback interface
    session.sendline('ip address 192.168.1.1 255.255.255.0')
    session.expect('#')

    # Save the changes to the router's configuration
    session.sendline('copy running-config startup-config')
    session.expect('#')

def show_loopback_ip(ip_address, username, password, password_enable):
    # Connect to the device using SSH and enter privileged mode
    session = device_connect_secure(ip_address, username, password, password_enable)

    # Use pexpect to retrieve the IP address of the loopback interface
    session.sendline('show ip interface loopback 0')
    session.expect('#')
    loopback_output = session.before

    # Use the re module to parse the output and extract the IP address
    loopback_ip_pattern = re.compile(r'Internet address is (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    loopback_ip_match = loopback_ip_pattern.search(loopback_output)
    loopback_ip = loopback_ip_match.group(1)

    # Print the IP address of the loopback interface
    print('IP address of loopback interface:', loopback_ip)

compare_running_offline('192.168.1.1', 'admin', 'cisco123', 'class123', '192.168.1.10', '/configs/device1.txt')