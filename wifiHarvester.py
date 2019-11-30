'''
Wi-Fi Harvester 1.0

Author: Phillip Kittelson
School: Champlain College
Course: DFS-510, Scripting for Digital Forensics
Date: 25 Nov 2019
'''

import subprocess
from prettytable import PrettyTable
import socket
import uuid
import sys


def wifiHarvester():
    print("Wi-Fi Harvester 1.0")
    print()
    
    # Create PrettyTable
    report = PrettyTable()
    
    # Set field names, alignment, and sort
    report.field_names = ['Network', 'Password','MAC Randomization','Connection Mode','SSID Count']
    report.align['Network'] = 'l'
    report.align['Password'] = 'l'
    report.align['Connection Mode'] = 'l'
    report.sortby = 'Network'

    #Gets the host name of the system
    hostName = socket.gethostname()
    print("Host Name: " + hostName)
    print()

    print("Checking saved Wi-Fi profiles...")
    # Iterate through profiles
    netshCommand = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8').split('\n')
    wifiProfiles = [i.split(":")[1][1:-1] for i in netshCommand if "All User Profile" in i]

    print("Extracting saved passwords...")
    for i in wifiProfiles:
        #Iterate through profile list and show security keys
        results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', i, 'key=clear']).decode('utf-8').split('\n')
        #Find profiles with security key present
        keyResults = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
        #Trying to determine if MAC Randomization is enabled
        macRandom = [b.split(":")[1][1:-1] for b in results if "MAC Randomization" in b]
        #Determine if the profile connects automatically or manually
        connectionMode = [b.split(":")[1][1:-1] for b in results if "Connection mode" in b]
        #Get the SSID count per profile
        ssidCount = [b.split(":")[1][1:-1] for b in results if "Number of SSIDs" in b]        
        
        # Strips [] from list
        keyResults = str(keyResults)[1:-1]
        macRandom = str(macRandom)[1:-1]
        connectionMode = str(connectionMode)[1:-1]
        ssidCount = str(ssidCount)[1:-1]
        
        #Add rows to pretty table
        if results:
            #If password found
            report.add_row([i, keyResults, macRandom, connectionMode, ssidCount])
        else:
            #If no password found
            report.add_row([i, "***NO PASSWORD FOUND***", macRandom, connectionMode, ssidCount])
    
    print("Generating Report...")
    
    #Uncomment to display PrettyTable in console
    #print(report)
    
    #Writes result to file, file name includes host name of system
    print("Writing Passwords to file...")
    f = open(hostName + "_passwords.txt", "w")
    f.write(str(report))
    f.write('\nNetwork = SSID'
            '\nPassword = security key for network'
            '\nMAC Randomization = If MAC Randomization is turned on'
            '\nConnection Mode = Automatic or manual connection'
            '\nSSID Count = If more than one SSID per profile')
    f.close()
    print("Operation Complete!")
    print()
    
    #Uncomment to keep console window open
    #input("Press 'Enter' to exit...")

wifiHarvester()