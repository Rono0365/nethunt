import nmap
import socket


def N3thunt():
    nm = nmap.PortScanner() 
    cidr2='192.168.100.*'
    while True:
        try:
            try:
                a=nm.scan(hosts=cidr2, arguments='-sP') 

                for k,v in a['scan'].items(): 
                    if str(v['status']['state']) == 'up':
                        #print(str(v))
                        try:
                            #note:use the  mac adress ,because it's static
                            #note:identify devices on your network then
                            #note:add their  mac addresses as below
                            #print (str(v['addresses']['ipv4']) + ' => ' + str(v['addresses']['mac']))
                            devices = {'04:25:C5:9A:9C:D2':'router',
                                       #'74:8A:28:26:F6:EC':'kimu',
                                       #'78:3A:6C:4C:22:A1':'Rono',
                                       '44:E4:EE:C0:22:47':'T.V',
                                       '6C:C4:D5:51:F2:17':'Mom',#you "Key":"value" the key is the mac adress and the value is name of your choice
                                       '0C:EE:E6:C0:55:FA':'Dad',
                                       '80:ED:2C:B9:DE:9D':'chero',
                                       }
                            for i in str(v['addresses']['mac']):
                                macval = str(v['addresses']['mac'])
                                if not macval in devices:
                                    textd ="unknown device with ipaddress {} is using your WI-FI network".format(str(v['addresses']['ipv4']))
                                    print(textd)
                                    client_program(textd)
                                    break
                                """
                                else:
                                    print(str(v['addresses']['ipv4'])+"has connected")
                                    break
                                """
                        except:#exception for a specific device
                            if  not '192.168.100.2' in str(v['addresses']['ipv4']):
                                textd = "Unknown device with ip {} is using wifi".format(str(v['addresses']['ipv4']))
                                
                                print (textd)
            except ConnectionRefusedError:
                  print("lost connection")
                  continue
        except ConnectionAbortedError:
            print("lost connection")
            continue
        break
        return textd
N3thunt()
#nethunt by Rono

'''
expected results:
Unknown device with ip 192.168.100.47 is using wifi
Unknown device with ip 192.168.100.76 is using wifi
Unknown device with ip 192.168.100.83 is using wifi
'''
