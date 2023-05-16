import subprocess
import sys

try:
    import nmap
except ImportError:
    print("[+] Installing Requarements libraries . . .")
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'python-nmap'])
    import nmap

target_ip = input('-| Enter the IP address or network range to scan: ')

print('-| Select a scan type:')
print('   [+] 1. Normal scan')
print('   [+] 2. OS detection scan')
print('   [+] 3. Vulnerability scan')
print('   [+] 4. Full scan')
print('   [+] 5. Expert scan')
print('   [+] 6. Firewall bypassing scan')
print('   [+] 7. Find all devices on the network')
scan_type = input('-| Enter the number of the scan type: ')

nm = nmap.PortScanner()

if scan_type == '1':
    nm.scan(target_ip, arguments='-sS -sV')
elif scan_type == '2':
    nm.scan(target_ip, arguments='-sS -O')
elif scan_type == '3':
    nm.scan(target_ip, arguments='-sS -sV --script vulners')
elif scan_type == '4':
    nm.scan(target_ip, arguments='-sS -sV -p-')
elif scan_type == '5':
    nm.scan(target_ip, arguments='-sS -sV -O -A -p- --script vulners')
elif scan_type == '6':
    nm.scan(target_ip, arguments='-sS -sV -T5 -f')
elif scan_type == '7':
    nm.scan(target_ip, arguments='-sn')

for host in nm.all_hosts():
    if nm[host].state() == 'up':
        print('----------------------------------------------------\n')
        print(' [+] Host: %s (%s)' % (host, nm[host].hostname()))
        print(' [+] State: %s' % nm[host].state(),'\n')
        if 'mac' in nm[host]['addresses']:
            print(' [+] MAC Address: %s' % nm[host]['addresses']['mac'],'\n')
        if 'vendor' in nm[host]['addresses']:
            print(' [+] Vendor: %s' % nm[host]['addresses']['vendor'],'\n')
        if 'osmatch' in nm[host]:
            print(' [+] OS Match: %s' % nm[host]['osmatch'][0]['name'])
            print(' [+] OS Accuracy: %s' % nm[host]['osmatch'][0]['accuracy'],'\n')
        for proto in nm[host].all_protocols():
            print(' [+] Protocol: %s' % proto,'\n')
            lport = list(nm[host][proto].keys())
            lport.sort()
            for port in lport:
                print(' [+] Port: %s\t | Service: %s' % (port, nm[host][proto][port]['name']))
                if 'vulners' in nm[host][proto][port].keys():
                    for vuln in nm[host][proto][port]['vulners']:
                        print(' [+] Vulnerability: %s' % vuln['title'])