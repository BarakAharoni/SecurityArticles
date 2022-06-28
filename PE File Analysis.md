Let's see how to start reversing a PE file.
Portable Executable (PE) format is basically the format of executable file in Windows (`.exe`, `.dll`).

# Workflow
1. Basic Static Analysis
2. Basic Dynamic Analysis
3. Advanced Analysis
5. Create Report


# Basic Static Anlysis
The purpose of this method is to collect as many information as possible about the program without running it and withoout spending too much time on the investigation.

So, first of all, we need to fegure its *file type* (make sure it is really `PE`, and its version - `x32` or `x64` bit). We are also look for interesting *strings* as host and network artifacts (IP addresses, ports, URL addresses, Registry keys, .etc).
In addition, looking in a known malwares databases (`VirusTotal`) and signatures (`YARA`).


## File Information

### CFFExplorer
Allows to watch and patch the file, based on the PE format.

### PEFA
PE File Analysis tool which allows to get interesting information about the file and check for matching *Yara-Rules* signatures.
https://github.com/BarakAharoni/PEFA


## Suscicious Indicators

### Strings
A tool from *SysInternals Suite* which allows to export both *ASCII* and *UNICODE* strings of the file.

All strings: `strings.exe -a {file}`

All *UNICODE* strings: `strings.exe --encoding=-l {file}`

### PeStudio
GUI tool which contains various information about the file.


## Packer Detection

### DIE
Detect It Easy tool allows loading a PE file and check if it is packed or not.

### Exeinfo PE
Similar to DIE with its abilities.


# Basic Dynamic Analysis
In this method, we want to understand the program behavior, to know where to focus on our advanced analysis. 
Here, we are gonna running the program under an *isolated environment*, which need to be similar as possible to the environment of the program (Simulate services, running under dedicated program, .etc).


## What to do?
1. Take a snapshot of the VM (before running the program/ malware).
2. Simulates different services needed for the program (using *INetSim* or `httpd start` on a Linux machine conected to the VM).
3. Network sniffing (using *Wireshark* or *TcpDump*).
4. Monitor operation system artifacts - like files atachments, registry keys and more (using *ProcMon*, *RegShot*).
5. Taking memory dump after runnig the program for later analysis with *Volatility*.


## Running DLL
Because DLLs don't have entry point, they can't run by themselves.
We can run DLL by the following instructions:
1. By export function: `rundll32.exe, {DLLName}, {ExportArg}`
2. By export index: `rundll32.exe, {DLLName}, #{Index}`
3. Patching the `PE Header` to load the DLL (may use with *CFF Explorer*): `IMAGE_FILE_HEADER -> Characteristics field -> IMAGE_FILE_DLL (0x2000)
4. Install as a service: `net start {ServiceName}` and than `rundll32.exe {DLLName}, InstallService {ServiceName}`


## Services Simulation
Because we running the program (or malware) in an isolated environment, the program not always has access to systems, applications or relevant servers he may related on. As a result, we can miss important information about its behaviour in the network.
Therefore, we can simulate the relevant services like *DNS* or *Application Services* and document the program's actions.

### INetSim
Allows simulates several protocols: `HTTP, HTTP, SMTP, FTF, POP3, TFTP, .etc`.

Based on a configuration file located at: `/etc/inetsim/inetsim.conf`.

Log files: `/var/log/inetsim`, `/var/log/inetsim/service.log`.

File the program uses will saved at: `/var/lib/inetsim`.

Any of those, may be IOC of program behaviour.

Running: `inetsim`.

### httpd Service
Running the `httpd` services can help to define the VM as HTTP Server. So, when the program will try to contact with a HTTP Server, he contact with the monitored VM.

Pay attention that the program may try to access to a specific Web page - we can create one and give it the matches name!

Running: `httpd start`.

### FakeDNS
In addition, the monitored VM can uses as a DNS Server, so every DNS query will first get to it. With this tool we can map which IPs the program will try to connect with.

Running: `fakedns`.


## Network Sniffing
Looking for network indicators may lead as more understanding of the program - what protocols and ports it uses, which URLs to IP addreses it try to connect with and more.

### tcpdump
Allows network capture acording to the NIC

Running: `tcpdump -i {interface_name}`

### Wireshark
Network sniffer with a lot of abilities.

### Fiddler
Similar to *Wireshark* with its purpose. Also uses for debugging by being a proxy in the network - which allows to watch encrypted traffic (like HTTPS).

Verify that it configured: `Direct to HTTPS -> Decrypt HTTPS Traffic Auto Responder -> Enable Rules`.

### IPTables
We can redirect all the network traffic to a local port which belongs to our investigation host. 

Running: `iptables -t nat -A PREROUTING -i {interface_name} -j REDIRECT` or `accept-all-ips start`.

Abort: `iptables -t nat -D PREROUTING -i {interface_name} -j REDIRECT` or `accept-all-ips stop`.

### Listen with Netcat

`nc -nlvp {port} > {out_file}`

Then, see the evidence: `xdd {out_file} | more`.


## File System Behavior

### Process Explorer
Real-Time process viewer.

### Resource Hacker
Real-Time process viewer.

### APIMonitor
WinAPI functions monitoring. We can use it to look over specific API function used by the program (like Crypto function uses to encrypt or decrypt, etc).

* Open APIMonitor
* Choose `API Filter`
* `Monitor New Process -> Choose the process`
* `Summery -> Choose the wanted API call entry`
* `Hex Buffer -> show results`

### ProcMon
Real-Time powerfull process monitor.
Save evidenc to a `CSV` file: `File -> Save -> Format: Comma-Separated Values (CSV), Path: -> OK`.

### ProcDot
Graph-View of the process' behavior. We can load a `CSV` file which contains the process' information (from `ProcMon`).



# Advanced Analysis
Open the program in relevant *Disassemblers* and *Debuggers* for deep understanding of the program. Pay attention to *Anti-Reversing* and *Packing* techniques.

## IDA PRO
Powerfull Disassembler and Debugger.

## Ghidra
Open-Source Disassembler.

## x32dbg / x64dbg
Excellent Debugger.

# WinDbg
Original windows debugger.


# Report
Creates a full documented report which contains all the IOCs found in the investigation.
