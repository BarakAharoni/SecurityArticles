Let's see how to start reversing a PE file.
Portable Executable (PE) format is basically the format of executable file in Windows (`.exe`, `.dll`).

# Investigation Workflow
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

## Suscicious Indicators
### Strings
A tool from *SysInternals Suite* which allows to export both *ASCII* and *UNICODE* strings of the file.

All strings: `strings.exe -a {file}`

All *UNICODE* strings: `strings.exe --encoding=-l {file}`

### PeStudio
GUI tool which contains various information about the file.

### PEFA
PE File Analysis tool which allows to get interesting information about the file and check for matching *Yara-Rules* signatures.
https://github.com/BarakAharoni/PEFA

## Packer Detection
### DIE
Detect It Easy tool allows loading a PE file and check if it is packed or not.

## Exeinfo PE
Similar to DIE with its abilities.

# Basic Dynamic Analysis
In this method, we want to understand the program behavior, to know where to focus on our advanced analysis. 
Here, we are gonna running the program under an *isolated environment*, which need to be similar as possible to the environment of the program (Simulate services, running under dedicated program, .etc).

In this method, documents all the evidence is really important! (Network truffic, actions that happend, what other artifacts in the OS the program is related to?).
At the end, we can take a *Real time memory dump* for later analysis (with `Volatility`).



# Advanced Analysis
Open the program in relevant *Disassemblers* and *Debuggers* for deep understanding of the program. Pay attention to *Anti-Reversing* and *Packing* techniques.

# Report
Creates a full documented report which contains all the IOCs found in the investigation.
