Let's see what shellcodes are and how we can Identify and Analyze them.

# Background
Shellcode is a sequence of instructions (Opcodes) that represent hex-values and can appear in variant formats in the code (as strings). This sequence is used as a payload of the code to execute in memory after exploiting a vulnerability. 
Its name comes from the fact that attackers use it to get a shell on a system.

## Dependencies
Shellcodes have some dependencies that may make it a little bit harder to write them.

1. Length - Because shellcode exploits a specific vulnerability in the memory, the sequence needs to be efficient as possible. It means the attacker has to suit its length to the buffer's size, so all of the instructions will run in memory space.
If the shellcode's length will be larger than the buffer's size, there may be certain results like a program crash or even exploitation (like buffer overflow).
2. Unallowed characters - When characters like `'\r'`, `'\n'`, `0x00`, etc. appear in the shellcode, the code that is supposed to run will terminate and not be finished.
For example, when 'Null Bytes' ( like `0x00` value) are being read, the CPU recognized it as the end of the string (Null Terminator).

# Unix Shellcodes
The Unix operation system provides direct access to communicate and manage the Kernel - with the instruction `int 0x80`.
Therefore, when a System Call follows with that instruction will set, the shellcode will be given the ability to execute with high privileges without a special effort from the attacker.

# Windows Shellcodes
In Windows-based operation systems, creating a shellcode could be a little harder, due to memory protection mechanisms such as ASLR (Address Space Layout Randomization).

## Finding API function's addresses in memory
Most of the time, the shellcode is injected into a running process, therefore it doesn't have any prior knowledge about the memory state, and so about API function's addresses. 
Conclusion: it can't be based on static addresses.

Therefore, a shellcode is unable to use instruction as `Call CreateProcessA` or `jmp sub_40100000`, and must be running independently from its location to find the wanted API function and resolve the address manually. In other words, to find the DLL it wants to use regardless of addresses but based on the structure of the objects in the memory. That is also the reason it is called - Position Independent Code (PIC).

For example, to call to `GetProcAddress`, the shellcode needs to find the address of `Kernel32.dll` DLL.

So how can it be done?

## PEB - Process Environment Block
Thanks to the fact that the PEB object is loaded always at the same address to the memory - `FS:[0x30]`, a shellcode can use it!

What it needs to do:

1. Goes to the PEB object.
2. Passes through `PEB_LDR_DATA` object until it gets to `InMemoryOrderModuleList` linked list, which contains information about the processes' loaded modules. After this, the shellcode will hold the wanted module (usually `Kernel32.dll` is the third object).
3. Finds Base-Address to the wanted DLL, using the `DllBase` field.
4. Finds its Export Table.
5. Locates the wanted function (like `GetProcAddress`).
6. Gets the function's address using the `GetProcAddress` function.
7. Eventually, running the wanted function using its suitable parameters.

## Using SEH - Structured Exception Handling
The technique is about accessing the bottom of the SEH Chain, by entering the first property in TIB (Thread Information Block), which has a constant address - `FS:[0x0]`. 
It contains the default exception handler of `Kernel32.dll` module. 
To locate the wanted module's address, it is possible to go back to the memory addresses until finding the module's entry point(using the `MZ` signature or `0x5A4D` for example).

## Using TEB - Thread Environment Block
Like the SEH technique, it's possible to access the TEB object, which has a constant location in memory - `FS:[0x18]`. Passing through this object may lead you to the SEH Chain, as mentioned above.

## TopStack
This method is not very common, as it relies on having the address of the desired DLL which has the wanted API function inside the stack.

## Find API function by Hash
This technique is also called SFHA (Stephen Fewer's Hash API). It uses 4 bytes to represent the Hash value of `DLL!WinAPI` function inside `EAX` register. Then, a `JMP` to that address is being made to call that function.

Pay attention to which function is called from `EAX` and what parameters it gets (you can check them in MSDN). Then, compare with the real values in the memory. For example, if a shellcode calls the `Win_Exec` function, it will pass through every `DLL!WinApi` uses one of the other techniques, and with other parameters(we can identify them by `PUSH` instruction before the register call).

When we enter the parameter's memory address, we may know what's in there (maybe a `PS1` script or Encoded Commands..).

# Detection
After we understood a little bit about what shellcodes are, let's see how to detect them. 
Pay attention to de-obfuscated, decrypt an obfuscated or encrypted script to expose the shellcode!
Using behavior pattern
As mentioned above, a shellcode is an Opcodes sequence that represents instructions. Therefore, we can find this sequence and examine it.

If we have the malicious program's source code running the shellcode (like PowerShell or JavaScript), we can look for values/variables/strings that could represent the Opcodes, which may lead us to the shellcode itself.

Let's take a look at the instruction: `mov ebp, esp`. The characters' sequence the shellcode will use can be in several formats:
- Hexa-Decimal Values: `8B EC`
- Backslash Hexa-Decimal Values: `\x8B\EC`
- Percentage Unicode: `%u8B%EC`
- Backslash Unicode: `\u8B\uEC`
- Array: `[0x8B, 0xEC]`

After identifying that these characters' sequences can represent CPU instructions - we will focus on it.

# Dump the shellcode
After detecting a potential shellcode, dumping it out to a binary file is the first step to achieving our goal.
- `base64dump.py` tool - allows finding a section that may contain the shellcode and dumping it out to a binary file (`.bin`), which can be analyzed.
`base64dump.py -e {param} {file}`
*Parameters*:
1. `pu` - allows searching of strings used for Percent Unicode encoding (`%u`).
2. `bu` - allows searching for string uses for Backslash Unicode encoding (`\u`).
3. `hex` - allows searching for strings uses as hexadecimal values.
4. `base64` - allows searching for strings with Base64 encoding.
`base64dump.py -e {param} {file} -s {sectionID} -d > {outFile.bin}`
Allows to locate the wanted section by its ID, and dump it out to a binary file. Most of the time, the largest section will be selected.
`base64dump.py -e {param} {file} -s {sectionID} -a`
Show a Hex-View of the selected section.

- `objdump.py` tool - Allows dumping the shellcode while it is extracted.

- Using a Hex-Editor - A Hex-Editor can be used for removing the irrelevant sections. Therefore, only the shellcode remains and can be saved to a `.bin` file.

# How to analyze the shellcode?
A shellcode analysis can be performed in two main ways: Static and Dynamic analysis.

## Static analysis - Code analysis
In this way, the binary file which contains the shellcode will be converted to an executable file and will be loaded to a Disassembler (such as IDA PRO). Then, it will be analyzed as an executable file.

*Usage:*
- `shellcode2exe.py {file.bin}`
- `shellcode2exe.bat {32\64} {file.bin} {file.exe}`

## Dynamic analysis
`scdbg` tool - allows simulating execution of the shellcode for purpose of finding API functions that it uses, which can indicate a lot of its behavior.
- `scdbg -s {steps} -f {file.bin}`
- Running the GUI `scdbg` tool and launching the binary file to it.
- Using the `FindSC` will find the beginning of the shellcode in the loaded binary.

`jmp2it` tool - allows executing the shellcode under a dedicated process, which uses as a "shell" of executable. Therefore, attaching the debugger to the running process, enable you to debug the shellcode.
- `jmp2it {file.bin} {offset}` - the offset indicates the offset of the shellcode from the binary entry-point ( `0x0` for the start).

`shellcode_launcher.exe` - Works similar to the previous tool.

# Conclusion
In this writeup, we understood how to identify and analyze a shellcode using several tools.
 I hope you learned a thing or two from this article.
Also, you can find it at:
<iframe width="560" height="315" src="https://infosecwriteups.com/shellcode-analysis-313bf4ca4dec" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

Thanks for reading.
