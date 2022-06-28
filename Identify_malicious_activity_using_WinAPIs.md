# Identify malicious activity using WinAPIs
Let's see how to use the WinAPI function to detect malicious activity.

## DLL Injection
1. Search for PID - `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`.
2. `OpenProcessVirtualAllocEx`, `WriteProcessMemory`.
3. `GetModuleHandle`, `GetProcAddress`.
4. `CreateRemoteThread`.



## APC Injection
Asynchronous Procedure Call injection.

### User Mode
For every thread, there is an APC Queue. When the thread is at an `Alertable` state (like when using `WaiteForMultipleObjectsEx`, `WaitForSingleObjectEx`), it is possible to set the thread to run a different code from the one in the queue.

1. Open thread - `OpenThread`.
2. Push the `LoadLibraryA` function onto the stack.
3. Call `QueueUserAPC` with the function, thread, and file name (`DLL`) which runs in the queue.

* Pay attention to the `svchost.exe`, which its threads are usually at the `Alerable` state.

### Kernel Mode
Restart the APC (using `KeInitializeApc`) - with parameters that indicates of running in user space:
1. `NormalRoutine` - different than `0`.
2. `ApcMode` - equal to `1`.
3. Call to `KeInsertQueueApc`.


## Windows Hooking
Detect using `SetWindowsHookEx`.
Malware prefers to choose a specific thread (`dwThreadId`) instead of loading the malware in every one of the threads of a process and performing the hook with a unique message (as `WH_CBT`).

After that, to call `SetNextHookEx` - also called *Threat Targeting*.
## Process Replacement
Overwriting the memory space of a running process with a malicious one. Which allows the malicious process the same privileges as the "replaced" process.

Detect by a pause - `CREATE_SUSPENDED` (`0x4`) as an argument to `CreateProcessA`.

## Process Doppelganging
Another injection method is used to inject a process into another process.

Detect:
1. Transact - overwrite a legitimate process (`notepad`, `svchost`, .etc) with a malicious executable.  API functions: `CreateTransaction`, `CreateFileTransacted`, `NtCreateTransaction`.
2. Load - load the malicious executable. API functions: `WriteFile`.
3. Rollback - rollback to the original executable. API functions: `RollbackTransaction`.
4. Animate - bring the "doppelganging" executable to life - run it. API functions: `NtCreateProcessEx`, `NtCreateThreadEx`.

