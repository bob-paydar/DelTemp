# DelTemp for Windows  
**Programmer:** Bob Paydar  

---

## Overview
DelTemp is a lightweight console application that helps keep your Windows system clean by deleting unnecessary temporary files.  

It supports cleaning the following locations:
- The current user’s `%TEMP%` folder  
- The system-wide `C:\Windows\Temp` folder (requires administrator rights)  
- The Windows Recycle Bin (optional)  

DelTemp is safe to use: files that are locked or in use will be skipped. It automatically removes read-only, hidden, and system attributes before deletion, ensuring files can be removed when possible.  

---

## Features
- Cleans user `%TEMP%` folder  
- Optionally cleans system-wide `C:\Windows\Temp` (`--system`)  
  - Auto-elevates with UAC prompt if not run as Administrator  
- Optionally empties the Recycle Bin (`--recycle`)  
- Quiet mode for minimal output (`--quiet`)  
- Simple help command (`--help`)  
- Logs actions and errors to the console  
- Safe: skips files in use  

---

## Usage
**Syntax:**
```bash
DelTemp.exe [options]
```

**Options:**
```
--system    Include C:\Windows\Temp in the cleanup
            (auto-elevates if needed)

--recycle   Empty the Windows Recycle Bin

--quiet     Minimal output (errors still shown)

--help      Show this help message
```

**Examples:**
```bash
DelTemp.exe
```
Cleans only the current user’s `%TEMP%` folder.  

```bash
DelTemp.exe --system
```
Cleans both user `%TEMP%` and `C:\Windows\Temp` (with UAC prompt).  

```bash
DelTemp.exe --system --recycle
```
Cleans user `%TEMP%`, system temp, and empties Recycle Bin.  

```bash
DelTemp.exe --quiet
```
Cleans user `%TEMP%` silently, only showing warnings or errors.  

---

## Requirements
- Windows 10/11 (x64 recommended)  
- Microsoft Visual C++ runtime (statically linked when built)  
- Administrator rights required for cleaning `C:\Windows\Temp`  

---

## Notes
- Files currently in use by Windows or applications cannot be deleted and will be skipped automatically.  
- If elevation is cancelled when using `--system`, only the user’s `%TEMP%` folder will be cleaned.  
- It is safe to run DelTemp frequently.  

---

## Version
**DelTemp v1.0**  
