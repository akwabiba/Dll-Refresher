# Dll-Refresher

given a process id, we calculate the hash of .text section of the module from disk and the one mapped in memory
if the hashes are different. we Map a fresh copy of the module

# Usage
 
    .\Dll-Refresher.exe <PID> <module.dll>

# Ref

    https://blog.f-secure.com/hunting-for-amsi-bypasses/
    https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
