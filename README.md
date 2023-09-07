> **Note**
> This project remains as an example or a tool, it is however outdated and you should use ClassDumper2/3 / SMemory API which are both actively developed.

# RTTIDumper
Injected Windows DLL that dumps Virtual Function Tables with Type Information from binaries including closed source binaries.

Only works with binaries compiled with Microsoft Visual Studio and contain Runtime Type information (RTTI).

## Goals
- [X] Extract Symbol Information about classes within a program incl. VFTables.
- [X] Demangle most symbols correctly. **Currently still testing**
- [X] Generate class Inheritance information from RTTI
- Further research and development in semi-automated C++ reverse engineering

## Using this project
Compile the dll to the same Bits as the target (x86 or x64)

The reason behind this is that 64bit still uses DWORD sized members
for the RTTI structures, but they are offsets, not direct memory pointers.
This means that you need to add the base address of the target module to the DWORD offset in 64bit mode.
e.g.
```c++
uintptr_t ModuleBaseAddress = GetBaseAddress..;
DWORD offset = ...;
uintptr_t address = offset + ModuleBaseAddress;
```

#References And Information
http://www.openrce.org/articles/full_view/23
