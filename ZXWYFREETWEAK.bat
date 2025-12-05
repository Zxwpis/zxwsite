@ECHO off
title ZXWY Tweaks - Requesting Admin
MODE 50,60
color 02
echo.
echo.
echo          ZXWY Tweaks - Requesting Admin
Reg.exe add HKLM /F >nul 2>&1
if %errorlevel% neq 0 start "" /wait /I /min powershell -NoProfile -Command start -verb runas "'%~s0'" && exit /b

chcp 65001

reg add "HKCU\Console" /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul 2>&1

set "ESC="

title  
cls
MODE 22,6
cls

MODE 194,115

cls
echo. 
echo     Welcome %USERNAME%, To ZXWY Tweaks!
echo. 

goto main
 
:main

title ZXWY FREE Tweaks

:: Change Window Size
MODE 122,16

MODE 220,174

cls
echo.
echo.                             
echo.                                           
echo.                                           ███████╗██╗  ██╗██╗    ██╗██╗   ██╗
echo.                                           ╚══███╔╝╚██╗██╔╝██║    ██║╚██╗ ██╔╝   
echo.                                             ███╔╝  ╚███╔╝ ██║ █╗ ██║ ╚████╔╝ 
echo.                                            ███╔╝   ██╔██╗ ██║███╗██║  ╚██╔╝    
echo.                                           ███████╗██╔╝ ██╗╚███╔███╔╝   ██║    
echo.                                           ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝    ╚═╝   
echo.
echo.                                    %ESC%[32m[%ESC%[37m R %ESC%[32m]%ESC%[37m Make a restore point (strongly recomended)%ESC%[0m
echo.                                    %ESC%[32m^________________________________________________
echo.                                    %ESC%[32m^------------------------------------------------                                                 
echo.
echo.                %ESC%[32m[%ESC%[37m 1 %ESC%[32m]%ESC%[37m Windows Tweaks       %ESC%[32m^|       [%ESC%[37m 2 %ESC%[32m]%ESC%[37m RAM Tweaks           %ESC%[32m^|       [%ESC%[37m 3 %ESC%[32m] %ESC%[37m Clean Up
echo.                %ESC%[32m^________________________________________________________________________________________
echo.                %ESC%[32m^----------------------------------------------------------------------------------------
echo.
echo.                                 %ESC%[32m[%ESC%[37m 4 %ESC%[32m]%ESC%[37m Storage Tweaks       %ESC%[32m^|       [%ESC%[37m 5 %ESC%[32m] %ESC%[37m Input Lag Tweaks 
echo.                %ESC%[32m^________________________________________________________________________________________
echo.                %ESC%[32m^----------------------------------------------------------------------------------------
echo.
echo.
echo.
echo.                                             %ESC%[32m[%ESC%[37m D %ESC%[32m]%ESC%[37m Discord%ESC%[0m %ESC%[32m[%ESC%[37m Z %ESC%[32m]%ESC%[37m Our Site%ESC%[0m
echo.                                             %ESC%[32m^____________________________
echo.                                             %ESC%[32m^----------------------------
echo.

set /p input=
if /i %input% == R goto res
if /i %input% == 1 goto win
if /i %input% == 2 goto ram
if /i %input% == 3 goto clean
if /i %input% == 4 goto stor
if /i %input% == 5 goto input
if /i %input% == d start https://discord.gg/CYk5zyHY
if /i %input% == Z start https://zxwsite.vercel.app/
echo "%input%" isn't a right choice, try again!
goto main

:priority
cls
echo.
echo. 
echo.                                                               ███████╗██╗  ██╗██╗    ██╗██╗   ██╗
echo.                                                               ╚══███╔╝╚██╗██╔╝██║    ██║╚██╗ ██╔╝   
echo.                                                                 ███╔╝  ╚███╔╝ ██║ █╗ ██║ ╚████╔╝ 
echo.                                                                ███╔╝   ██╔██╗ ██║███╗██║  ╚██╔╝    
echo.                                                               ███████╗██╔╝ ██╗╚███╔███╔╝   ██║    
echo.                                                               ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝    ╚═╝
echo.
echo.                %ESC%[32m[%ESC%[37m 1 %ESC%[32m]%ESC%[37m Optimize MMCSS                  %ESC%[32m^|       [%ESC%[37m 2 %ESC%[32m] %ESC%[37m Service Prioirty                 %ESC%[32m^|       [%ESC%[37m 3 %ESC%[32m] %ESC%[37m Game Priority%ESC%[0m
echo.                %ESC%[32m^___________________________________________________________________________________________________________________________
echo.                %ESC%[32m^---------------------------------------------------------------------------------------------------------------------------
echo.
echo.                %ESC%[32m[%ESC%[37m 4 %ESC%[32m]%ESC%[37m Win32 Priority Seperation       %ESC%[32m^|       [%ESC%[37m 5 %ESC%[32m] %ESC%[37m Thread Priority                  %ESC%[32m^|       [%ESC%[37m 6 %ESC%[32m] %ESC%[37m System Responsivness%ESC%[0m
echo.                %ESC%[32m^___________________________________________________________________________________________________________________________
echo.                %ESC%[32m^---------------------------------------------------------------------------------------------------------------------------
echo.
echo.                %ESC%[32m[%ESC%[37m 7 %ESC%[32m]%ESC%[37m IRQ8 Priority                   %ESC%[32m^|       [%ESC%[37m 8 %ESC%[32m] %ESC%[37m IRQ16 Priority                   %ESC%[32m^|       [%ESC%[37m 9 %ESC%[32m] %ESC%[37m Crss Prioirty%ESC%[0m
echo.                %ESC%[32m^___________________________________________________________________________________________________________________________
echo.                %ESC%[32m^---------------------------------------------------------------------------------------------------------------------------
echo.
echo.                %ESC%[32m[%ESC%[37m 10 %ESC%[32m]%ESC%[37m Window Manager Priority        %ESC%[32m^|       [%ESC%[37m 11 %ESC%[32m] %ESC%[37m Secret Service Priorities       %ESC%[32m^|       [%ESC%[37m 12%ESC%[32m] %ESC%[37m Secret Priority Tweaks%ESC%[0m
echo.                %ESC%[32m^___________________________________________________________________________________________________________________________
echo.                %ESC%[32m^---------------------------------------------------------------------------------------------------------------------------
echo.
echo.
echo.                                                                           %ESC%[32m[%ESC%[37m X %ESC%[32m]%ESC%[37m back
echo.

set /p input=:
if /i %input% == 1 goto game
if /i %input% == 3 goto gamepriority
if /i %input% == 2 goto SvcPriority
if /i %input% == 4 goto w32prio
if /i %input% == 5 goto thrprio
if /i %input% == 6 goto sysrep
if /i %input% == 7 goto irq8
if /i %input% == 8 goto IRQ16
if /i %input% == 9 goto crss
if /i %input% == 10 goto wmngr
if /i %input% == 11 goto pr11
if /i %input% == 12 goto pr12
if /i %input% == X goto main

:pr11
for %%a in (
	fontdrvhost.exe
	dwm.exe
	lsass.exe
	svchost.exe
	WmiPrvSE.exe
	winlogon.exe
	audiodg.exe
	ntoskrnl.exe
	services.exe
) do (
	Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%a" /v "MitigationOptions" /t REG_BINARY /d "!mitigation_mask!" /f 
	Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%a" /v "MitigationAuditOptions" /t REG_BINARY /d "!mitigation_mask!" /f 
)
echo.
pause
goto :priority

:pr12
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "CapPercentage" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "SchedulingType" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "CapPercentage" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "SchedulingType" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "CapPercentage" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "SchedulingType" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "CapPercentage" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "SchedulingType" /t REG_DWORD /d "0" /f 

reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\BackgroundDefault" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Frozen" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNCS" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenPPLE" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Paused" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PausedDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Pausing" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PrelaunchForeground" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\ThrottleGPUInterference" /v "IsLowPriority" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\BackgroundDefault" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Frozen" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNCS" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenPPLE" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Paused" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PausedDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Pausing" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PrelaunchForeground" /v "IsLowPriority" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\ThrottleGPUInterference" /v "IsLowPriority" /t REG_DWORD /d "0" /f 

reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 

reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitLimit" /t REG_DWORD /d "4294967295" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitTarget" /t REG_DWORD /d "4294967295" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "BasePriority" /t REG_DWORD /d "82" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "OverTargetPriority" /t REG_DWORD /d "50" /f 

reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitLimit" /t REG_DWORD /d "4294967295" /f 
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitTarget" /t REG_DWORD /d "4294967295" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "ValueMax" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ValueMax" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
echo.
pause
goto :menu


:w32prio
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
echo.
pause
goto :priority

:gamepriority

cls
echo.
echo.
echo.                     ██████╗  █████╗ ███╗   ███╗███████╗    ██████╗ ██████╗ ██╗ ██████╗ ██████╗ ██╗████████╗██╗   ██╗
echo.                    ██╔════╝ ██╔══██╗████╗ ████║██╔════╝    ██╔══██╗██╔══██╗██║██╔═══██╗██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
echo.                    ██║  ███╗███████║██╔████╔██║█████╗      ██████╔╝██████╔╝██║██║   ██║██████╔╝██║   ██║    ╚████╔╝ 
echo.                    ██║   ██║██╔══██║██║╚██╔╝██║██╔══╝      ██╔═══╝ ██╔══██╗██║██║   ██║██╔══██╗██║   ██║     ╚██╔╝  
echo.                    ╚██████╔╝██║  ██║██║ ╚═╝ ██║███████╗    ██║     ██║  ██║██║╚██████╔╝██║  ██║██║   ██║      ██║   
echo.                     ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝    ╚═╝     ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   
echo.                                                                                                  
echo.                                                   Game specific Priority Tweaks
echo.                                                   %ESC%[32m^_____________________________
echo.                                                   %ESC%[32m^-----------------------------
echo.
echo.                                                
echo.                %ESC%[32m[%ESC%[37m 1 %ESC%[32m]%ESC%[37m Fortnite Priority       %ESC%[32m^|       [%ESC%[37m 2 %ESC%[32m] %ESC%[37m Valorant Priority       %ESC%[32m^|       [%ESC%[37m 3 %ESC%[32m] %ESC%[37m CSGO 2 Priority%ESC%[0m
echo.                %ESC%[32m^_______________________________________________________________________________________________________
echo.                %ESC%[32m^-------------------------------------------------------------------------------------------------------
echo.
echo.
echo.                                                               %ESC%[32m[%ESC%[37m X %ESC%[32m]%ESC%[37m back
echo.
echo. 
echo.

set /p input=:
if /i %input% == 1 goto fn
if /i %input% == 2 goto val
if /i %input% == 3 goto cs2
if /i %input% == X goto priority

:cs2
for %%i in (cs2.exe) do (
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Application Name" /t REG_SZ /d "%%i.exe" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Version" /t REG_SZ /d "1.0" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Protocol" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local Port" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local IP" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local IP Prefix Length" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote Port" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote IP" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote IP Prefix Length" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "DSCP Value" /t REG_SZ /d "46" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Throttle Rate" /t REG_SZ /d "-1" /f
)
timeout /t 1 /nobreak > nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuPriorityClass" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "CpuPriority" /t REG_DWORD /d "42" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuPriority" /t REG_DWORD /d "42" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "Clock Rate" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "CpuThreadPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "CpuPriorityControl" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "CpuThreadCount" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "CpuPrioritySeperation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "RMHdcpKeyGlobZero" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "PowerLimitEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "IOPriorityClass" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "MaximumPerformanceEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "MaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "LowestPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "MinimumPerformanceEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "Io Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "HBFlagsSwitch" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "PowerSettingProfile" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "SleepStudyDeviceAccountingLevel" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "WatchdogResumeTimeout" /t REG_DWORD /d "120" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "WatchdogSleepTimeout" /t REG_DWORD /d "300" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "POSTTime" /t REG_DWORD /d "8323" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "BootmgrUserInputTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "FwPOSTTime" /t REG_DWORD /d "8323" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuSpeed" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /ve /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "CpuCoresAlways" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "CpuUtilization" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "LatencyPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "RenderingSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "RenderingPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "LatencySpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "RenderingPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "LatencyPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "CpuSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuRenderingPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "SpreadPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuMax" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "MinPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "PerformancePriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "PerformanceSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuMaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "CpuMaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuAccelerating" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "DisableHWAcceleration" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "MaxMultisampleSize" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "HwSchMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuThrottling" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuStutter" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "FadeIo" /t REG_DWORD /d "24" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuClockSwitchLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "UseReferenceRasterizer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "EnableHWAcceleration" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "SmoothBrightnessDefaultEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "SmoothBrightnessDefaultDisable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "EnableRenderingSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "EnableRenderingCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "EnableRenderingPowerSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "EnablePowerSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "EnablePowerControlSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "DisableRenderingContextPreemption" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "DisableRenderingPreemption" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "DisableFGBoostDecay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "IsRenderingLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "RenderingBasePriority" /t REG_DWORD /d "130" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "RenderingOverTargetPriority" /t REG_DWORD /d "80" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "RenderThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "EnableMidRenderingPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "RenderingPowerSteeringEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "PowerSavingVsyncOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "HwSchedMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "UnlimitedPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "SmoothStutterEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "EnableGpuTempData" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "EnableGpuCashing" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "EnableGpuSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "PPMEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "EnableGpuPowerControl" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "EnableGpuPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuIdleLatencyEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuIdleEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuPreemptionEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuBackgoundTaskPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuRenderingPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuBackgoundTaskLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "PowerSavingBackgoundTaskEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "RenderingSmoothStutterEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "RenderingStutterEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuRenderingLatencyEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuRenderingPriorityForBackgoundTask" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "PowerSavingRenderingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuClockSpeed" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuRenderingClockSpeed" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "UseBestResolution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "SmoothResolutionEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "TVSupportEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "GpuThrottleRate" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "SwapEffectUpgradeCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
echo.
pause
goto gamepriority

:fn

for %%i in (FortniteClient-Win64) do (
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Application Name" /t REG_SZ /d "%%i.exe" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Version" /t REG_SZ /d "1.0" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Protocol" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local Port" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local IP" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local IP Prefix Length" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote Port" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote IP" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote IP Prefix Length" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "DSCP Value" /t REG_SZ /d "46" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Throttle Rate" /t REG_SZ /d "-1" /f
)
timeout /t 1 /nobreak > nul

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuPriorityClass" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuPriority" /t REG_DWORD /d "42" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuPriority" /t REG_DWORD /d "42" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "Clock Rate" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuThreadPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuPriorityControl" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuThreadCount" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuPrioritySeperation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "RMHdcpKeyGlobZero" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "PowerLimitEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "IOPriorityClass" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "MaximumPerformanceEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "MaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "LowestPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "MinimumPerformanceEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "Io Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "HBFlagsSwitch" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "PowerSettingProfile" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "SleepStudyDeviceAccountingLevel" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "WatchdogResumeTimeout" /t REG_DWORD /d "120" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "WatchdogSleepTimeout" /t REG_DWORD /d "300" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "POSTTime" /t REG_DWORD /d "8323" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "BootmgrUserInputTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "FwPOSTTime" /t REG_DWORD /d "8323" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuSpeed" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /ve /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuCoresAlways" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuUtilization" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "LatencyPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "RenderingSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "RenderingPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "LatencySpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "RenderingPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "LatencyPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuRenderingPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "SpreadPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuMax" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "MinPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "PerformancePriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "PerformanceSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuMaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuMaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuAccelerating" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "DisableHWAcceleration" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "MaxMultisampleSize" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "HwSchMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuThrottling" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuStutter" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "FadeIo" /t REG_DWORD /d "24" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuClockSwitchLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "UseReferenceRasterizer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "EnableHWAcceleration" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "SmoothBrightnessDefaultEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "SmoothBrightnessDefaultDisable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "EnableRenderingSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "EnableRenderingCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "EnableRenderingPowerSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "EnablePowerSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "EnablePowerControlSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "DisableRenderingContextPreemption" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "DisableRenderingPreemption" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "DisableFGBoostDecay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "IsRenderingLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "RenderingBasePriority" /t REG_DWORD /d "130" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "RenderingOverTargetPriority" /t REG_DWORD /d "80" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "RenderThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "EnableMidRenderingPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "RenderingPowerSteeringEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "PowerSavingVsyncOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "HwSchedMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "UnlimitedPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "SmoothStutterEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "EnableGpuTempData" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "EnableGpuCashing" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "EnableGpuSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "PPMEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "EnableGpuPowerControl" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "EnableGpuPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuIdleLatencyEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuIdleEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuPreemptionEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuBackgoundTaskPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuRenderingPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuBackgoundTaskLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "PowerSavingBackgoundTaskEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "RenderingSmoothStutterEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "RenderingStutterEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuRenderingLatencyEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuRenderingPriorityForBackgoundTask" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "PowerSavingRenderingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuClockSpeed" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuRenderingClockSpeed" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "UseBestResolution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "SmoothResolutionEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "TVSupportEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "GpuThrottleRate" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "SwapEffectUpgradeCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
echo.
pause
goto gamepriority

:val
for %%i in (ValorantClient-Win64-Shipping.exe) do (
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Application Name" /t REG_SZ /d "%%i.exe" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Version" /t REG_SZ /d "1.0" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Protocol" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local Port" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local IP" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local IP Prefix Length" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote Port" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote IP" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote IP Prefix Length" /t REG_SZ /d "*" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "DSCP Value" /t REG_SZ /d "46" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Throttle Rate" /t REG_SZ /d "-1" /f
)
timeout /t 1 /nobreak > nul
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuPriorityClass" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "CpuPriority" /t REG_DWORD /d "42" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuPriority" /t REG_DWORD /d "42" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "Clock Rate" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "CpuThreadPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "CpuPriorityControl" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "CpuThreadCount" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "CpuPrioritySeperation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "RMHdcpKeyGlobZero" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "PowerLimitEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "IOPriorityClass" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "MaximumPerformanceEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "MaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "LowestPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "MinimumPerformanceEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "Io Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "HBFlagsSwitch" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "PowerSettingProfile" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "SleepStudyDeviceAccountingLevel" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "WatchdogResumeTimeout" /t REG_DWORD /d "120" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "WatchdogSleepTimeout" /t REG_DWORD /d "300" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "POSTTime" /t REG_DWORD /d "8323" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "BootmgrUserInputTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "FwPOSTTime" /t REG_DWORD /d "8323" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuSpeed" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /ve /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "CpuCoresAlways" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "CpuUtilization" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "LatencyPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "RenderingSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "RenderingPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "LatencySpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "RenderingPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "LatencyPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "CpuSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuRenderingPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "SpreadPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuMax" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "MinPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "PerformancePriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "PerformanceSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuMaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "CpuMaxPerformance" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuAccelerating" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "DisableHWAcceleration" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "MaxMultisampleSize" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "HwSchMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuThrottling" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuStutter" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "FadeIo" /t REG_DWORD /d "24" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuClockSwitchLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "UseReferenceRasterizer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "EnableHWAcceleration" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "SmoothBrightnessDefaultEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "SmoothBrightnessDefaultDisable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "EnableRenderingSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "EnableRenderingCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "EnableRenderingPowerSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "EnablePowerSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "EnablePowerControlSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "DisableRenderingContextPreemption" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "DisableRenderingPreemption" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "DisableFGBoostDecay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "IsRenderingLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "RenderingBasePriority" /t REG_DWORD /d "130" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "RenderingOverTargetPriority" /t REG_DWORD /d "80" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "RenderThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "EnableMidRenderingPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "RenderingPowerSteeringEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "PowerSavingVsyncOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "HwSchedMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "UnlimitedPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "SmoothStutterEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "EnableGpuTempData" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "EnableGpuCashing" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "EnableGpuSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "PPMEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "EnableGpuPowerControl" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "EnableGpuPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuIdleLatencyEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuIdleEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuPreemptionEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuBackgoundTaskPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuRenderingPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuBackgoundTaskLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "PowerSavingBackgoundTaskEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "RenderingSmoothStutterEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "RenderingStutterEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuRenderingLatencyEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuRenderingPriorityForBackgoundTask" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "PowerSavingRenderingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuClockSpeed" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuRenderingClockSpeed" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "UseBestResolution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "SmoothResolutionEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "TVSupportEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "GpuThrottleRate" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "SwapEffectUpgradeCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ValorantClient-Win64-Shipping.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f

echo.
pause
goto gamepriority

:game

Echo MMCSS Priority For Low Latency
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "BackgroundPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f
timeout /t 1 /nobreak > nul


Echo MMCSS Priority For Games
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "BackgroundPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f
echo.
pause
goto :priority

:wmngr
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
echo.
pause
goto :priority

:crss
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "4" /f

echo.
pause
goto :priority

:irq8
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
echo.
pause
goto :priority

:irq16
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f
echo.
pause
goto :priority



:SvcPriority

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
echo.
pause
goto :priority




:thrprio
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f
echo.
pause
goto :priority

:sysrep
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
echo.
pause
goto :priority

:debloat
cls
echo.
echo.                                           ███████╗██╗  ██╗██╗    ██╗██╗   ██╗
echo.                                           ╚══███╔╝╚██╗██╔╝██║    ██║╚██╗ ██╔╝   
echo.                                             ███╔╝  ╚███╔╝ ██║ █╗ ██║ ╚████╔╝ 
echo.                                            ███╔╝   ██╔██╗ ██║███╗██║  ╚██╔╝    
echo.                                           ███████╗██╔╝ ██╗╚███╔███╔╝   ██║    
echo.                                           ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝    ╚═╝
echo.
echo.                %ESC%[32m[%ESC%[37m 1 %ESC%[32m]%ESC%[37m Disable Startup Apps                 %ESC%[32m^|       [%ESC%[37m 2 %ESC%[32m] %ESC%[37m Debloat Chrome
echo.                %ESC%[32m^_____________________________________________________________________________________________
echo.                %ESC%[32m^---------------------------------------------------------------------------------------------
echo.
echo.                %ESC%[32m[%ESC%[37m 3 %ESC%[32m]%ESC%[37m Disable Useless Services             %ESC%[32m^|       [%ESC%[37m 4 %ESC%[32m] %ESC%[37m Uninstall Useless Preinstalled Apps
echo.                %ESC%[32m^_____________________________________________________________________________________________
echo.                %ESC%[32m^---------------------------------------------------------------------------------------------
echo.
echo.                %ESC%[32m[%ESC%[37m 5 %ESC%[32m]%ESC%[37m Disable Unneccesarry bloatware       %ESC%[32m^|       [%ESC%[37m 6 %ESC%[32m] %ESC%[37m Reinstall Useless Preinstalled Apps
echo.                %ESC%[32m^_____________________________________________________________________________________________
echo.                %ESC%[32m^---------------------------------------------------------------------------------------------
echo.
echo.                                                       %ESC%[32m[%ESC%[37m X %ESC%[32m]%ESC%[37m back
echo.

set /p input=:
if /i %input% == 1 goto startup
if /i %input% == 2 goto chrome
if /i %input% == 3 goto serv
if /i %input% == 4 goto windebloat
if /i %input% == 5 goto bl6
if /i %input% == 6 goto Fixes
if /i %input% == X goto main

:Fixes

chcp 437 > nul
Powershell -Command "Get-AppxPackage -allusers | foreach {Add-AppxPackage -register “$($_.InstallLocation)\appxmanifest.xml” -DisableDevelopmentMode}"
chcp 65001 > nul
pause
goto :debloat

:bl6
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Diagnostics\Performance" /v "DisableDiagnosticTracing" /t REG_DWORD /d "1" /f >nul 2>&1 
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d "0" /f
echo.
pause
goto :debloat



:serv

schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\MouseSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks /Change /TN "Microsoft\Windows\MUI\LPRemove" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WDI\ResolutionHost" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /Disable


echo.
pause
goto :debloat

:startup
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Discord" /t REG_BINARY /d "0300000066AF9C7C5A46D901" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Synapse3" /t REG_BINARY /d "030000007DC437B0EA9FD901" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Spotify" /t REG_BINARY /d "0300000070E93D7B5A46D901" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "EpicGamesLauncher" /t REG_BINARY /d "03000000F51C70A77A48D901" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "RiotClient" /t REG_BINARY /d "03000000A0EA598A88B2D901" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Steam" /t REG_BINARY /d "03000000E7766B83316FD901" /f 
echo.
pause
goto :debloat

:chrome

Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TranslateEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TaskManagerEndProcessEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SpellCheckServiceEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SpellcheckEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MediaRouterCastAllowAllIPs" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowDinosaurEasterEgg" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultGeolocationSetting" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultCookiesSetting" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultFileHandlingGuardSetting" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultFileSystemReadGuardSetting" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultFileSystemnv11GuardSetting" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultImagesSetting" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultPopupsSetting" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultSensorsSetting" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultSerialGuardSetting" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultWebBluetoothGuardSetting" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultWebUsbGuardSetting" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "EnableMediaRouter" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ShowCastIconInToolbar" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "CloudPrintProxyEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "PrintRasterizationMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "PrintingEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DefaultPluginsSetting" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SafeBrowsingProtectionLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SafeBrowsingExtendedReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "HomepageIsNewTabPage" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "HomepageLocation" /t REG_SZ /d "google.com" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "NewTabPageLocation" /t REG_SZ /d "google.com" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome\Recommended" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome\Recommended" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome\Recommended" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome\Recommended" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "Install{8A69D345-D564-463C-AFF1-A69D9E530F96}" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "TargetChannel{8A69D345-D564-463C-AFF1-A69D9E530F96}" /t REG_SZ /d "stable" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "Update{8A69D345-D564-463C-AFF1-A69D9E530F96}" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "Install{4CCED17F-7852-4AFC-9E9E-C89D8795BDD2}" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "AutoUpdateCheckPeriodMinutes" /t REG_DWORD /d "43200" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "DownloadPreference" /t REG_SZ /d "cacheable" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "UpdatesSuppressedStartHour" /t REG_DWORD /d "23" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "UpdatesSuppressedStartMin" /t REG_DWORD /d "48" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Google\Update" /v "UpdatesSuppressedDurationMin" /t REG_DWORD /d "55" /f
echo.
pause
goto :debloat

:windebloat
cls 
chcp 437 > nul
Powershell.exe -command "& {Get-AppxPackage *Microsoft.BingWeather* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling BingWeather
Powershell.exe -command "& {Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling GetHelp
Powershell.exe -command "& {Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling Getstarted
Powershell.exe -command "& {Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling Messaging
Powershell.exe -command "& {Get-AppxPackage *Microsoft.Microsoft3DViewer* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling Microsoft3DViewer
Powershell.exe -command "& {Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling MicrosoftSolitaireCollection
Powershell.exe -command "& {Get-AppxPackage *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling MicrosoftStickyNotes
Powershell.exe -command "& {Get-AppxPackage *Microsoft.MixedReality.Portal* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling MixedReality.Portal
Powershell.exe -command "& {Get-AppxPackage *Microsoft.OneConnect* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling OneConnect
Powershell.exe -command "& {Get-AppxPackage *Microsoft.People* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling People
Powershell.exe -command "& {Get-AppxPackage *Microsoft.Print3D* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling Print3D
Powershell.exe -command "& {Get-AppxPackage *Microsoft.SkypeApp* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling SkypeApp
Powershell.exe -command "& {Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage}
echo Uninstalling WindowsAlarms
Powershell.exe -command "& {Get-AppxPackage *Microsoft.WindowsCamera* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling WindowsCamera
Powershell.exe -command "& {Get-AppxPackage *microsoft.windowscommunicationsapps* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling windowscommunicationsapps
Powershell.exe -command "& {Get-AppxPackage *Microsoft.WindowsMaps* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling WindowsMaps
Powershell.exe -command "& {Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling WindowsFeedbackHub
Powershell.exe -command "& {Get-AppxPackage *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling WindowsSoundRecorder
Powershell.exe -command "& {Get-AppxPackage *Microsoft.YourPhone* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling YourPhone
Powershell.exe -command "& {Get-AppxPackage *Microsoft.ZuneMusic* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling ZuneMusic
Powershell.exe -command "& {Get-AppxPackage *Microsoft.HEIFImageExtension* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling HEIFImageExtension
Powershell.exe -command "& {Get-AppxPackage *Microsoft.WebMediaExtensions* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling WebMediaExtensions
Powershell.exe -command "& {Get-AppxPackage *Microsoft.WebpImageExtension* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling WebpImageExtension
Powershell.exe -command "& {Get-AppxPackage *Microsoft.3dBuilder* | Remove-AppxPackage}
timeout /t 1 /nobreak > NUL
echo Uninstalling 3dBuilder
PowerShell -Command "Get-AppxPackage -allusers *bing* | Remove-AppxPackage"
timeout /t 1 /nobreak > NUL
echo Uninstalling bing
PowerShell -Command "Get-AppxPackage -allusers *bingfinance* | Remove-AppxPackage"
timeout /t 1 /nobreak > NUL
echo Uninstalling bingfinance
PowerShell -Command "Get-AppxPackage -allusers *bingsports* | Remove-AppxPackage"
timeout /t 1 /nobreak > NUL
echo Uninstalling bingsports
timeout /t 1 /nobreak > NUL
PowerShell -Command "Get-AppxPackage -allusers *CommsPhone* | Remove-AppxPackage"
echo Uninstalling CommsPhone
timeout /t 1 /nobreak > NUL
PowerShell -Command "Get-AppxPackage -allusers *Drawboard PDF* | Remove-AppxPackage"
echo Uninstalling Drawboard PDF
timeout /t 1 /nobreak > NUL
echo Uninstalling Sway
PowerShell -Command "Get-AppxPackage -allusers *Sway* | Remove-AppxPackage"
echo Uninstalling WindowsAlarms
timeout /t 1 /nobreak > NUL
PowerShell -Command "Get-AppxPackage -allusers *WindowsAlarms* | Remove-AppxPackage"
echo Uninstalling WindowsPhone
PowerShell -Command "Get-AppxPackage -allusers *WindowsPhone* | Remove-AppxPackage"
timeout /t 1 /nobreak > NUL
echo Uninstalling zune
PowerShell -Command "Get-AppxPackage -allusers *zune* | Remove-AppxPackage"
timeout /t 1 /nobreak > NUL
echo Uninstalling MicrosoftEdge
PowerShell -Command "Get-AppxPackage Microsoft.MicrosoftEdge_41.16299.1004.0_netural__8wekyb3d8bbwe｜Remove-AppxPackage"
chcp 65001 > nul
echo.
pause
goto :debloat

:usb

cls
echo.
echo.

echo.                                           ███████╗██╗  ██╗██╗    ██╗██╗   ██╗
echo.                                           ╚══███╔╝╚██╗██╔╝██║    ██║╚██╗ ██╔╝   
echo.                                             ███╔╝  ╚███╔╝ ██║ █╗ ██║ ╚████╔╝ 
echo.                                            ███╔╝   ██╔██╗ ██║███╗██║  ╚██╔╝    
echo.                                           ███████╗██╔╝ ██╗╚███╔███╔╝   ██║    
echo.                                           ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝    ╚═╝ 
echo.
echo.                                    %ESC%[32m]%ESC%[37m All of those safe!%ESC%[0m
echo.                                    %ESC%[32m^________________________________________________
echo.                                    %ESC%[32m^------------------------------------------------  
echo.
echo.                %ESC%[32m[%ESC%[37m 1 %ESC%[32m]%ESC%[37m USB Thread Priority           %ESC%[32m^|       [%ESC%[37m 2 %ESC%[32m] %ESC%[37m Disable USB Power Savings etc.
echo.                %ESC%[32m^______________________________________________________________________________________
echo.                %ESC%[32m^--------------------------------------------------------------------------------------
echo.
echo.                %ESC%[32m[%ESC%[37m 3 %ESC%[32m]%ESC%[37m USB Controller Priority       %ESC%[32m^|       [%ESC%[37m 4 %ESC%[32m] %ESC%[37m Enable MSI for USB Controller
echo.                %ESC%[32m^______________________________________________________________________________________
echo.                %ESC%[32m^--------------------------------------------------------------------------------------
echo.
echo.                %ESC%[32m[%ESC%[37m 5 %ESC%[32m]%ESC%[37m Disale Hidden Usb Power Savings       
echo.                %ESC%[32m^______________________________________________________________________________________
echo.                %ESC%[32m^--------------------------------------------------------------------------------------
echo.   
echo.                                                       %ESC%[32m[%ESC%[37m X %ESC%[32m]%ESC%[37m back
echo.



set /p input=:
if /i %input% == 1 goto twkusb
if /i %input% == 2 goto savingp
if /i %input% == 3 goto usb1
if /i %input% == 4 goto umsi
if /i %input% == 5 goto usb2
if /i %input% == X goto main


:usb2

for %%a in (
	EnhancedPowerManagementEnabled
	AllowIdleIrpInD3
	EnableSelectiveSuspend
	DeviceSelectiveSuspended
	SelectiveSuspendEnabled
	SelectiveSuspendOn
	EnumerationRetryCount
	ExtPropDescSemaphore
	WaitWakeEnabled
	D3ColdSupported
	WdfDirectedPowerTransitionEnable
	EnableIdlePowerManagement
	IdleInWorkingState
) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f 
pause
goto :usb

:usb1

for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID 2^>nul') do set "str=%%i" & if "!str:PCI\VEN_=!" neq "!str!" (
echo DEL Sata controllers Device Priority
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
)
echo.
pause
goto :usb

:umsi

for /f %%i in ('wmic path Win32_USBController get PNPDeviceID') do set "str=%%i" & (
echo.DEL USB Device Priority
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
echo.Enable MSI Mode on USB
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
)
echo.
pause
goto :usb

:savingp

for /f %%u in ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "fid_D1Latency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "fid_D2Latency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "fid_D3Latency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f

)
echo.
pause
goto :usb

:twkusb

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\usbxhci\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f

echo.
pause
goto :usb

:bios
echo You selected Bios Tweaks!
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "AGPConcur" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "PCIConcur" /t REG_DWORD /d "1" /f
timeout /t 1 /nobreak > NUL

bcdedit /set tscsyncpolicy legacy
echo tscsyncpolicy legacy
timeout /t 1 /nobreak > NUL


bcdedit /set hypervisorlaunchtype off
echo Disable Hyper-V
timeout /t 1 /nobreak > NUL


bcdedit /set linearaddress57 OptOut
bcdedit /set increaseuserva 268435328
echo Linear Address 57
timeout /t 1 /nobreak > NUL


bcdedit /set isolatedcontext No
bcdedit /set allowedinmemorysettings 0x0
echo Kernel memory mitigations

timeout /t 1 /nobreak > NUL

bcdedit /set vsmlaunchtype Off
bcdedit /set vm No
Reg.exe add "HKLM\Software\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f
echo DMA memory protection and cores isolation
timeout /t 1 /nobreak > NUL


bcdedit /set x2apicpolicy Enable
bcdedit /set uselegacyapicmode No
echo Enable X2Apic
timeout /t 1 /nobreak > NUL


bcdedit /set configaccesspolicy Default
bcdedit /set MSI Default
bcdedit /set usephysicaldestination No
bcdedit /set usefirmwarepcisettings No
echo Enable Memory Mapping
timeout /t 1 /nobreak > NUL
echo All tweaks applied successfully!
pause
goto main

:bcd
echo You selected BCDedit!
bcdedit /set configaccesspolicy default
bcdedit /set MSI default
bcdedit /set usephysicaldestination no
bcdedit /set usefirmwarepcisettings no
bcdedit /deletevalue useplatformtick >nul 2>&1 
bcdedit /deletevalue useplatformclockJ >nul 2>&1 
bcdedit /set disabledynamictick yes
bcdedit /set tscsyncpolicy legacy
bcdedit /set x2apicpolicy enable
bcdedit /set ems no
bcdedit /set bootems no
bcdedit /set vm no
bcdedit /set sos no
bcdedit /set quietboot yes
bcdedit /set integrityservices disable
bcdedit /set bootux disabled
bcdedit /set bootlog no
bcdedit /set tpmbootentropy ForceDisable
bcdedit /set disableelamdrivers yes
bcdedit /set hypervisorlaunchtype off
bcdedit /set isolatedcontext no
bcdedit /set pae ForceDisable
bcdedit /set vsmlaunchtype off
echo All tweaks applied successfully!
pause
goto main

:res
echo You are creating restore point!
start "" "%SystemRoot%\System32\SystemPropertiesProtection.exe"
echo Restore point created successfully!
pause
goto main

:win
echo You selected Windows Tweaks!
bcdedit /deletevalue loadoptions >nul 2>&1
bcdedit /set allowedinmemorysettings 0x15000075 >nul 2>&1
bcdedit /set isolatedcontext yes >nul 2>&1
bcdedit /deletevalue useplatformclock >nul 2>&1
bcdedit /deletevalue disabledynamictick >nul 2>&1
bcdedit /deletevalue useplatformtick >nul 2>&1
bcdedit /deletevalue hypervisorlaunchtype >nul 2>&1
bcdedit /deletevalue tscsyncpolicy >nul 2>&1
bcdedit /deletevalue vsmlaunchtype >nul 2>&1
bcdedit /deletevalue tpmbootentropy >nul 2>&1
bcdedit /deletevalue lastknowngood >nul 2>&1
bcdedit /set forcefipscrypto no >nul 2>&1
bcdedit /deletevalue pae >nul 2>&1
bcdedit /deletevalue msi >nul 2>&1
bcdedit /set nx OptIn >nul 2>&1
bcdedit /set ems no >nul 2>&1
bcdedit /set bootems no >nul 2>&1
bcdedit /deletevalue vm >nul 2>&1
bcdedit /deletevalue firstmegabytepolicy >nul 2>&1
bcdedit /deletevalue avoidlowmemory >nul 2>&1
bcdedit /deletevalue nolowmem >nul 2>&1
bcdedit /set x2apicpolicy Enable >nul 2>&1
bcdedit /set configaccesspolicy Default >nul 2>&1
bcdedit /deletevalue usephysicaldestination >nul 2>&1
bcdedit /deletevalue usefirmwarepcisettings >nul 2>&1
pnputil /enable-device "ACPI\PNP0103\0" >nul 2>&1
pnputil /enable-device "ACPI\PNP0103\2&DABA3FF&0" >nul 2>&1
pnputil /enable-device "SWD\MSDAS\{CE958E9A-424F-4C88-86F4-11314821E75A}" >nul 2>&1
pnputil /disable-device "SWD\MMDEVAPI\MICROSOFTGSWAVETABLESYNTH" >nul 2>&1
pnputil /enable-device "ACPI\INT0800\4&1EA43E0E&0" >nul 2>&1
pnputil /enable-device "ACPI\PNP0C04\4&1EA43E0E&0" >nul 2>&1
pnputil /disable-device "ROOT\NDISVIRTUALBUS\0000" >nul 2>&1
pnputil /enable-device "ROOT\VDRVROOT\0000" >nul 2>&1
pnputil /disable-device "ROOT\RDPBUS\0000" >nul 2>&1
pnputil /enable-device "ACPI\MSFT0200\1" >nul 2>&1
pnputil /enable-device "ROOT\KDNIC\0000" >nul 2>&1
pnputil /enable-device "ROOT\VID\0000" >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcWatchdogProfileOffset /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcTimeout /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v IdealDpcRate /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v MaximumDpcQueueDepth /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v MinimumDpcRate /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcWatchdogPeriod /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaxDynamicTickDuration" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumSharedReadyQueueSize" /t REG_DWORD /d "128" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "BufferSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItem" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItemToNode" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItemEx" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueThreadIrp" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ExTryQueueWorkItem" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ExQueueWorkItem" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoEnqueueIrp" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "XMMIZeroingEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "UseNormalStack" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "UseNewEaBuffering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "StackSubSystemStackSize" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "QueueDepth" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "NvmeMaxReadSplit" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "NvmeMaxWriteSplit" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ForceFlush" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ImmediateData" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxSegmentsPerCommand" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxOutstandingCmds" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ForceEagerWrites" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxQueuedCommands" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxOutstandingIORequests" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "NumberOfRequests" /t REG_DWORD /d "1500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "IoSubmissionQueueCount" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "IoQueueDepth" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "HostMemoryBufferBytes" /t REG_DWORD /d "1500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ArbitrationBurst" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "QueueDepth" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "NvmeMaxReadSplit" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "NvmeMaxWriteSplit" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ForceFlush" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ImmediateData" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxSegmentsPerCommand" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxOutstandingCmds" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ForceEagerWrites" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxQueuedCommands" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxOutstandingIORequests" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "NumberOfRequests" /t REG_DWORD /d "1500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "IoSubmissionQueueCount" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "IoQueueDepth" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "HostMemoryBufferBytes" /t REG_DWORD /d "1500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ArbitrationBurst" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ENABLE_UNSAFE_COMMAND_BUFFER_REUSE" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ENABLE_RUNTIME_DRIVER_OPTIMIZATIONS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_RESOURCE_ALIGNMENT" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_MULTITHREADED" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_MULTITHREADED" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_DEFERRED_CONTEXTS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_DEFERRED_CONTEXTS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_ALLOW_TILING" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D11_ENABLE_DYNAMIC_CODEGEN" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_ALLOW_TILING" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_CPU_PAGE_TABLE_ENABLED" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_HEAP_SERIALIZATION_ENABLED" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_MAP_HEAP_ALLOCATIONS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectX" /v "D3D12_RESIDENCY_MANAGEMENT_ENABLED" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "CreateGdiPrimaryOnSlaveGPU" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DriverSupportsCddDwmInterop" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddSyncDxAccess" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddSyncGPUAccess" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddWaitForVerticalBlankEvent" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCreateSwapChain" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkFreeGpuVirtualAddress" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkOpenSwapChain" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkShareSwapChainObject" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkWaitForVerticalBlankEvent" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkWaitForVerticalBlankEvent2" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "SwapChainBackBuffer" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "TdrResetFromTimeoutAsync" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Priority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "BackgroundPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Priority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MMCSS" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
echo All tweaks applied successfully!
pause
goto main

:gpu

cls
echo.
echo.                             
echo.                                           
echo.                                             ███████╗██╗  ██╗██╗    ██╗██╗   ██╗
echo.                                             ╚══███╔╝╚██╗██╔╝██║    ██║╚██╗ ██╔╝   
echo.                                               ███╔╝  ╚███╔╝ ██║ █╗ ██║ ╚████╔╝ 
echo.                                              ███╔╝   ██╔██╗ ██║███╗██║  ╚██╔╝    
echo.                                             ███████╗██╔╝ ██╗╚███╔███╔╝   ██║    
echo.                                             ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝    ╚═╝       
echo.
echo.                           %ESC%[32m[%ESC%[37m WARNING %ESC%[32m]%ESC%[37m Please avoid this step if your PC have overheating issues
echo.                           %ESC%[32m^_____________________________________________________________________
echo.                           %ESC%[32m^---------------------------------------------------------------------
echo.
echo.
echo.                                           %ESC%[32m[%ESC%[37m 1 %ESC%[32m]%ESC%[37m AMD         %ESC%[32m^|     [%ESC%[37m 2 %ESC%[32m] %ESC%[37m Nvidia
echo.                                           %ESC%[32m^_____________________________________
echo.                                           %ESC%[32m^-------------------------------------
echo.
echo.                                                         %ESC%[32m[%ESC%[37m X %ESC%[32m]%ESC%[37m back
echo.
echo.
set /p input=
if /i %input% == 1 goto amd
if /i %input% == 2 goto nvid
if /i %input% == X goto main
echo "%input%" isn't a right choice, try again!
goto gpu

:nvid
echo You selected Nvidia Tweaks!
schtasks /Change /Disable /TN "NvDriverUpdateCheckDaily_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
schtasks /Change /Disable /TN "NVIDIA GeForce Experience SelfUpdate_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
schtasks /Change /Disable /TN "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
schtasks /Change /Disable /TN "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
schtasks /Change /Disable /TN "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
schtasks /Change /Disable /TN "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
schtasks /Change /Disable /TN "NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
schtasks /Change /Disable /TN "NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
schtasks /Change /Disable /TN "NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
cls
reg add "hklm\system\currentcontrolset\control\class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "perflevelsrc" /t reg_dword /d "0x00002222" /f > nul
reg add "hklm\system\currentcontrolset\control\class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "powermizerenable" /t reg_dword /d "00000001" /f > nul
reg add "hklm\system\currentcontrolset\control\class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "powermizerlevel" /t reg_dword /d "00000001" /f > nul
reg add "hklm\system\currentcontrolset\control\class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "powermizerlevelac" /t reg_dword /d "00000001" /f > nul
reg add "hklm\system\currentcontrolset\control\class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "enablecoreslowdown" /t reg_dword /d "00000000" /f > nul
reg add "hklm\system\currentcontrolset\control\class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "enablemclkslowdown" /t reg_dword /d "00000000" /f > nul
reg add "hklm\system\currentcontrolset\control\class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "enablenvclkslowdown" /t reg_dword /d "00000000" /f > nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableCudaContextPreemption" /t REG_DWORD /d "1" /f > nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemption" /t REG_DWORD /d "1" /f > nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMPcieLinkSpeed" /t REG_DWORD /d "4" /f > nul
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t REG_DWORD /d "1" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0002" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0003" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0004" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0005" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0006" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0007" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0008" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0009" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\NvTray" /v StartOnLogin /t REG_DWORD /d 0 /f
Reg add "HKEY_CURRENT_USER\Software\NVIDIA Corporation\Global\NVTweak" /v HideXGpuTrayIcon /t REG_DWORD /d 1 /f
Reg add "HKEY_CURRENT_USER\Software\NVIDIA Corporation\Global\NVTweak" /v Gestalt /t REG_DWORD /d 2 /f
Reg add "HKEY_CURRENT_USER\Software\NVIDIA Corporation\Global\NVTweak" /v DisplayPowerSaving /t REG_DWORD /d 0 /f
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\%GPU_DEVICE_CLASS_GUID_WITH_KEY%" /v RMHdcpKeyglobZero /t REG_DWORD /d 1 /f
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v DisableVidMemVBs /t REG_DWORD /d 0 /f
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D\Drivers" /v SoftwareOnly /t REG_DWORD /d 0 /f
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D\ReferenceDevice" /v AllowAsync /t REG_DWORD /d 1 /f
reg ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectDraw" /v EmulationOnly /t REG_DWORD /d 0 /f
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v DisplayPowerSaving /t REG_DWORD /d 0 /f
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\nvlddmkm\FTS" /v EnableGR535 /t REG_DWORD /d 0 /f
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v VsyncIdleTimeout /t REG_DWORD /d 0 /f
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v EnablePreemption /t REG_DWORD /d 0 /f
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyActivelyUsed /t REG_DWORD /d 1 /f
reg ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleLongTime /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleMonitorOff /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleShortTime /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleVeryLongTime /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleNoContext /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceIdle0 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceIdle0MonitorOff /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceIdle1 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceIdle1MonitorOff /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceMemory /t REG_DWORD /d 1 /f\
echo Tweaks applied successfully!
pause
goto main

:amd
echo You selected AMD Tweaks!
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class%GPU_DEVICE_CLASS_GUID_WITH_KEY%" /v PP_RTPMComputeF1Latency /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class%GPU_DEVICE_CLASS_GUID_WITH_KEY%" /v PP_DGBMMMaxTransitionLatencyUvd /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class%GPU_DEVICE_CLASS_GUID_WITH_KEY%" /v PP_DGBPMMaxTransitionLatencyGfx /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class%GPU_DEVICE_CLASS_GUID_WITH_KEY%" /v DalNBLatencyForUnderFlow /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class%GPU_DEVICE_CLASS_GUID_WITH_KEY%" /v BGM_LTRSnoopL1Latency /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class%GPU_DEVICE_CLASS_GUID_WITH_KEY%" /v BGM_LTRSnoopL0Latency /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class%GPU_DEVICE_CLASS_GUID_WITH_KEY%" /v BGM_LTRNoSnoopL1Latency /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class%GPU_DEVICE_CLASS_GUID_WITH_KEY%" /v BGM_LTRNoSnoopL0Latency /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class%GPU_DEVICE_CLASS_GUID_WITH_KEY%" /v BGM_LTRMaxSnoopLatencyValue /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class%GPU_DEVICE_CLASS_GUID_WITH_KEY%" /v BGM_LTRMaxNoSnoopLatencyValue /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableComputePreemption" /t REG_DWORD /d "0" /f > nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_DeLagEnabled" /t REG_DWORD /d "0" /f > nul
echo Tweaks applied successfully!
pause
goto main

:cpu
echo You selected CPU Tweaks!
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Processor" /v Capabilities /t REG_DWORD /d 0x0007e066 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Processor" /v Cstates /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Processor" /v CPPCEnable /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Processor" /v AllowPepPerfStates /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "AllowPepPerfStates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fDisablePowerManagement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\Default\VetoPolicy" /v "EA:EnergySaverEngaged" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\28\VetoPolicy" /v "EA:PowerStateDischarging" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Misc" /v "DeviceIdlePolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPCONCURRENCY" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleThreshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuLatencyTimer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuSlowdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "Threshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuDebuggingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorLatencyThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubThreshold" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubType" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValue" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMaximum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMinimum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueStep" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCurrent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValuePrevious" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueNext" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueLast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueFirst" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueIndex" /t REG_DWORD /d "42" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueName" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDescription" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueVisible" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueHidden" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadWrite" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueWriteOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueExecute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueNoExecute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueSystem" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueUser" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCustom" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAutomatic" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabledByDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabledByDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultManual" /t REG_DWORD /d "0" /f
echo Tweaks applied successfully!
pause
goto main

:ram

cls
echo.
echo.                             
echo.                                           
echo.                                           ███████╗██╗  ██╗██╗    ██╗██╗   ██╗
echo.                                           ╚══███╔╝╚██╗██╔╝██║    ██║╚██╗ ██╔╝   
echo.                                             ███╔╝  ╚███╔╝ ██║ █╗ ██║ ╚████╔╝ 
echo.                                            ███╔╝   ██╔██╗ ██║███╗██║  ╚██╔╝    
echo.                                           ███████╗██╔╝ ██╗╚███╔███╔╝   ██║    
echo.                                           ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝    ╚═╝                                              
echo.
echo.
echo.
echo.                             %ESC%[32m[%ESC%[37m 1 %ESC%[32m]%ESC%[37m 2 GB       %ESC%[32m^|       [%ESC%[37m 2 %ESC%[32m] %ESC%[37m 3 GB       %ESC%[32m^|       [%ESC%[37m 3 %ESC%[32m] %ESC%[37m 4 GB%ESC%[0m
echo.          %ESC%[32m^____________________________________________________________________________________________________
echo.          %ESC%[32m^----------------------------------------------------------------------------------------------------
echo.
echo.                             %ESC%[32m[%ESC%[37m 4 %ESC%[32m]%ESC%[37m 6 GB       %ESC%[32m^|       [%ESC%[37m 5 %ESC%[32m] %ESC%[37m 8 GB       %ESC%[32m^|       [%ESC%[37m 6 %ESC%[32m] %ESC%[37m 16 GB%ESC%[0m
echo.          %ESC%[32m^____________________________________________________________________________________________________
echo.          %ESC%[32m^----------------------------------------------------------------------------------------------------
echo.
echo.                             %ESC%[32m[%ESC%[37m 7 %ESC%[32m]%ESC%[37m 24 GB      %ESC%[32m^|       [%ESC%[37m 8 %ESC%[32m] %ESC%[37m 32 GB      %ESC%[32m^|       [%ESC%[37m 9 %ESC%[32m] %ESC%[37m 64 GB%ESC%[0m
echo.          %ESC%[32m^____________________________________________________________________________________________________
echo.          %ESC%[32m^----------------------------------------------------------------------------------------------------
echo.
echo.                             %ESC%[32m[%ESC%[37m 10 %ESC%[32m]%ESC%[37m Optimize SSH            %ESC%[32m^|                   [%ESC%[37m 11 %ESC%[32m] %ESC%[37m Ram Tweaks
echo.          %ESC%[32m^____________________________________________________________________________________________________
echo.          %ESC%[32m^----------------------------------------------------------------------------------------------------
echo.
echo.                             [%ESC%[37m 12 %ESC%[32m]%ESC%[37m Disable MC%ESC%[0m              %ESC%[32m^|                   [%ESC%[37m 13 %ESC%[32m] %ESC%[37m Disable Page Combining
echo.          %ESC%[32m^____________________________________________________________________________________________________
echo.          %ESC%[32m^----------------------------------------------------------------------------------------------------
echo.
echo.                             [%ESC%[37m 14 %ESC%[32m]%ESC%[37m Disable Prefetch%ESC%[0m        %ESC%[32m^|                   [%ESC%[37m 15 %ESC%[32m] %ESC%[37m Disable Superfetch
echo.          %ESC%[32m^____________________________________________________________________________________________________
echo.          %ESC%[32m^----------------------------------------------------------------------------------------------------
echo.
echo.                                                       %ESC%[32m[%ESC%[37m X %ESC%[32m]%ESC%[37m back
echo.
echo.
set /p input=
if /i %input% == X goto main
if /i %input% == 1 goto 2g
if /i %input% == 2 goto 3g
if /i %input% == 3 goto 4g
if /i %input% == 4 goto 6g
if /i %input% == 5 goto 8g
if /i %input% == 6 goto 16g
if /i %input% == 7 goto 24g
if /i %input% == 8 goto 32g
if /i %input% == 9 goto 64g
if /i %input% == 10 goto svc
if /i %input% == 11 goto reged
if /i %input% == 12 goto memsk
if /i %input% == 13 goto memski
if /i %input% == 14 goto preftch
if /i %input% == 15 goto superfetch
echo "%input%" isn't a right choice, try again!
goto main

:superfetch
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\memory management\prefetchparameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f 
echo.
pause
goto :ram

:memsk
chcp 437 > nul
PowerShell -Command "Disable-MMAgent -PageCombining"
chcp 65001 > nul
echo.
pause
goto :ram

:memski
chcp 437 > nul
PowerShell -Command "Disable-MMAgent -MemoryCompression"
chcp 65001 > nul
echo.
pause
goto :ram

:preftch
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f

echo.
pause
goto :ram

:reged

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolQuota" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolSize" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolQuota" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SecondLevelDataCache" /t REG_DWORD /d "1024" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionPoolSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionViewSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemPages" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PhysicalAddressExtension" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolQuota" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolSize" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolQuota" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SecondLevelDataCache" /t REG_DWORD /d "1024" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionPoolSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionViewSize" /t REG_DWORD /d "192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemPages" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PhysicalAddressExtension" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PoolUsageMaximum" /t REG_DWORD /d "96" /f

echo.
pause
goto :ram

:svc
for /f "skip=1" %%i in ('wmic os get TotalVisibleMemorySize') do if not defined TOTAL_MEMORY set "TOTAL_MEMORY=%%i" & set /a SVCHOST=%%i+1024000
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "!SVCHOST!" /f 
echo.
pause
goto :ram

:2g
echo You selected 2 GB RAM Tweak!
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "2097152" /f > nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IOPageLockLimit" /t REG_DWORD /d "2097152" /f > nul
echo Tweaks applied successfully!
pause
goto :ram

:3g
echo You selected 3 GB RAM Tweak!
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "3145728" /f > nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IOPageLockLimit" /t REG_DWORD /d "3145728" /f > nul
echo Tweaks applied successfully!
pause
goto :ram

:4g
echo You selected 4 GB RAM Tweak!
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "4194304" /f > nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IOPageLockLimit" /t REG_DWORD /d "4194304" /f > nul
echo Tweaks applied successfully!
pause
goto :ram

:6g
echo You selected 6 GB RAM Tweak!
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "6291456" /f > nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IOPageLockLimit" /t REG_DWORD /d "6291456" /f > nul
echo Tweaks applied successfully!
pause
goto :ram

:8g
echo You selected 8 GB RAM Tweak!
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "8388608" /f > nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IOPageLockLimit" /t REG_DWORD /d "8388608" /f > nul
echo Tweaks applied successfully!
pause
goto :ram

:16g
echo You selected 16 GB RAM Tweak!
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "16777216" /f > nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IOPageLockLimit" /t REG_DWORD /d "16777216" /f > nul
echo Tweaks applied successfully!
pause
goto :ram

:24g
echo You selected 24 GB RAM Tweak!
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "25165824" /f > nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IOPageLockLimit" /t REG_DWORD /d "25165824" /f > nul
echo Tweaks applied successfully!
pause
goto :ram

:32g
echo You selected 32 GB RAM Tweak!
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "33554432" /f > nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IOPageLockLimit" /t REG_DWORD /d "33554432" /f > nul
echo Tweaks applied successfully!
pause
goto :ram

:64g
echo You selected 64 GB RAM Tweak!
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "67108864" /f > nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IOPageLockLimit" /t REG_DWORD /d "67108864" /f > nul
echo Tweaks applied successfully!
pause
goto :ram


:clean
sc config ALG start=disabled
sc config AJRouter start=disabled
sc config lfsvc start=disabled
sc config RemoteRegistry start=disabled
sc config WpcMonSvc start=disabled
sc config SEMgrSvc start=disabled
sc config SCardSvr start=disabled
sc config Netlogon start=disabled
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Enable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Enable
sc config CscService start=disabled
sc config icssvc start=disabled
sc config wisvc start=disabled
sc config RetailDemo start=disabled
sc config WalletService start=disabled
sc config Fax start=disabled
sc config WbioSrvc start=disabled
sc config iphlpsvc start=disabled
sc config wcncsvc start=disabled
sc config fhsvc start=disabled
sc config SysMain start= auto
sc config DiagTrack start= auto
sc config RetailDemo start= manual
sc config TabletInputService start= manual
sc config XboxNetApiSvc start= demand
sc config XblAuthManager start= demand
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "1" /f
sc config XblGameSave start= demand
sc config XboxGipSvc start= demand
sc config PhoneSvc start=disabled
sc config seclogon start=disabled
sc config FrameServer start=disabled
sc config PcaSvc start=disabled
sc config DPS start=disabled
sc config MapsBroker start=disabled
sc config bthserv start=disabled
sc config BDESVC start=disabled
sc config BthAvctpSvc start=disabled
sc config WpcMonSvc start=disabled
sc config DiagTrack start=disabled
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Enable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Enable
sc config CertPropSvc start=disabled
sc config WdiServiceHost start=disabled
sc config lmhosts start=disabled
sc config WdiSystemHost start=disabled
sc config TrkWks start=disabled
sc config WerSvc start=disabled
sc config TabletInputService start=disabled
sc config EntAppSvc start=disabled
sc config diagnosticshub.standardcollector.service start=disabled
sc config DmEnrollmentSvc start=disabled
sc config PNRPAutoReg start=disabled
sc config AXInstSV start=disabled
sc config lfsvc start=disabled
del /s /f /q c:\windows\temp\*.*
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks /Change /TN "Microsoft\Windows\MUI\LPRemove" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable
schtasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable
echo Apps / Features removed successfully!
pause
goto main

:netw
ipconfig /release
ipconfig /renew
ipconfig /flushdns
netsh winsock reset
netsh int ip reset
netsh interface ip delete arpcache
for /f "tokens=*" %%a in ('netsh interface show interface ^| findstr /c:"Connected"') do (
    set "line=%%a"
    for /f "tokens=1,2,3 delims= " %%b in ("!line!") do (
        netsh interface set interface name="%%d" admin=disable
        timeout /t 2 >nul
        netsh interface set interface name="%%d" admin=enable
    )
)
cls
chcp 1252
PowerShell Disable-NetAdapterLso -Name "*"
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}"
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}"
netsh interface teredo set state disabled
netsh interface 6to4 set state disabled
netsh winsock reset
netsh int isatap set state disable
netsh int ip set global taskoffload=enabled
netsh int ip set global neighborcachelimit=4096
netsh int tcp set global timestamps=disabled
netsh int tcp set heuristics disabled
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global congestionprovider=ctcp
netsh int tcp set supplemental Internet congestionprovider=CTCP
netsh int tcp set global chimney=disabled
netsh int tcp set global ecncapability=disabled
netsh int tcp set global rss=enabled
netsh int tcp set global rsc=disabled
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=enabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set security mpp=disabled
netsh int tcp set security profiles=disabled
PowerShell Disable-NetAdapterChecksumOffload -Name "*"
PowerShell Disable-NetAdapterLso -Name "*"
PowerShell Disable-NetAdapterRsc -Name "*"
PowerShell Disable-NetAdapterIPsecOffload -Name "*"
PowerShell Disable-NetAdapterPowerManagement -Name "*"
PowerShell Disable-NetAdapterQos -Name "*"
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "%%n" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "AdvancedEEE" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "DisableDelayedPowerUp" /t REG_SZ /d "2" /f
Reg.exe add "%%n" /v "*EEE" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EEE" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnablePME" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnablePowerManagement" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableWakeOnLan" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "GigaLite" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "NicAutoPowerSaver" /t REG_SZ /d "2" /f
Reg.exe add "%%n" /v "PowerDownPll" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "PowerSavingMode" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "S5WakeOnLan" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "ULPMode" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "WakeOnDisconnect" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "*WakeOnPattern" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "AdvancedEEE" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "GigaLite" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "NicAutoPowerSaver" /t REG_SZ /d "2" /f 
Reg.exe add "%%n" /v "PowerDownPll" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "PowerSavingMode" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "S5WakeOnLan" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "ULPMode" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "WakeOnDisconnect" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "*WakeOnPattern" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "WakeOnLink" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f 
Reg.exe add "%%n" /v "JumboPacket" /t REG_SZ /d "1514" /f 
Reg.exe add "%%n" /v "TransmitBuffers" /t REG_SZ /d "4096" /f 
Reg.exe add "%%n" /v "ReceiveBuffers" /t REG_SZ /d "512" /f 
Reg.exe add "%%n" /v "IPChecksumOffloadIPv4" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "LsoV1IPv4" /t REG_SZ /d "0" /f  
Reg.exe add "%%n" /v "LsoV2IPv4" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "LsoV2IPv6" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "PMARPOffload" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "PMNSOffload" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "UDPChecksumOffloadIPv6" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "UDPChecksumOffloadIPv4" /t REG_SZ /d "0" /f 
Reg.exe add "%%n" /v "RSS" /t REG_SZ /d "1" /f 
Reg.exe add "%%n" /v "*NumRssQueues" /t REG_SZ /d "2" /f 
Reg.exe add "%%n" /v "RSSProfile" /t REG_SZ /d "3" /f 
Reg.exe add "HKLM\System\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "0200" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "1700" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckFrequency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckTicks" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "CongestionAlgorithm" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MultihopSets" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d "16384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "16384" /f
for /f %%q in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%q" /v InterfaceMetric /t REG_DWORD /d 0000055 /f
for /f %%q in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%q" /v TCPNoDelay /t REG_DWORD /d 0000001 /f
for /f %%q in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%q" /v TcpAckFrequency /t REG_DWORD /d 0000001 /f
for /f %%q in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%q" /v TcpDelAckTicks /t REG_DWORD /d 0000000 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPDelAckTicks" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPDelAckTicks" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
netsh int tcp set global dca=enabled
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
netsh int ipv6 set state disabled
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "20" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f 
Reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "04" /f
Reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f
Reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MessageNumberLimit" /t REG_DWORD /d "256" /f
echo Network tweaks applied successfully!
pause
goto main

:stor
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SD\IdleState\1" /v "IdleExitEnergyMicroJoules" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SD\IdleState\1" /v "IdleExitEnergyMicroJoules" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SD\IdleState\1" /v "IdleExitEnergyMicroJoules" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SD\IdleState\1" /v "IdleExitEnergyMicroJoules" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage\SD\IdleState\1" /v "IdleExitEnergyMicroJoules" /t REG_DWORD /d "0" /f 
fsutil behavior set memoryusage 2 >nul 2>&1
fsutil behavior set mftzone 4 >nul 2>&1
fsutil behavior set Disabledeletenotify 1 >nul 2>&1
fsutil behavior set encryptpagingfile 0 >nul 2>&1
pause
goto main

:input
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\usbxhci\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f 	
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f 	
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f 	
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "fid_D1Latency" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "fid_D2Latency" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "fid_D3Latency" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f 	
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f 	
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f 	
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f 	
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f 	
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f 
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%s\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%s\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f 
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%s\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%s\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%s\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f 
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f > nul
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f > nul
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f > nul
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f > nul
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f > nul
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f > nul
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f > nul
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
bcdedit /set configaccesspolicy default
bcdedit /set MSI default
bcdedit /set usephysicaldestination no
bcdedit /set usefirmwarepcisettings no
bcdedit /deletevalue useplatformtick
bcdedit /deletevalue useplatformclockJ
bcdedit /set disabledynamictick yes
bcdedit /set tscsyncpolicy legacy
bcdedit /set x2apicpolicy enable
bcdedit /set ems no
bcdedit /set bootems no
bcdedit /set vm no
bcdedit /set sos no
bcdedit /set quietboot yes
bcdedit /set integrityservices disable
bcdedit /set bootux disabled
bcdedit /set bootlog no
bcdedit /set tpmbootentropy ForceDisable
bcdedit /set disableelamdrivers yes
bcdedit /set hypervisorlaunchtype off
bcdedit /set isolatedcontext no
bcdedit /set pae ForceDisable
bcdedit /set vsmlaunchtype off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\943c8cb6_6f93_4227_ad87_e9a3feec08d1" /v "Attributes" /t REG_SZ /d "2" /
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "BackgroundPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\19cbb8fa_5279_450e_9fac_8a3d5fedd0c1\12bbebe6_58d6_4636_95bb_3217ef867c1a" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\245d8541_3943_4422_b025_13a784f679b7" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441_1930_4402_8d77_b2bebba308a3\0853a681_27c8_4100_a2fd_82013e970683" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441_1930_4402_8d77_b2bebba308a3\48e6b7a6_50f5_4782_a5d4_53bb8f07e226" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441_1930_4402_8d77_b2bebba308a3\d4e98f31_5ffe_4ce1_be31_1b38b384c009" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\44f3beca_a7c0_460e_9df2_bb8b99e0cba6\3619c3f2_afb2_4afc_b0e9_e7fef372de36" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\4faab71a_92e5_4726_b531_224559672d19" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\501a4d13_42af_4429_9fd1_a8218c268e20\ee12f906_d277_404b_b6da_e5fa1a576df5" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\5FB4938D_1EE8_4b0f_9A3C_5036B0AB995C\DD848B2A_8A5D_4451_9AE2_39CD41658F6C" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\68AFB2D9_EE95_47A8_8F50_4115088073B1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\F15576E8_98B7_4186_B944_EAFA664402D9" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\8619B916_E004_4dd8_9B66_DAE86F806698\468FE7E5_1158_46EC_88BC_5B96C9E44FD0" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\8619B916_E004_4dd8_9B66_DAE86F806698\49CB11A5_56E2_4AFB_9D38_3DF47872E21B" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\8619B916_E004_4dd8_9B66_DAE86F806698\60C07FE1_0556_45CF_9903_D56E32210242" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\8619B916_E004_4dd8_9B66_DAE86F806698\82011705_FB95_4D46_8D35_4042B1D20DEF" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\8619B916_E004_4dd8_9B66_DAE86F806698\9FE527BE_1B70_48DA_930D_7BCF17B44990" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\8619B916_E004_4dd8_9B66_DAE86F806698\C763EE92_71E8_4127_84EB_F6ED043A3E3D" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\9596FB26_9850_41fd_AC3E_F7C3C00AFD4B\03680956_93BC_4294_BBA6_4E0F09BB717F" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\9596FB26_9850_41fd_AC3E_F7C3C00AFD4B\10778347_1370_4ee0_8bbd_33bdacaade49" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\9596FB26_9850_41fd_AC3E_F7C3C00AFD4B\34C7B99F_9A6D_4b3c_8DC7_B6693B78CEF4" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\DE830923_A562_41AF_A086_E3A2C6BAD2DA\13D09884_F74E_474A_A852_B6BDE8AD03A8" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\DE830923_A562_41AF_A086_E3A2C6BAD2DA\5C5BB349_AD29_4ee2_9D0B_2B25270F7A81" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\DE830923_A562_41AF_A086_E3A2C6BAD2DA\E69653CA_CF7F_4F05_AA73_CB833FA90AD4" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\75b0ae3f_bce0_45a7_8c89_c9611c25e100" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\893dee8e_2bef_41e0_89c6_b55d0929964c" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\94D3A615_A899_4AC5_AE2B_E4D8F634367F" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251_82be_4824_96c1_47b60b740d00\bc5038f7_23e0_4960_96da_33abaf5935ec" /v "Attributes" /t REG_DWORD /d "2" /f
echo Input tweaks applied successfully!
pause
goto main

:kbm
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "DelayBeforeAcceptance" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last BounceKey Setting" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Delay" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Repeat" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Wait" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f 
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f 
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "MouseWheelRouting" /t REG_DWORD /d "0" /f 
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "Beep" /t REG_SZ /d "No" /f 
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "ExtendedSounds" /t REG_SZ /d "No" /f 
Reg.exe add "HKU\.DEFAULT\Control Panel\Sound" /v "Beep" /t REG_SZ /d "no" /f 
Reg.exe add "HKU\.DEFAULT\Control Panel\Sound" /v "ExtendedSounds" /t REG_SZ /d "no" /f 
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f 
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f 
Reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "MouseWheelRouting" /t REG_DWORD /d "0" /f 
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "Beep" /t REG_SZ /d "No" /f 
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "ExtendedSounds" /t REG_SZ /d "No" /f 
Reg.exe add "HKU\.DEFAULT\Control Panel\Sound" /v "Beep" /t REG_SZ /d "no" /f 
Reg.exe add "HKU\.DEFAULT\Control Panel\Sound" /v "ExtendedSounds" /t REG_SZ /d "no" /f 
Reg.exe add "HKCU\Control Panel\Mouse" /v "ActiveWindowTracking" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "Beep" /t REG_SZ /d "No" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickHeight" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickSpeed" /t REG_SZ /d "500" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickWidth" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "ExtendedSounds" /t REG_SZ /d "No" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverHeight" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverWidth" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseTrails" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000c0cc0c0000000000809919000000000040662600000000000033330000000000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000a800000000000000e00000000000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SnapToDefaultButton" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SwapMouseButtons" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorSensitivity" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorUpdateInterval" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "IRRemoteNavigationDelta" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "AttractionRectInsetInDIPS" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "DistanceThresholdInDIPS" /t REG_DWORD /d "40" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismDelayInMilliseconds" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismUpdateIntervalInMilliseconds" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "VelocityInDIPSPerSecond" /t REG_DWORD /d "360" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
echo Input tweaks applied successfully!
pause
goto main

:pwr
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0AABB002-A307-447e-9B81-1D819DF6C6D0}" /v "Name" /t REG_SZ /d "SustainedPerf" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0AABB002-A307-447e-9B81-1D819DF6C6D0}" /v "Pri" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0c3d5326-944b-4aab-8ad8-fe422a0e50e0}" /v "Name" /t REG_SZ /d "MultimediaQos" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0c3d5326-944b-4aab-8ad8-fe422a0e50e0}" /v "Pri" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}" /v "Name" /t REG_SZ /d "LowLatency" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}" /v "Pri" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{4569E601-272E-4869-BCAB-1C6C03D7966F}" /v "Name" /t REG_SZ /d "LowPower" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{4569E601-272E-4869-BCAB-1C6C03D7966F}" /v "Pri" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{8BC6262C-C026-411d-AE3B-7E2F70811A13}" /v "Name" /t REG_SZ /d "Standby" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{8BC6262C-C026-411d-AE3B-7E2F70811A13}" /v "Pri" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{a4a61b5f-f42c-4d23-b3ab-5c27df9f0f18}" /v "Name" /t REG_SZ /d "EntryLevelPerf" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{a4a61b5f-f42c-4d23-b3ab-5c27df9f0f18}" /v "Pri" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{c04a802d-2205-4910-ae98-3b51e3bb72f2}" /v "Name" /t REG_SZ /d "Background" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{c04a802d-2205-4910-ae98-3b51e3bb72f2}" /v "Pri" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{D4140C81-EBBA-4e60-8561-6918290359CD}" /v "Name" /t REG_SZ /d "GameMode" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{D4140C81-EBBA-4e60-8561-6918290359CD}" /v "Pri" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{EE1E4F72-E368-46b1-B3C6-5048B11C2DBD}" /v "Name" /t REG_SZ /d "Constrained" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{EE1E4F72-E368-46b1-B3C6-5048B11C2DBD}" /v "Pri" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}" /v "TimeLimitInSeconds" /t REG_DWORD /d "1" /f
echo Power tweaks applied successfully!
pause
goto main