@echo off
setlocal enabledelayedexpansion
net session
if %errorlevel%==0 (
	echo Admin rights granted!
) else (
    echo Failure, no rights
	pause
    exit
)

cls

set /p answer=Have you answered all the forensics questions?[y/n]: 
	if /I {%answer%}=={y} (
		goto :menu
	) else (
		echo please go and answer them.
		pause
		exit
	)
	
:menu
	cls
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~Spokane Valley Tech~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "1)Account Policies		2)Local Policies"
	echo "3)Disable the Guest	    4)User management(New Menu)"
	echo "5)Group management   		6)File Share Mangement"
	echo "7)Service Mangement 		8)Windows Features"
	echo "9)Remote Desktop Config  	10)Screensaver config"
	echo "11)User Account Control   12)Disable AutoPlay"
	echo "13)Firewall Config        14)Windows Updates/Auto"
	echo "15)Media file Detect      16)RPC and RDP Configuration"
	echo "17)Disable IPv6           18)Scan for Hidden Files"
	echo "19)Startup Management     20)Scheuduled Tasks Management"
	echo "21)Windows Defender Menu  22)Powershell check"
	echo "23)Security Checks        24)Network checks(ports&stuff)"
	echo "25)Exploit/Script Scan    26)Server Hardening"
	echo "69)Exit				    70)Reboot"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	set /p answer=Please choose an option: 
		if "%answer%"=="1" goto :accountPolicies
		if "%answer%"=="2" goto :localPolicies
		if "%answer%"=="3" goto :disableGuest
		if "%answer%"=="4" goto :userManagement
		if "%answer%"=="5" goto :groupManagement
		if "%answer%"=="6" goto :fileSharesManagement
		if "%answer%"=="7" goto :servicesManagement
		if "%answer%"=="8" goto :windowsFeatures
		if "%answer%"=="9" goto :remDesk
		if "%answer%"=="10" goto :screensaver
		if "%answer%"=="11" goto :uacConfig
		if "%answer%"=="12" goto :autoPlayConfig
		if "%answer%"=="13" goto :firewallConfig
		if "%answer%"=="14" goto :autoUpdate
		if "%answer%"=="15" goto :badFiles
		if "%answer%"=="16" goto :rpcRdpEncryption
		if "%answer%"=="17" goto :disableIPv6
		if "%answer%"=="18" goto :scanHiddenFiles
		if "%answer%"=="19" goto :startupManagement
		if "%answer%"=="20" goto :taskSchedulerCleanup
		if "%answer%"=="21" goto :windowsSecurityConfig
		if "%answer%"=="22" goto :powershellCheck
		if "%answer%"=="23" goto :criticalChecks
		if "%answer%"=="24" goto :networkSecurity
		if "%answer%"=="25" goto :exploitScanner
		if "%answer%"=="26" goto :serverHardening
		rem turn on screensaver
		rem password complexity
		if "%answer%"=="69" exit
		if "%answer%"=="70" shutdown /r
	
	echo Invalid option. Please try again.
	pause
	goto :menu

:accountPolicies
	echo Configuring Account Policies...
	echo.
	
	rem Password Policy
	echo Setting Password Policy...
	net accounts /minpwlen:14
	net accounts /maxpwage:30
	net accounts /minpwage:3
	net accounts /uniquepw:24
	
	rem Enable password complexity and disable reversible encryption
	secedit /export /cfg %temp%\secpol.cfg
	(echo [Unicode]&echo Unicode=yes&echo [System Access]&echo PasswordComplexity = 1&echo PasswordHistorySize = 24&echo ClearTextPassword = 0&echo [Version]&echo signature="$CHICAGO$"&echo Revision=1) > %temp%\secpol.cfg
	secedit /configure /db %windir%\security\local.sdb /cfg %temp%\secpol.cfg /areas SECURITYPOLICY
	del %temp%\secpol.cfg
	
	rem Account Lockout Policy
	echo Setting Account Lockout Policy...
	net accounts /lockoutduration:30
	net accounts /lockoutthreshold:5
	net accounts /lockoutwindow:30
	
	echo.
	echo Account Policies configured successfully!
	pause
	goto :menu


:localPolicies
	echo Configuring Local Policies...
	echo.
	
	rem Audit Policy - Set everything to Success, Failure
	echo Setting Audit Policies...
	auditpol /set /category:* /success:enable
	auditpol /set /category:* /failure:enable
	
	rem Security Options
	echo Setting Security Options...
	
	rem Accounts
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
	
	rem Devices
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
	
	rem Interactive Login
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
	
	rem Logon message
	set /p body=Please enter logon text: 
	reg ADD "HKLM\SYSTEM\microsoft\Windows\CurrentVersion\Policies\System\legalnoticetext" /v LegalNoticeText /t REG_SZ /d "%body%" /f
	set /p subject=Please enter the title of the message: 
	reg ADD "HKLM\SYSTEM\microsoft\Windows\CurrentVersion\Policies\System\legalnoticecaption" /v LegalNoticeCaption /t REG_SZ /d "%subject%" /f
	
	rem MS Network Server - Digitally sign communications
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 1 /f
	
	rem MS network client - Digitally sign communications (ALWAYS - ENABLED)
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnableSecuritySignature /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v RequireSecuritySignature /t REG_DWORD /d 1 /f
	
	rem Disable reversible encryption for passwords
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v ClearTextPassword /t REG_DWORD /d 0 /f
	
	rem Disable WinRM unencrypted traffic
	reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f
	reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f
	
	rem Network Access
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
	
	rem Network Security
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v NoLMHash /t REG_DWORD /d 1 /f
	
	rem Recovery Console
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
	
	rem Shutdown
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ShutdownWithoutLogon /t REG_DWORD /d 0 /f
	
	rem User Account Control
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v FilterAdministratorToken /t REG_DWORD /d 1 /f
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
	
	rem Additional Security Options
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f
	
	rem Enable DEP
	bcdedit.exe /set {current} nx AlwaysOn
	
	echo.
	echo Local Policies configured successfully!
	pause
	goto :menu

:disableGuest
	echo Disabling Guest account...
	echo.
	
	rem Check if Guest account is already disabled
	net user Guest | findstr /C:"Account active" | findstr /C:"No"
	if %errorlevel%==0 (
		echo Guest account is already disabled.
	) else (
		net user Guest /active:no
		echo Guest account has been disabled.
	)
	
	echo.
	pause
	goto :menu

	
:userManagement
	cls
	echo "============== USER MANAGEMENT =============="
	echo.
	echo "1) Create a user"
	echo "2) Delete a user"
	echo "3) Disable a user"
	echo "4) Change all user passwords (except current user)"
	echo "5) Set user properties"
	echo "6) Back to main menu"
	echo.
	set /p choice=Select an option: 
	
	if "%choice%"=="1" goto :createUser
	if "%choice%"=="2" goto :delUser
	if "%choice%"=="3" goto :disUser
	if "%choice%"=="4" goto :passwd
	if "%choice%"=="5" goto :userProp
	if "%choice%"=="6" goto :menu
	
	echo "Invalid option. Please try again."
	pause
	goto :userManagement

:userProp
	echo Setting user properties for ALL users...
	echo.
	echo Configuring:
	echo - User must change password at next logon (except admin accounts)
	echo - User CAN change password
	echo - Password DOES expire
	echo - Password IS required
	echo - Account is NOT disabled
	echo - Account is NOT locked out
	echo.
	
	rem Set global properties via WMIC (applies to all users)
	wmic UserAccount set PasswordExpires=True
	wmic UserAccount set PasswordChangeable=True
	wmic UserAccount set PasswordRequired=True
	
	echo.
	echo Setting "User must change password at next logon" for each user...
	echo.
	
	rem Set "User must change password at next logon" for each user (except admins)
	for /f "tokens=1,2,3" %%A in ('net user ^| findstr /v "User accounts" ^| findstr /v "^--" ^| findstr /v "^The command" ^| findstr /v "completed successfully"') do (
		if NOT "%%A"=="" (
			if /I NOT "%%A"=="Administrator" if /I NOT "%%A"=="Guest" if /I NOT "%%A"=="DefaultAccount" (
				echo Setting properties for %%A
				net user "%%A" /logonpasswordchg:yes 2>nul
			)
		)
		if NOT "%%B"=="" (
			if /I NOT "%%B"=="Administrator" if /I NOT "%%B"=="Guest" if /I NOT "%%B"=="DefaultAccount" (
				echo Setting properties for %%B
				net user "%%B" /logonpasswordchg:yes 2>nul
			)
		)
		if NOT "%%C"=="" (
			if /I NOT "%%C"=="Administrator" if /I NOT "%%C"=="Guest" if /I NOT "%%C"=="DefaultAccount" (
				echo Setting properties for %%C
				net user "%%C" /logonpasswordchg:yes 2>nul
			)
		)
	)
	
	echo.
	echo User properties set successfully for all users!
	pause
	goto :userManagement

:passwd
	echo Changing all user passwords (except current user)
	echo.
	
	rem Get current username
	set CURRENTUSER=%USERNAME%
	echo Current user: %CURRENTUSER% (will be skipped)
	echo.
	
	rem Parse all usernames (net user shows 3 columns)
	for /f "tokens=1,2,3" %%A in ('net user ^| findstr /v "User accounts" ^| findstr /v "^--" ^| findstr /v "^The command" ^| findstr /v "completed successfully"') do (
		if NOT "%%A"=="" (
			if /I NOT "%%A"=="Administrator" if /I NOT "%%A"=="Guest" if /I NOT "%%A"=="DefaultAccount" if /I NOT "%%A"=="%CURRENTUSER%" (
				echo Changing password for %%A
				net user "%%A" "CyberPatriot2024@"
			)
		)
		if NOT "%%B"=="" (
			if /I NOT "%%B"=="Administrator" if /I NOT "%%B"=="Guest" if /I NOT "%%B"=="DefaultAccount" if /I NOT "%%B"=="%CURRENTUSER%" (
				echo Changing password for %%B
				net user "%%B" "CyberPatriot2024@"
			)
		)
		if NOT "%%C"=="" (
			if /I NOT "%%C"=="Administrator" if /I NOT "%%C"=="Guest" if /I NOT "%%C"=="DefaultAccount" if /I NOT "%%C"=="%CURRENTUSER%" (
				echo Changing password for %%C
				net user "%%C" "CyberPatriot2024@"
			)
		)
	)
	
	echo.
	echo Password changes complete.
	pause
	goto :userManagement

:disUser
	cls
	net user
	set /p answer=Would you like to disable a user?[y/n]: 
	if /I "%answer%"=="y" (
		cls
		net user
		set /p DISABLE=What is the name of the user?:
			net user !DISABLE! /active:no
		echo !DISABLE! has been disabled
		pause
		goto :disUser
	)
	
	pause
	goto :userManagement

:createUser
	cls
	echo Current users on the system:
	net user
	echo.
	set /p NAME=What is the user you would like to create? (or type 'n' to cancel): 
	if /I "%NAME%"=="n" goto :userManagement
	set "PASS="
	set /p PASS=Enter a password for the user: 
	if "!PASS!"==" " (
		net user !NAME! /add
	) else (
		net user !NAME! !PASS! /add
	)
	echo !NAME! has been added
	pause 

	set /p answer=Do you want to create another user?[y/n]: 
	if /I "%answer%"=="y" goto :createUser
	if /I "%answer%"=="n" goto :userManagement
	goto :userManagement

:delUser
	cls
	net user
	set /p answer=Would you like to delete a user?[y/n]: 
	if /I "%answer%"=="n" goto :userManagement
	if /I NOT "%answer%"=="y" goto :userManagement
	
	cls
	net user
	set /p DELUSER=What is the name of the user to delete?: 
	net user !DELUSER! /delete
	echo !DELUSER! has been deleted
	pause
	
	set /p answer=Do you want to delete another user?[y/n]: 
	if /I "%answer%"=="y" goto :delUser
	goto :userManagement

:groupManagement
	cls
	echo "============== GROUP MANAGEMENT =============="
	echo.
	echo "1) Add user to group"
	echo "2) Remove user from group"
	echo "3) Create a new group"
	echo "4) Delete a group"
	echo "5) View groups/members"
	echo "6) Back to main menu"
	echo.
	set /p choice=Select an option: 
	
	if "%choice%"=="1" goto :addToGroup
	if "%choice%"=="2" goto :removeFromGroup
	if "%choice%"=="3" goto :createGroup
	if "%choice%"=="4" goto :deleteGroup
	if "%choice%"=="5" goto :viewGroup
	if "%choice%"=="6" goto :menu
	
	echo "Invalid option. Please try again."
	pause
	goto :groupManagement

:viewGroup
	cls
	echo Current groups:
	net localgroup
	echo.
	set /p grp=What group would you like to view? (or type 'back' to cancel): 
	if /I "!grp!"=="back" goto :groupManagement
	
	echo.
	echo Members of !grp!:
	net localgroup "!grp!"
	pause
	goto :groupManagement

:addToGroup
	cls
	echo Current groups:
	net localgroup
	echo.
	set /p grp=What group would you like to add users to? (or type 'back' to cancel): 
	if /I "!grp!"=="back" goto :groupManagement
	
:addToGroupLoop
	echo.
	echo Current members of !grp!:
	net localgroup "!grp!"
	echo.
	
	set /p userAdd=Enter the username to add (or 'done' to finish): 
	if /I "!userAdd!"=="done" goto :groupManagement
	
	net localgroup "!grp!" "!userAdd!" /add
	
	if %errorlevel%==0 (
		echo !userAdd! has been added to !grp!
	) else (
		echo Failed to add !userAdd! to !grp!
	)
	
	echo.
	set /p answer=Add another user to !grp!? [y/n]: 
	if /I "%answer%"=="y" goto :addToGroupLoop
	goto :groupManagement

:removeFromGroup
	cls
	echo Current groups:
	net localgroup
	echo.
	set /p grp=What group would you like to remove users from? (or type 'back' to cancel): 
	if /I "!grp!"=="back" goto :groupManagement
	
:removeFromGroupLoop
	echo.
	echo Current members of !grp!:
	net localgroup "!grp!"
	echo.
	
	set /p userRem=Enter the username to remove (or 'done' to finish): 
	if /I "!userRem!"=="done" goto :groupManagement
	
	net localgroup "!grp!" "!userRem!" /delete
	
	if %errorlevel%==0 (
		echo !userRem! has been removed from !grp!
	) else (
		echo Failed to remove !userRem! from !grp!
	)
	
	echo.
	set /p answer=Remove another user from !grp!? [y/n]: 
	if /I "%answer%"=="y" goto :removeFromGroupLoop
	goto :groupManagement

:createGroup
	cls
	echo Current groups:
	net localgroup
	echo.
	set /p newgrp=Enter the name of the group to create (or type 'back' to cancel): 
	if /I "!newgrp!"=="back" goto :groupManagement
	
	set /p comment=Enter a description for the group (optional): 
	
	if "!comment!"=="" (
		net localgroup "!newgrp!" /add
	) else (
		net localgroup "!newgrp!" /add /comment:"!comment!"
	)
	
	if %errorlevel%==0 (
		echo Group !newgrp! has been created!
	) else (
		echo Failed to create group !newgrp!
	)
	
	pause
	
	set /p answer=Create another group?[y/n]: 
	if /I "%answer%"=="y" goto :createGroup
	goto :groupManagement

:deleteGroup
	cls
	echo Current groups:
	net localgroup
	echo.
	echo WARNING: Do NOT delete default Windows groups!
	echo.
	set /p delgrp=Enter the name of the group to delete (or type 'back' to cancel): 
	if /I "!delgrp!"=="back" goto :groupManagement
	
	set /p confirm=Are you sure you want to delete !delgrp!?[y/n]: 
	if /I "!confirm!"=="y" (
		net localgroup "!delgrp!" /delete
		
		if %errorlevel%==0 (
			echo Group !delgrp! has been deleted!
		) else (
			echo Failed to delete group !delgrp!
		)
	) else (
		echo Deletion cancelled.
	)
	
	pause
	
	set /p answer=Delete another group?[y/n]: 
	if /I "%answer%"=="y" goto :deleteGroup
	goto :groupManagement



:fileSharesManagement
	cls
	echo "============== FILE SHARES MANAGEMENT =============="
	echo.
	echo "1) View current shares"
	echo "2) Remove unauthorized shares"
	echo "3) Disconnect all sessions"
	echo "4) Back to main menu"
	echo.
	set /p choice=Select an option: 
	
	if "%choice%"=="1" goto :viewShares
	if "%choice%"=="2" goto :removeShares
	if "%choice%"=="3" goto :disconnectSessions
	if "%choice%"=="4" goto :menu
	
	echo Invalid option. Please try again.
	pause
	goto :fileSharesManagement

:viewShares
	cls
	echo "============== CURRENT SHARES =============="
	echo.
	echo Mandatory shares (DO NOT remove):
	echo - ADMIN$
	echo - C$
	echo - IPC$
	echo - Any shares ending with $
	echo.
	echo Current shares on this system:
	net share
	echo.
	pause
	goto :fileSharesManagement

:removeShares
	cls
	echo "============== REMOVE UNAUTHORIZED SHARES =============="
	echo.
	echo WARNING: Only remove shares that are NOT mandatory!
	echo.
	echo Mandatory shares (DO NOT remove):
	echo - ADMIN$
	echo - C$
	echo - IPC$
	echo - Any shares ending with $
	echo.
	echo Current shares:
	net share
	echo.
	set /p sharename=Enter the share name to remove (or 'back' to cancel): 
	
	if /I "!sharename!"=="back" goto :fileSharesManagement
	
	rem Check if it's a mandatory share
	if /I "!sharename!"=="ADMIN$" (
		echo ERROR: Cannot remove ADMIN$ - this is a mandatory share!
		pause
		goto :removeShares
	)
	if /I "!sharename!"=="C$" (
		echo ERROR: Cannot remove C$ - this is a mandatory share!
		pause
		goto :removeShares
	)
	if /I "!sharename!"=="IPC$" (
		echo ERROR: Cannot remove IPC$ - this is a mandatory share!
		pause
		goto :removeShares
	)
	
	echo.
	set /p confirm=Are you sure you want to remove share "!sharename!"?[y/n]: 
	
	if /I "!confirm!"=="y" (
		net share "!sharename!" /delete
		if %errorlevel%==0 (
			echo Share "!sharename!" has been removed!
		) else (
			echo Failed to remove share "!sharename!"
		)
	) else (
		echo Removal cancelled.
	)
	
	echo.
	set /p answer=Remove another share?[y/n]: 
	if /I "!answer!"=="y" goto :removeShares
	goto :fileSharesManagement

:disconnectSessions
	echo "============== DISCONNECT ALL SESSIONS =============="
	echo.
	echo This will disconnect all active sessions to shared folders.
	echo.
	set /p confirm=Are you sure you want to disconnect all sessions?[y/n]: 
	
	if /I "!confirm!"=="y" (
		echo.
		echo Disconnecting all sessions...
		for /f "skip=1 tokens=2" %%s in ('net session') do (
			net session %%s /delete 2>nul
		)
		echo.
		echo All sessions have been disconnected.
	) else (
		echo Operation cancelled.
	)
	
	pause
	goto :fileSharesManagement


:servicesManagement
	cls
	echo "============== SERVICES MANAGEMENT =============="
	echo.
	echo "1) Disable common unnecessary services"
	echo "2) Disable specific service (manual)"
	echo "3) Enable/Start specific service (manual)"
	echo "4) View service status"
	echo "5) Back to main menu"
	echo.
	set /p choice=Select an option: 
	
	if "%choice%"=="1" goto :disableCommonServices
	if "%choice%"=="2" goto :disableSpecificService
	if "%choice%"=="3" goto :enableSpecificService
	if "%choice%"=="4" goto :viewServiceStatus
	if "%choice%"=="5" goto :menu
	
	echo "Invalid option. Please try again."
	pause
	goto :servicesManagement

:disableCommonServices
	cls
	echo ============== DISABLE COMMON SERVICES ==============
	echo.
	echo The following services will be disabled:
	echo.
	echo Remote Desktop Services:
	echo   - TermService (Remote Desktop)
	echo   - SessionEnv (Remote Desktop Configuration)
	echo   - UmRdpService (Remote Desktop UserMode Port Redirector)
	echo   - RpcSs (Remote Procedure Call)
	echo.
	echo File Transfer:
	echo   - ftpsvc (FTP Server)
	echo.
	echo Remote Access:
	echo   - TlntSvr (Telnet Server)
	echo   - RemoteRegistry (Remote Registry)
	echo   - RemoteAccess (Routing and Remote Access)
	echo.
	echo Network Services:
	echo   - SNMP (SNMP Service)
	echo   - SNMPTRAP (SNMP Trap)
	echo   - SSDPSRV (SSDP Discovery)
	echo   - upnphost (UPnP Device Host)
	echo.
	echo Other Services:
	echo   - SharedAccess (Internet Connection Sharing)
	echo   - W3SVC (World Wide Web Publishing Service)
	echo   - TapiSrv (Telephony)
	echo   - iprip (RIP Listener)
	echo   - HomeGroupProvider
	echo   - HomeGroupListener
	echo   - BDESVC (BitLocker Drive Encryption)
	echo.
	echo NOTE: Check the README for any critical services before disabling!
	echo.
	set /p confirm=Do you want to disable all these services?[y/n]: 
	
	if /I NOT "%confirm%"=="y" (
		echo Operation cancelled.
		pause
		goto :servicesManagement
	)
	
	echo.
	echo Disabling services...
	echo.
	
	rem Common services to disable from checklist
	echo Stopping and disabling Remote Desktop services...
	sc stop TermService
	sc config TermService start= disabled
	sc stop SessionEnv
	sc config SessionEnv start= disabled
	sc stop UmRdpService
	sc config UmRdpService start= disabled
	sc stop RpcSs
	sc config RpcSs start= disabled
	
	echo Stopping and disabling FTP...
	sc stop ftpsvc
	sc config ftpsvc start= disabled
	
	echo Stopping and disabling Telnet...
	sc stop TlntSvr
	sc config TlntSvr start= disabled
	
	echo Stopping and disabling SNMP...
	sc stop SNMP
	sc config SNMP start= disabled
	sc stop SNMPTRAP
	sc config SNMPTRAP start= disabled
	
	echo Stopping and disabling Remote Registry...
	sc stop RemoteRegistry
	sc config RemoteRegistry start= disabled
	
	echo Stopping and disabling Remote Access...
	sc stop RemoteAccess
	sc config RemoteAccess start= disabled
	
	echo Stopping and disabling UPnP/SSDP...
	sc stop SSDPSRV
	sc config SSDPSRV start= disabled
	sc stop upnphost
	sc config upnphost start= disabled
	
	echo Stopping and disabling ICS (Internet Connection Sharing)...
	sc stop SharedAccess
	sc config SharedAccess start= disabled
	
	echo Stopping and disabling WWW Publishing Service...
	sc stop W3SVC
	sc config W3SVC start= disabled
	
	echo Stopping and disabling Telephony...
	sc stop TapiSrv
	sc config TapiSrv start= disabled
	
	echo Stopping and disabling RIP Listener...
	sc stop iprip
	sc config iprip start= disabled
	
	echo Stopping and disabling HomeGroup services...
	sc stop HomeGroupProvider
	sc config HomeGroupProvider start= disabled
	sc stop HomeGroupListener
	sc config HomeGroupListener start= disabled
	
	echo Stopping and disabling BitLocker...
	sc stop BDESVC
	sc config BDESVC start= disabled
	
	echo.
	echo Common unnecessary services have been disabled!
	echo.
	pause
	goto :servicesManagement

:disableSpecificService
	cls
	set /p svcname=Enter the service name to disable (or type 'back' to cancel): 
	if /I "!svcname!"=="back" goto :servicesManagement
	
	echo.
	echo Stopping and disabling !svcname!...
	sc stop "!svcname!"
	sc config "!svcname!" start= disabled
	
	if %errorlevel%==0 (
		echo Service !svcname! has been stopped and disabled!
	) else (
		echo Failed to disable service !svcname! (may not exist or already disabled)
	)
	
	pause
	
	set /p answer=Disable another service?[y/n]: 
	if /I "%answer%"=="y" goto :disableSpecificService
	goto :servicesManagement

:enableSpecificService
	cls
	set /p svcname=Enter the service name to enable (or type 'back' to cancel): 
	if /I "!svcname!"=="back" goto :servicesManagement
	
	echo.
	echo Starting and enabling !svcname!...
	sc config "!svcname!" start= auto
	sc start "!svcname!"
	
	if %errorlevel%==0 (
		echo Service !svcname! has been started and set to automatic!
	) else (
		echo Failed to enable service !svcname! (may not exist)
	)
	
	pause
	
	set /p answer=Enable another service?[y/n]: 
	if /I "%answer%"=="y" goto :enableSpecificService
	goto :servicesManagement

:viewServiceStatus
	cls
	set /p svcname=Enter the service name to view (or type 'back' to cancel): 
	if /I "!svcname!"=="back" goto :servicesManagement
	
	echo.
	sc query "!svcname!"
	echo.
	sc qc "!svcname!"
	
	pause
	goto :servicesManagement



:windowsFeatures
	cls
	echo "============== WINDOWS FEATURES =============="
	echo.
	echo "1) Remove common unnecessary features"
	echo "2) Open Windows Features (manual configuration)"
	echo "3) Back to main menu"
	echo.
	set /p choice=Select an option: 
	
	if "%choice%"=="1" goto :removeCommonFeatures
	if "%choice%"=="2" goto :openWindowsFeatures
	if "%choice%"=="3" goto :menu
	
	echo "Invalid option. Please try again."
	pause
	goto :windowsFeatures

:removeCommonFeatures
	cls
	echo ============== REMOVE COMMON FEATURES ==============
	echo.
	echo The following Windows features will be REMOVED:
	echo.
	echo Network Protocols:
	echo   - SMB 1.0/CIFS File Sharing Support (security vulnerability)
	echo   - Telnet Client
	echo   - TFTP Client
	echo   - Simple TCP/IP Services
	echo.
	echo Server Features:
	echo   - FTP Server (IIS)
	echo.
	echo Legacy Features:
	echo   - PowerShell 2.0 (outdated and insecure)
	echo   - Work Folders Client
	echo.
	echo WARNING: These features will be permanently removed!
	echo.
	set /p confirm=Do you want to remove all these features?[y/n]: 
	
	if /I NOT "%confirm%"=="y" (
		echo Operation cancelled.
		pause
		goto :windowsFeatures
	)
	
	echo.
	echo Removing features...
	echo This may take a few minutes...
	echo.
	
	rem Disable SMB 1.0
	echo Disabling SMB 1.0/CIFS File Sharing Support...
	dism /online /Disable-Feature /FeatureName:SMB1Protocol /NoRestart
	
	rem Disable Telnet Client
	echo Disabling Telnet Client...
	dism /online /Disable-Feature /FeatureName:TelnetClient /NoRestart
	
	rem Disable TFTP Client
	echo Disabling TFTP Client...
	dism /online /Disable-Feature /FeatureName:TFTP /NoRestart
	
	rem Disable Simple TCP/IP Services
	echo Disabling Simple TCP/IP Services...
	dism /online /Disable-Feature /FeatureName:SimpleTCP /NoRestart
	
	rem Disable FTP Server (IIS)
	echo Disabling FTP Server...
	dism /online /Disable-Feature /FeatureName:IIS-FTPServer /NoRestart
	dism /online /Disable-Feature /FeatureName:IIS-FTPSvc /NoRestart
	dism /online /Disable-Feature /FeatureName:IIS-FTPExtensibility /NoRestart
	
	rem Disable Windows PowerShell 2.0 (outdated and insecure)
	echo Disabling PowerShell 2.0...
	dism /online /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2Root /NoRestart
	
	rem Disable Work Folders Client
	echo Disabling Work Folders Client...
	dism /online /Disable-Feature /FeatureName:WorkFolders-Client /NoRestart
	
	echo.
	echo Common unnecessary features have been disabled!
	echo NOTE: A restart may be required for changes to take effect.
	echo.
	pause
	goto :windowsFeatures

:openWindowsFeatures
	echo Opening Windows Features dialog...
	echo.
	echo This will open the Windows Features control panel.
	echo You can manually enable or disable features from there.
	echo.
	echo Common features to remove:
	echo - FTP Server
	echo - Simple TCP/IP Services
	echo - Telnet Client
	echo - SMB 1.0/CIFS File Sharing Support
	echo - PowerShell 2.0
	echo.
	pause
	
	rem Open Windows Features dialog
	optionalfeatures.exe
	
	pause
	goto :windowsFeatures



:remDesk
	echo "============== REMOTE DESKTOP CONFIGURATION =============="
	echo.
	echo "NOTE: Check the README to see if remote desktop is critical!"
	echo.
	echo "Current options:"
	echo "1) Disable Remote Desktop (RECOMMENDED)"
	echo "2) Enable Remote Desktop"
	echo "3) Back to main menu"
	echo.
	set /p choice=Select an option: 
	
	if "%choice%"=="1" goto :disableRDP
	if "%choice%"=="2" goto :enableRDP
	if "%choice%"=="3" goto :menu
	
	echo Invalid option. Please try again.
	pause
	goto :remDesk

:disableRDP
	echo Disabling Remote Desktop...
	echo.
	
	rem Disable Remote Desktop connections
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
	
	rem Disable Remote Assistance
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
	
	rem Disable Remote Desktop via System Properties
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
	
	echo.
	echo Remote Desktop and Remote Assistance have been disabled.
	echo Reboot for changes to take full effect.
	echo.
	pause
	goto :menu

:enableRDP
	echo Enabling Remote Desktop...
	echo.
	echo WARNING: Only enable if specified in the README!
	echo.
	set /p confirm=Are you sure you want to enable Remote Desktop?[y/n]: 
	
	if /I "%confirm%"=="y" (
		rem Enable Remote Desktop connections
		reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
		reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f
		
		rem Enable firewall rule for Remote Desktop
		netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
		
		echo.
		echo Remote Desktop has been enabled.
		echo Reboot for changes to take full effect.
	) else (
		echo Remote Desktop configuration cancelled.
	)
	
	echo.
	pause
	goto :menu



:screensaver
	echo "============== SCREENSAVER CONFIGURATION =============="
	echo.
	echo "Configuring screensaver to require password on resume..."
	echo.
	
	rem Enable screensaver
	reg add "HKCU\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f
	
	rem Set screensaver timeout (5 minutes = 300 seconds)
	reg add "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 300 /f
	
	rem Require password on resume
	reg add "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 1 /f
	
	rem Enable "On resume, display logon screen" in Power Options
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1
	powercfg /SETACTIVE SCHEME_CURRENT
	
	rem Set screensaver to blank screen
	reg add "HKCU\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "scrnsave.scr" /f
	
	echo.
	echo Screensaver configuration complete!
	echo - Screensaver enabled
	echo - Timeout set to 5 minutes
	echo - Password required on resume
	echo - Logon screen displayed on power resume
	echo.
	
	set /p open=Would you like to open screensaver settings to verify?[y/n]: 
	if /I "%open%"=="y" (
		control desk.cpl,,@screensaver
	)
	
	pause
	goto :menu


:uacConfig
	echo "============== UAC CONFIGURATION =============="
	echo.
	echo "Setting User Account Control to highest level (Always notify)..."
	echo.
	
	rem Set UAC to highest level (Always notify)
	rem ConsentPromptBehaviorAdmin: 2 = Always notify
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
	
	rem Prompt for credentials on the secure desktop
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
	
	rem Enable UAC
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
	
	rem Elevate without prompting (disabled for security)
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f
	
	echo.
	echo UAC has been configured!
	echo - UAC level set to: Always notify
	echo - Secure desktop prompting: Enabled
	echo - UAC: Enabled
	echo.
	
	set /p open=Would you like to open UAC settings to verify?[y/n]: 
	if /I "%open%"=="y" (
		UserAccountControlSettings.exe
	)
	
	pause
	goto :menu


:autoPlayConfig
	echo "============== AUTOPLAY CONFIGURATION =============="
	echo.
	echo "Disabling AutoPlay for all media and devices..."
	echo.
	
	rem Disable AutoPlay for all drives
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
	
	rem Disable AutoPlay via user settings
	reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v DisableAutoplay /t REG_DWORD /d 1 /f
	
	rem Disable AutoPlay for all users
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f
	
	rem Turn off AutoPlay via Group Policy
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
	
	echo.
	echo AutoPlay has been disabled!
	echo - AutoPlay for all media and devices: OFF
	echo - AutoPlay for all drives: Disabled
	echo.
	
	set /p open=Would you like to open AutoPlay settings to verify?[y/n]: 
	if /I "%open%"=="y" (
		control.exe /name Microsoft.AutoPlay
	)
	
	pause
	goto :menu

:firewallConfig
	echo "============== FIREWALL CONFIGURATION =============="
	echo.
	echo "1) Enable and configure firewall (recommended settings)"
	echo "2) Block specific ports"
	echo "3) Open Windows Defender Firewall Advanced Security"
	echo "4) Back to main menu"
	echo.
	set /p choice=Select an option: 
	
	if "%choice%"=="1" goto :enableFirewall
	if "%choice%"=="2" goto :blockPorts
	if "%choice%"=="3" goto :openFirewallAdvanced
	if "%choice%"=="4" goto :menu
	
	echo Invalid option. Please try again.
	pause
	goto :firewallConfig

:enableFirewall
	echo Enabling and configuring Windows Defender Firewall...
	echo.
	
	rem Turn on firewall for all profiles
	netsh advfirewall set allprofiles state on
	
	rem Domain Profile Configuration
	echo Configuring Domain Profile...
	netsh advfirewall set domainprofile firewallpolicy blockinbound,allowoutbound
	netsh advfirewall set domainprofile settings inboundusernotification disable
	netsh advfirewall set domainprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
	netsh advfirewall set domainprofile logging maxfilesize 16384
	netsh advfirewall set domainprofile logging droppedconnections enable
	netsh advfirewall set domainprofile logging allowedconnections enable
	
	rem Private Profile Configuration
	echo Configuring Private Profile...
	netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound
	netsh advfirewall set privateprofile settings inboundusernotification disable
	netsh advfirewall set privateprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
	netsh advfirewall set privateprofile logging maxfilesize 16384
	netsh advfirewall set privateprofile logging droppedconnections enable
	netsh advfirewall set privateprofile logging allowedconnections enable
	
	rem Public Profile Configuration
	echo Configuring Public Profile...
	netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound
	netsh advfirewall set publicprofile settings inboundusernotification disable
	netsh advfirewall set publicprofile settings localconsecrules disable
	netsh advfirewall set publicprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
	netsh advfirewall set publicprofile logging maxfilesize 16384
	netsh advfirewall set publicprofile logging droppedconnections enable
	netsh advfirewall set publicprofile logging allowedconnections enable
	
	echo.
	echo Firewall configuration complete!
	echo - All profiles: Enabled
	echo - Inbound connections: Block (default)
	echo - Outbound connections: Allow (default)
	echo - Notifications: Disabled
	echo - Logging: Enabled (16384 KB)
	echo - Log dropped packets: Yes
	echo - Log successful connections: Yes
	echo.
	pause
	goto :firewallConfig

:blockPorts
	cls
	echo "============== BLOCK SPECIFIC PORTS =============="
	echo.
	echo Common ports to block:
	echo - 21 (FTP)
	echo - 22 (SSH)
	echo - 23 (Telnet)
	echo - 161 (SNMP)
	echo - 389 (LDAP)
	echo - 3389 (RDP)
	echo.
	echo "1) Block all common vulnerable ports"
	echo "2) Block specific port (manual)"
	echo "3) Back"
	echo.
	set /p blockchoice=Select an option: 
	
	if "%blockchoice%"=="1" goto :blockCommonPorts
	if "%blockchoice%"=="2" goto :blockSpecificPort
	if "%blockchoice%"=="3" goto :firewallConfig
	
	echo Invalid option.
	pause
	goto :blockPorts

:blockCommonPorts
	echo Blocking common vulnerable ports...
	echo.
	
	rem Block FTP (21)
	netsh advfirewall firewall add rule name="Block FTP Port 21" dir=in action=block protocol=TCP localport=21
	
	rem Block SSH (22)
	netsh advfirewall firewall add rule name="Block SSH Port 22" dir=in action=block protocol=TCP localport=22
	
	rem Block Telnet (23)
	netsh advfirewall firewall add rule name="Block Telnet Port 23" dir=in action=block protocol=TCP localport=23
	
	rem Block SNMP (161)
	netsh advfirewall firewall add rule name="Block SNMP Port 161" dir=in action=block protocol=UDP localport=161
	
	rem Block LDAP (389)
	netsh advfirewall firewall add rule name="Block LDAP Port 389" dir=in action=block protocol=TCP localport=389
	
	rem Block RDP (3389)
	netsh advfirewall firewall add rule name="Block RDP Port 3389" dir=in action=block protocol=TCP localport=3389
	
	echo.
	echo Common vulnerable ports have been blocked!
	pause
	goto :firewallConfig

:blockSpecificPort
	echo.
	set /p portnum=Enter port number to block (or 'back' to cancel): 
	if /I "%portnum%"=="back" goto :blockPorts
	
	set /p protocol=Enter protocol (TCP/UDP): 
	
	netsh advfirewall firewall add rule name="Block Port %portnum%" dir=in action=block protocol=%protocol% localport=%portnum%
	
	echo.
	echo Port %portnum% (%protocol%) has been blocked!
	pause
	
	set /p another=Block another port?[y/n]: 
	if /I "%another%"=="y" goto :blockSpecificPort
	goto :firewallConfig

:openFirewallAdvanced
	echo Opening Windows Defender Firewall with Advanced Security...
	wf.msc
	pause
	goto :firewallConfig


:autoUpdate
	echo "============== WINDOWS UPDATES =============="
	echo.
	echo "1) Enable Automatic Updates"
	echo "2) Check for Windows Updates"
	echo "3) Open Windows Update settings"
	echo "4) Back to main menu"
	echo.
	set /p choice=Select an option: 
	
	if "%choice%"=="1" goto :enableAutoUpdate
	if "%choice%"=="2" goto :checkUpdates
	if "%choice%"=="3" goto :openUpdateSettings
	if "%choice%"=="4" goto :menu
	
	echo Invalid option. Please try again.
	pause
	goto :autoUpdate

:enableAutoUpdate
	echo Enabling Automatic Windows Updates...
	echo.
	
	rem Enable automatic updates via registry (value 4 = automatically download and install)
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
	
	rem Enable automatic updates via Group Policy
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 4 /f
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f
	
	rem Start Windows Update service
	sc config wuauserv start= auto
	sc start wuauserv
	
	echo.
	echo Automatic Windows Updates have been enabled!
	echo - Mode: Automatically download and install updates
	echo - Windows Update service: Started and set to automatic
	echo.
	pause
	goto :autoUpdate

:checkUpdates
	echo Checking for Windows Updates...
	echo.
	echo Opening Windows Update to check for updates...
	echo This may take a few moments.
	echo.
	
	rem Open Windows Update settings
	start ms-settings:windowsupdate
	
	echo.
	echo NOTE: Windows Update has been opened.
	echo Please click "Check for updates" to scan for available updates.
	echo.
	echo WARNING: Updates can take a long time! Don't save this for last minute.
	echo.
	pause
	goto :autoUpdate

:openUpdateSettings
	echo Opening Windows Update settings...
	start ms-settings:windowsupdate
	pause
	goto :autoUpdate


:rpcRdpEncryption
	echo "============== RPC & RDP ENCRYPTION CONFIGURATION =============="
	echo.
	echo Configuring secure RPC and RDP encryption settings...
	echo.
	
	rem Require secure RPC communication
	echo Setting RPC to require secure communication...
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
	
	rem Set RDP connection encryption level to High
	echo Setting RDP encryption level to High...
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MinEncryptionLevel /t REG_DWORD /d 3 /f
	
	rem Additional RDP security settings
	echo Configuring additional RDP security...
	
	rem Require use of specific security layer for RDP connections
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v SecurityLayer /t REG_DWORD /d 2 /f
	
	rem Require user authentication for remote connections by using Network Level Authentication
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v UserAuthentication /t REG_DWORD /d 1 /f
	
	rem Set client connection encryption level
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v ClientConnectionEncryptionLevel /t REG_DWORD /d 3 /f
	
	echo.
	echo RPC and RDP encryption configuration complete!
	echo.
	echo Settings applied:
	echo - Secure RPC communication: ENABLED
	echo - RDP encryption level: HIGH (3)
	echo - Security layer: SSL/TLS (2)
	echo - Network Level Authentication: ENABLED
	echo - Client connection encryption: HIGH (3)
	echo.
	echo NOTE: Run 'gpupdate /force' to apply Group Policy changes immediately
	echo.
	
	set /p update=Run 'gpupdate /force' now?[y/n]: 
	if /I "%update%"=="y" (
		echo.
		echo Running gpupdate /force...
		gpupdate /force
		echo.
		echo Group Policy has been updated.
	)
	
	pause
	goto :menu


:disableIPv6
	echo "============== DISABLE IPv6 =============="
	echo.
	echo Disabling IPv6 on all network adapters...
	echo.
	
	rem Method 1: Disable IPv6 via Registry (recommended configuration)
	echo Setting registry value to disable IPv6...
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0xff /f
	
	rem Method 2: Disable IPv6 on all network adapters
	echo Disabling IPv6 on network adapters...
	powershell -Command "Get-NetAdapterBinding -ComponentID ms_tcpip6 | Disable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false"
	
	echo.
	echo IPv6 has been disabled!
	echo.
	echo What was done:
	echo - Registry DisabledComponents set to 0xff (255)
	echo - IPv6 disabled on all network adapters
	echo.
	echo NOTE: A system restart is required for changes to take full effect.
	echo.
	
	set /p reboot=Would you like to reboot now?[y/n]: 
	if /I "%reboot%"=="y" (
		echo Rebooting system in 30 seconds...
		echo Press Ctrl+C to cancel.
		shutdown /r /t 30 /c "Reboot required for IPv6 disable to take effect"
	) else (
		echo Please reboot manually for changes to take full effect.
	)
	
	pause
	goto :menu

:badFiles
	echo "============= MEDIA FILES SCANNER =============="
	echo.
	echo WARNING: Do NOT delete files related to forensics questions
	echo until after you have gotten the points for them!
	echo.
	echo Scanning for prohibited media files...
	echo - Images: .png, .jpg, .gif
	echo - Videos: .mp4, .mov
	echo - Audio: .mp3
	echo.
	echo Creating list in %temp%\mediafiles.txt...
	echo.
	
	rem Search C: drive for all prohibited media file types
	dir /s /b C:\Users\*.png C:\Users\*.jpg C:\Users\*.gif C:\Users\*.mp3 C:\Users\*.mp4 C:\Users\*.mov 2>nul > %temp%\mediafiles.txt
	
	 rem Check if any files were found
	for %%A in (%temp%\mediafiles.txt) do set filesize=%%~zA
	if %filesize% GTR 0 (
		echo Media files found! Opening list...
		start notepad %temp%\mediafiles.txt
		echo.
		echo Please review the list in Notepad.
		echo Make sure NO forensics-related files are included!
		echo.
		set /p answer=Do you want to delete these files?[y/n]: 
		if /I "!answer!"=="y" (
			echo.
			echo Deleting media files...
			for /f "delims=" %%F in (%temp%\mediafiles.txt) do (
				del /f "%%F" 2>nul
				if %errorlevel%==0 (
					echo Deleted: %%F
				) else (
					echo Failed to delete: %%F
				)
			)
			echo.
			echo Media file deletion complete.
		) else (
			echo Media files were not deleted.
		)
	) else (
		echo No prohibited media files found.
	)
	
	del %temp%\mediafiles.txt 2>nul
	pause
	goto :menu

	:scanHiddenFiles
	echo "============== HIDDEN & SUSPICIOUS FILES SCANNER =============="
	echo.
	echo WARNING: Review carefully before deleting!
	echo Some system files are hidden for a reason.
	echo.
	echo Scanning for:
	echo - Hidden files in user directories
	echo - Suspicious file types (.zip, .rar, .7z, .exe, .bat, .vbs, .ps1)
	echo.
	
	set /p answer=Continue with scan?[y/n]: 
	if /I NOT "%answer%"=="y" goto :menu
	
	echo.
	echo Scanning... This may take a moment.
	echo.
	
	rem Search for hidden files and suspicious types in user directories
	echo Searching C:\Users\ for hidden and suspicious files...
	dir /s /b /a:h C:\Users\*.zip C:\Users\*.rar C:\Users\*.7z C:\Users\*.exe C:\Users\*.bat C:\Users\*.vbs C:\Users\*.ps1 C:\Users\*.cmd 2>nul > %temp%\hiddenfiles.txt
	
	rem Also search for hidden files with common extensions in Downloads
	dir /s /b /a:h C:\Users\*\Downloads\* 2>nul >> %temp%\hiddenfiles.txt
	
	rem Check if any files were found
	for %%A in (%temp%\hiddenfiles.txt) do set filesize=%%~zA
	if %filesize% GTR 0 (
		echo.
		echo Hidden/suspicious files found! Opening list...
		start notepad %temp%\hiddenfiles.txt
		echo.
		echo Please review the list in Notepad.
		echo.
		echo "Options:"
		echo "1) Delete all files in the list"
		echo "2) Unhide files (remove hidden attribute)"
		echo "3) Do nothing"
		echo.
		set /p choice=Select an option [1/2/3]: 
		
		if "%choice%"=="1" (
			echo.
			echo Deleting files...
			for /f "delims=" %%F in (%temp%\hiddenfiles.txt) do (
				del /f /a:h "%%F" 2>nul
				if %errorlevel%==0 (
					echo Deleted: %%F
				) else (
					echo Failed to delete: %%F
				)
			)
			echo.
			echo File deletion complete.
		)
		
		if "%choice%"=="2" (
			echo.
			echo Unhiding files...
			for /f "delims=" %%F in (%temp%\hiddenfiles.txt) do (
				attrib -h "%%F" 2>nul
				if %errorlevel%==0 (
					echo Unhidden: %%F
				) else (
					echo Failed to unhide: %%F
				)
			)
			echo.
			echo Files have been unhidden.
		)
		
		if "%choice%"=="3" (
			echo No action taken.
		)
	) else (
		echo No hidden or suspicious files found in user directories.
	)
	
	del %temp%\hiddenfiles.txt 2>nul
	pause
	goto :menu

:startupManagement
	echo "============== STARTUP ITEMS MANAGEMENT =============="
	echo.
	echo This will help you identify and disable unauthorized startup items.
	echo.
	echo "1) View Startup Programs (Task Manager method)"
	echo "2) View Registry Startup Items (Run/RunOnce)"
	echo "3) Disable startup item via registry"
	echo "4) View Startup Folder contents"
	echo "5) Back to main menu"
	echo.
	set /p choice=Select an option: 
	
	if "%choice%"=="1" goto :viewStartupTaskMgr
	if "%choice%"=="2" goto :viewRegistryStartup
	if "%choice%"=="3" goto :disableRegistryStartup
	if "%choice%"=="4" goto :viewStartupFolder
	if "%choice%"=="5" goto :menu
	
	echo "Invalid option. Please try again."
	pause
	goto :startupManagement

:viewStartupTaskMgr
	echo "============== STARTUP PROGRAMS (Task Manager) =============="
	echo.
	echo Opening Task Manager to Startup tab...
	echo.
	echo NOTE: You can manually disable items from the Startup tab.
	echo Look for suspicious or unauthorized programs.
	echo.
	pause
	
	rem Open Task Manager (will need manual navigation to Startup tab)
	taskmgr.exe
	
	echo.
	echo Task Manager opened. Navigate to the "Startup" tab to manage items.
	pause
	goto :startupManagement

:viewRegistryStartup
	echo "============== REGISTRY STARTUP ITEMS =============="
	echo.
	echo Checking common startup registry locations...
	echo.
	
	echo [HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
	reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul
	echo.
	
	echo [HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce]
	reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 2>nul
	echo.
	
	echo [HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
	reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul
	echo.
	
	echo [HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce]
	reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 2>nul
	echo.
	
	echo Review the above entries. Look for suspicious programs.
	pause
	goto :startupManagement

:disableRegistryStartup
	echo "============== DISABLE REGISTRY STARTUP ITEM =============="
	echo.
	echo WARNING: Only remove entries you are certain are unauthorized!
	echo.
	echo "Common startup locations:"
	echo "1) HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
	echo "2) HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
	echo "3) HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
	echo "4) HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
	echo.
	
	set /p location=Enter location number [1-4] or 'cancel' to go back: 
	if /I "!location!"=="cancel" goto :startupManagement
	
	if "!location!"=="1" set regPath=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	if "!location!"=="2" set regPath=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
	if "!location!"=="3" set regPath=HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	if "!location!"=="4" set regPath=HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
	
	if not defined regPath (
		echo Invalid selection.
		pause
		goto :disableRegistryStartup
	)
	
	echo.
	echo Current entries in !regPath!:
	reg query "!regPath!" 2>nul
	echo.
	
	set /p valueName=Enter the VALUE NAME to delete (exact name): 
	if "!valueName!"=="" (
		echo No value name provided.
		pause
		goto :startupManagement
	)
	
	echo.
	set /p confirm=Are you sure you want to delete "!valueName!" from !regPath!? [y/n]: 
	if /I "!confirm!"=="y" (
		reg delete "!regPath!" /v "!valueName!" /f
		if %errorlevel%==0 (
			echo Successfully deleted !valueName!
		) else (
			echo Failed to delete !valueName!. It may not exist or you lack permissions.
		)
	) else (
		echo Deletion cancelled.
	)
	
	echo.
	set /p another=Delete another startup item? [y/n]: 
	if /I "!another!"=="y" goto :disableRegistryStartup
	goto :startupManagement

:viewStartupFolder
	echo "============== STARTUP FOLDER CONTENTS =============="
	echo.
	echo Checking startup folders...
	echo.
	
	echo [All Users Startup Folder]
	if exist "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" (
		dir /b "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
		if %errorlevel%==1 echo (Empty)
	) else (
		echo (Folder not found)
	)
	echo.
	
	echo [Current User Startup Folder]
	if exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" (
		dir /b "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
		if %errorlevel%==1 echo (Empty)
	) else (
		echo (Folder not found)
	)
	echo.
	
	echo To remove an item, manually delete it from the startup folder.
	echo.
	set /p open=Open startup folders in Explorer? [y/n]: 
	if /I "!open!"=="y" (
		start "" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
		start "" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
	)
	
	pause
	goto :startupManagement

:taskSchedulerCleanup
	echo "============== TASK SCHEDULER CLEANUP =============="
	echo.
	echo This will help identify and remove suspicious scheduled tasks.
	echo.
	echo "1) List all scheduled tasks"
	echo "2) View task details"
	echo "3) Delete a scheduled task"
	echo "4) Disable a scheduled task"
	echo "5) Open Task Scheduler GUI"
	echo "6) Back to main menu"
	echo.
	set /p choice=Select an option: 
	
	if "%choice%"=="1" goto :listScheduledTasks
	if "%choice%"=="2" goto :viewTaskDetails
	if "%choice%"=="3" goto :deleteScheduledTask
	if "%choice%"=="4" goto :disableScheduledTask
	if "%choice%"=="5" goto :openTaskScheduler
	if "%choice%"=="6" goto :menu
	
	echo "Invalid option. Please try again."
	pause
	goto :taskSchedulerCleanup

:listScheduledTasks
	echo "============== ALL SCHEDULED TASKS =============="
	echo.
	echo Listing all scheduled tasks (this may take a moment)...
	echo.
	
	rem List tasks with their state
	schtasks /query /fo LIST /v > %temp%\tasks.txt
	
	echo Tasks saved to %temp%\tasks.txt
	echo Opening in Notepad for review...
	echo.
	echo Look for:
	echo - Tasks you don't recognize
	echo - Tasks pointing to suspicious executables
	echo - Tasks running from TEMP or user directories
	echo - Tasks with suspicious names or authors
	echo.
	
	start notepad %temp%\tasks.txt
	pause
	
	del %temp%\tasks.txt 2>nul
	goto :taskSchedulerCleanup

:viewTaskDetails
	echo "============== VIEW TASK DETAILS =============="
	echo.
	echo Enter the exact task name to view details.
	echo TIP: Use option 1 first to see all task names.
	echo.
	
	set /p taskName=Enter task name (or 'cancel' to go back): 
	if /I "!taskName!"=="cancel" goto :taskSchedulerCleanup
	if "!taskName!"==" " goto :taskSchedulerCleanup
	
	echo.
	echo Details for task: !taskName!
	echo.
	schtasks /query /tn "!taskName!" /fo LIST /v
	
	if %errorlevel% NEQ 0 (
		echo.
		echo Task not found. Make sure you entered the exact name.
	)
	
	echo.
	pause
	goto :taskSchedulerCleanup

:deleteScheduledTask
	echo "============== DELETE SCHEDULED TASK =============="
	echo.
	echo WARNING: Only delete tasks you are certain are unauthorized!
	echo System tasks are necessary for Windows to function properly.
	echo.
	
	set /p taskName=Enter task name to delete (or 'cancel' to go back): 
	if /I "!taskName!"=="cancel" goto :taskSchedulerCleanup
	if "!taskName!"==" " goto :taskSchedulerCleanup
	
	echo.
	echo Task to delete: !taskName!
	echo.
	schtasks /query /tn "!taskName!" /fo LIST 2>nul
	
	if %errorlevel% NEQ 0 (
		echo Task not found.
		pause
		goto :taskSchedulerCleanup
	)
	
	echo.
	set /p confirm=Are you SURE you want to delete this task? [y/n]: 
	if /I "!confirm!"=="y" (
		schtasks /delete /tn "!taskName!" /f
		if %errorlevel%==0 (
			echo Task deleted successfully!
		) else (
			echo Failed to delete task. Check permissions or task name.
		)
	) else (
		echo Deletion cancelled.
	)
	
	echo.
	set /p another=Delete another task? [y/n]: 
	if /I "!another!"=="y" goto :deleteScheduledTask
	goto :taskSchedulerCleanup

:disableScheduledTask
	echo "============== DISABLE SCHEDULED TASK =============="
	echo.
	echo This will disable a task without deleting it.
	echo.
	
	set /p taskName=Enter task name to disable (or 'cancel' to go back): 
	if /I "!taskName!"=="cancel" goto :taskSchedulerCleanup
	if "!taskName!"==" " goto :taskSchedulerCleanup
	
	echo.
	echo Task to disable: !taskName!
	echo.
	schtasks /query /tn "!taskName!" /fo LIST 2>nul
	
	if %errorlevel% NEQ 0 (
		echo Task not found.
		pause
		goto :taskSchedulerCleanup
	)
	
	echo.
	set /p confirm=Disable this task? [y/n]: 
	if /I "!confirm!"=="y" (
		schtasks /change /tn "!taskName!" /disable
		if %errorlevel%==0 (
			echo Task disabled successfully!
		) else (
			echo Failed to disable task. Check permissions or task name.
		)
	) else (
		echo Action cancelled.
	)
	
	echo.
	set /p another=Disable another task? [y/n]: 
	if /I "!another!"=="y" goto :disableScheduledTask
	goto :taskSchedulerCleanup

:openTaskScheduler
	echo "============== OPEN TASK SCHEDULER GUI =============="
	echo.
	echo Opening Task Scheduler...
	echo.
	echo You can manually review and manage tasks from the GUI.
	echo.
	
	taskschd.msc
	
	echo Task Scheduler opened.
	pause
	goto :taskSchedulerCleanup

:windowsSecurityConfig
	echo "============== WINDOWS DEFENDER & SECURITY =============="
	echo.
	echo This will enable and configure Windows security features.
	echo.
	echo "1) Enable Windows Defender"
	echo "2) Update Windows Defender definitions"
	echo "3) Run quick scan"
	echo "4) Run full scan"
	echo "5) Enable Real-time Protection"
	echo "6) Check Windows Security status"
	echo "7) Open Windows Security Center"
	echo "8) Back to main menu"
	echo.
	set /p choice=Select an option: 
	
	if "%choice%"=="1" goto :enableDefender
	if "%choice%"=="2" goto :updateDefender
	if "%choice%"=="3" goto :quickScan
	if "%choice%"=="4" goto :fullScan
	if "%choice%"=="5" goto :enableRealTimeProtection
	if "%choice%"=="6" goto :checkSecurityStatus
	if "%choice%"=="7" goto :openSecurityCenter
	if "%choice%"=="8" goto :menu
	
	echo "Invalid option. Please try again."
	pause
	goto :windowsSecurityConfig

:enableDefender
	echo "============== ENABLE WINDOWS DEFENDER =============="
	echo.
	echo Enabling Windows Defender via registry and services...
	echo.
	
	rem Remove DisableAntiSpyware registry key if it exists
	reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /f 2>nul
	if %errorlevel%==0 (
		echo Removed DisableAntiSpyware policy.
	) else (
		echo DisableAntiSpyware policy not found (already enabled).
	)
	
	rem Enable Windows Defender service
	echo.
	echo Enabling Windows Defender service...
	sc config WinDefend start= auto
	net start WinDefend 2>nul
	
	if %errorlevel%==0 (
		echo Windows Defender service started.
	) else (
		echo Windows Defender service may already be running.
	)
	
	echo.
	echo Windows Defender enabled!
	pause
	goto :windowsSecurityConfig

:updateDefender
	echo "============== UPDATE DEFENDER DEFINITIONS =============="
	echo.
	echo Updating Windows Defender virus definitions...
	echo This may take a few moments.
	echo.
	
	rem Update definitions using PowerShell
	powershell -Command "Update-MpSignature"
	
	if %errorlevel%==0 (
		echo.
		echo Defender definitions updated successfully!
	) else (
		echo.
		echo Failed to update definitions. Check your internet connection.
	)
	
	pause
	goto :windowsSecurityConfig

:quickScan
	echo "============== WINDOWS DEFENDER QUICK SCAN =============="
	echo.
	echo Starting a quick scan...
	echo This will scan common malware locations.
	echo.
	
	powershell -Command "Start-MpScan -ScanType QuickScan"
	
	echo.
	echo Quick scan completed. Check Windows Security for results.
	pause
	goto :windowsSecurityConfig

:fullScan
	echo "============== WINDOWS DEFENDER FULL SCAN =============="
	echo.
	echo WARNING: A full scan can take a long time (30+ minutes).
	echo.
	set /p confirm=Start full scan? [y/n]: 
	
	if /I "!confirm!"=="y" (
		echo.
		echo Starting full scan...
		echo.
		powershell -Command "Start-MpScan -ScanType FullScan"
		echo.
		echo Full scan completed. Check Windows Security for results.
	) else (
		echo Scan cancelled.
	)
	
	pause
	goto :windowsSecurityConfig

:enableRealTimeProtection
	echo "============== ENABLE REAL-TIME PROTECTION =============="
	echo.
	echo Enabling Real-time Protection...
	echo.
	
	rem Enable real-time monitoring
	powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"
	
	if %errorlevel%==0 (
		echo Real-time protection enabled!
	) else (
		echo Failed to enable real-time protection. May require manual configuration.
	)
	
	echo.
	echo Enabling other protection features...
	powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $false"
	powershell -Command "Set-MpPreference -DisableIOAVProtection $false"
	powershell -Command "Set-MpPreference -DisableScriptScanning $false"
	
	echo.
	echo Protection features configured!
	pause
	goto :windowsSecurityConfig

:checkSecurityStatus
	echo "============== WINDOWS SECURITY STATUS =============="
	echo.
	echo Checking Windows Defender status...
	echo.
	
	powershell -Command "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, BehaviorMonitorEnabled, AntivirusSignatureLastUpdated | Format-List"
	
	echo.
	echo Checking Windows Defender service status...
	sc query WinDefend | findstr "STATE"
	
	echo.
	pause
	goto :windowsSecurityConfig

:openSecurityCenter
	echo "============== OPEN WINDOWS SECURITY CENTER =============="
	echo.
	echo Opening Windows Security Center...
	echo.
	
	start windowsdefender:
	
	echo Windows Security opened.
	pause
	goto :windowsSecurityConfig

:powershellCheck
	echo "============== POWERSHELL VERSION CHECK =============="
	echo.
	echo Checking PowerShell version...
	echo.
	
	rem Display PowerShell version
	powershell -Command "$PSVersionTable.PSVersion | Format-List"
	
	echo.
	echo Recommended: PowerShell 5.1 or higher for Windows 10/11
	echo.
	echo If your version is outdated:
	echo - Windows 10/11: Update via Windows Update
	echo - Windows 7/8: Install Windows Management Framework 5.1
	echo.
	
	set /p install=Would you like to check for Windows Updates now? [y/n]: 
	if /I "!install!"=="y" (
		echo.
		echo Opening Windows Update...
		start ms-settings:windowsupdate
	)
	
	pause
	goto :menu

:criticalChecks
	echo "============== CRITICAL SECURITY CHECKS =============="
	echo.
	echo Running comprehensive security checks...
	echo.
	echo "1) Check for missing critical updates"
	echo "2) Verify system file integrity (SFC)"
	echo "3) Check disk health (CHKDSK)"
	echo "4) Review event logs for security issues"
	echo "5) Check for rootkits (basic)"
	echo "6) Run all checks (recommended)"
	echo "7) Back to main menu"
	echo.
	set /p choice=Select an option: 
	
	if "%choice%"=="1" goto :checkUpdates
	if "%choice%"=="2" goto :runSFC
	if "%choice%"=="3" goto :runCHKDSK
	if "%choice%"=="4" goto :reviewEventLogs
	if "%choice%"=="5" goto :rootkitCheck
	if "%choice%"=="6" goto :runAllChecks
	if "%choice%"=="7" goto :menu
	
	echo "Invalid option. Please try again."
	pause
	goto :criticalChecks

:checkUpdates
	echo "============== CHECK FOR UPDATES =============="
	echo.
	echo Checking Windows Update status...
	echo.
	
	powershell -Command "Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 10 | Format-Table -AutoSize"
	
	echo.
	echo Above are the 10 most recent updates installed.
	echo.
	set /p open=Open Windows Update to check for more? [y/n]: 
	if /I "!open!"=="y" (
		start ms-settings:windowsupdate
	)
	
	pause
	goto :criticalChecks

:runSFC
	echo "============== SYSTEM FILE CHECKER =============="
	echo.
	echo Running System File Checker to verify integrity of system files...
	echo This may take 10-15 minutes.
	echo.
	set /p confirm=Start SFC scan? [y/n]: 
	
	if /I "!confirm!"=="y" (
		echo.
		echo Running SFC /scannow...
		sfc /scannow
		echo.
		echo SFC scan completed. Review results above.
	) else (
		echo Scan cancelled.
	)
	
	pause
	goto :criticalChecks

:runCHKDSK
	echo "============== CHECK DISK =============="
	echo.
	echo CHKDSK scans for disk errors and bad sectors.
	echo.
	echo NOTE: Full scan requires a reboot and runs before Windows starts.
	echo.
	echo "Options:"
	echo "1) Quick check (read-only, no reboot)"
	echo "2) Full scan on next reboot (recommended if issues suspected)"
	echo "3) Cancel"
	echo.
	set /p chkChoice=Select option: 
	
	if "!chkChoice!"=="1" (
		echo.
		echo Running quick disk check...
		chkdsk C:
		echo.
		echo Quick check completed.
	) else if "!chkChoice!"=="2" (
		echo.
		echo Scheduling full CHKDSK on next reboot...
		echo Y | chkdsk C: /F /R
		echo.
		echo CHKDSK will run on next system reboot.
		set /p reboot=Reboot now? [y/n]: 
		if /I "!reboot!"=="y" shutdown /r /t 30
	) else (
		echo Cancelled.
	)
	
	pause
	goto :criticalChecks

:reviewEventLogs
	echo "============== REVIEW SECURITY EVENT LOGS =============="
	echo.
	echo Checking recent security events...
	echo.
	
	echo [Failed Login Attempts]
	powershell -Command "Get-EventLog -LogName Security -InstanceId 4625 -Newest 10 -ErrorAction SilentlyContinue | Format-Table -AutoSize TimeGenerated, Message"
	
	echo.
	echo [Account Lockouts]
	powershell -Command "Get-EventLog -LogName Security -InstanceId 4740 -Newest 10 -ErrorAction SilentlyContinue | Format-Table -AutoSize TimeGenerated, Message"
	
	echo.
	echo [System Errors (Critical)]
	powershell -Command "Get-EventLog -LogName System -EntryType Error -Newest 10 -ErrorAction SilentlyContinue | Format-Table -AutoSize TimeGenerated, Source, Message"
	
	echo.
	set /p openEV=Open Event Viewer for detailed review? [y/n]: 
	if /I "!openEV!"=="y" eventvwr.msc
	
	pause
	goto :criticalChecks

:rootkitCheck
	echo "============== BASIC ROOTKIT CHECK =============="
	echo.
	echo Checking for common rootkit indicators...
	echo.
	
	echo [Checking for hidden processes]
	tasklist /SVC
	
	echo.
	echo [Checking for suspicious drivers]
	driverquery
	
	echo.
	echo NOTE: For thorough rootkit detection, use dedicated tools like:
	echo - GMER
	echo - TDSSKiller
	echo - Malwarebytes Anti-Rootkit
	echo.
	
	pause
	goto :criticalChecks

:runAllChecks
	echo "============== RUNNING ALL CHECKS =============="
	echo.
	echo This will run all security checks. This may take 30+ minutes.
	echo.
	set /p confirmAll=Continue with all checks? [y/n]: 
	
	if /I NOT "!confirmAll!"=="y" goto :criticalChecks
	
	echo.
	echo [1/5] Checking Windows Updates...
	powershell -Command "Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 5"
	
	echo.
	echo [2/5] Running System File Checker...
	sfc /scannow
	
	echo.
	echo [3/5] Checking disk (read-only)...
	chkdsk C:
	
	echo.
	echo [4/5] Reviewing security event logs...
	powershell -Command "Get-EventLog -LogName Security -InstanceId 4625 -Newest 5 -ErrorAction SilentlyContinue | Format-Table TimeGenerated, Message"
	
	echo.
	echo [5/5] Checking for suspicious processes...
	tasklist /SVC | findstr /I "suspicious malware trojan"
	
	echo.
	echo ========================================
	echo ALL CHECKS COMPLETED!
	echo ========================================
	echo.
	echo Review the output above for any issues.
	
	pause
	goto :criticalChecks

:networkSecurity
	echo "============== NETWORK SECURITY CHECKS =============="
	echo.
	echo Check and secure network connections and ports.
	echo.
	echo "1) Show active network connections"
	echo "2) Show listening ports"
	echo "3) Show network adapter configuration"
	echo "4) Disable unused network adapters"
	echo "5) Check for open shares"
	echo "6) Reset TCP/IP stack"
	echo "7) Back to main menu"
	echo.
	set /p choice=Select an option: 
	
	if "%choice%"=="1" goto :showConnections
	if "%choice%"=="2" goto :showListeningPorts
	if "%choice%"=="3" goto :showNetworkConfig
	if "%choice%"=="4" goto :disableAdapters
	if "%choice%"=="5" goto :checkShares
	if "%choice%"=="6" goto :resetTCPIP
	if "%choice%"=="7" goto :menu
	
	echo "Invalid option. Please try again."
	pause
	goto :networkSecurity

:showConnections
	echo "============== ACTIVE NETWORK CONNECTIONS =============="
	echo.
	echo Showing all active network connections...
	echo.
	
	netstat -ano | findstr ESTABLISHED
	
	echo.
	echo Legend: Proto Local-Address Foreign-Address State PID
	echo.
	echo Review the foreign addresses. Suspicious connections may indicate:
	echo - Malware communicating with C2 servers
	echo - Unauthorized remote access
	echo - Data exfiltration
	echo.
	set /p pid=Enter PID to investigate (or press Enter to skip): 
	if NOT "!pid!"=="" (
		echo.
		echo Process details for PID !pid!:
		tasklist /FI "PID eq !pid!" /V
	)
	
	pause
	goto :networkSecurity

:showListeningPorts
	echo "============== LISTENING PORTS =============="
	echo.
	echo Showing all listening ports and associated processes...
	echo.
	
	netstat -ano | findstr LISTENING
	
	echo.
	echo Common legitimate ports:
	echo - 135, 139, 445: Windows networking (SMB, RPC)
	echo - 3389: Remote Desktop
	echo - 80, 443: HTTP/HTTPS (if running web server)
	echo.
	echo Investigate any unexpected listening ports!
	echo.
	
	set /p saveList=Save listening ports to file? [y/n]: 
	if /I "!saveList!"=="y" (
		netstat -ano | findstr LISTENING > %temp%\listening_ports.txt
		echo Saved to %temp%\listening_ports.txt
		start notepad %temp%\listening_ports.txt
	)
	
	pause
	goto :networkSecurity

:showNetworkConfig
	echo "============== NETWORK ADAPTER CONFIGURATION =============="
	echo.
	echo Displaying network adapter information...
	echo.
	
	ipconfig /all
	
	echo.
	echo Check for:
	echo - Unexpected IP addresses
	echo - Unauthorized DNS servers
	echo - Multiple network adapters (some may be unused)
	echo.
	
	pause
	goto :networkSecurity

:disableAdapters
	echo "============== DISABLE UNUSED NETWORK ADAPTERS =============="
	echo.
	echo Listing network adapters...
	echo.
	
	powershell -Command "Get-NetAdapter | Format-Table Name, Status, InterfaceDescription"
	
	echo.
	echo WARNING: Only disable adapters you are certain are not in use!
	echo Disabling the wrong adapter could break network connectivity.
	echo.
	
	set /p adapterName=Enter adapter name to disable (or 'cancel' to go back): 
	if /I "!adapterName!"=="cancel" goto :networkSecurity
	if "!adapterName!"=="" goto :networkSecurity
	
	echo.
	set /p confirm=Are you sure you want to disable "!adapterName!"? [y/n]: 
	if /I "!confirm!"=="y" (
		powershell -Command "Disable-NetAdapter -Name '!adapterName!' -Confirm:$false"
		if %errorlevel%==0 (
			echo Adapter disabled successfully!
		) else (
			echo Failed to disable adapter. Check the name and try again.
		)
	) else (
		echo Action cancelled.
	)
	
	pause
	goto :networkSecurity

:checkShares
	echo "============== CHECK NETWORK SHARES =============="
	echo.
	echo Listing all network shares...
	echo.
	
	net share
	
	echo.
	echo Default Windows shares (usually safe):
	echo - ADMIN$, C$, IPC$: Administrative shares
	echo.
	echo Remove any unauthorized shares immediately!
	echo.
	
	set /p removeShare=Enter share name to remove (or press Enter to skip): 
	if NOT "!removeShare!"=="" (
		echo.
		set /p confirm=Remove share "!removeShare!"? [y/n]: 
		if /I "!confirm!"=="y" (
			net share !removeShare! /delete
			echo Share removed.
		)
	)
	
	pause
	goto :networkSecurity

:resetTCPIP
	echo "============== RESET TCP/IP STACK =============="
	echo.
	echo This will reset the TCP/IP stack and Winsock catalog.
	echo Use this if you suspect network configuration tampering.
	echo.
	echo WARNING: This may temporarily disrupt network connectivity.
	echo.
	
	set /p confirm=Proceed with TCP/IP reset? [y/n]: 
	if /I NOT "!confirm!"=="y" goto :networkSecurity
	
	echo.
	echo Resetting TCP/IP stack...
	netsh int ip reset
	
	echo.
	echo Resetting Winsock catalog...
	netsh winsock reset
	
	echo.
	echo TCP/IP stack has been reset!
	echo.
	echo A system reboot is recommended for changes to take full effect.
	set /p reboot=Reboot now? [y/n]: 
	if /I "!reboot!"=="y" shutdown /r /t 30
	
	pause
	goto :networkSecurity

:exploitScanner
	echo "============== EXPLOIT SCRIPT SCANNER =============="
	echo.
	echo Scanning for common exploit scripts and hacking tools...
	echo.
	
	set FOUND=0
	
	rem Scan for shellshock exploits
	echo [1/5] Scanning for shellshock exploits...
	dir /s /b C:\Users\*shellshock* 2>nul > %temp%\exploits.txt
	for %%A in (%temp%\exploits.txt) do set /a FOUND+=1
	
	rem Scan for metasploit
	echo [2/5] Scanning for Metasploit...
	dir /s /b C:\Users\*metasploit* C:\Users\*msfconsole* 2>nul >> %temp%\exploits.txt
	
	rem Scan for common exploit file extensions
	echo [3/5] Scanning for exploit scripts (.py, .rb, .sh with exploit in name)...
	dir /s /b C:\Users\*exploit*.py C:\Users\*exploit*.rb C:\Users\*exploit*.sh 2>nul >> %temp%\exploits.txt
	
	rem Scan for hacking tools
	echo [4/5] Scanning for hacking tools...
	dir /s /b C:\Users\*nmap* C:\Users\*wireshark* C:\Users\*burp* C:\Users\*sqlmap* 2>nul >> %temp%\exploits.txt
	
	rem Scan for keyloggers and backdoors
	echo [5/5] Scanning for keyloggers and backdoors...
	dir /s /b C:\Users\*keylog* C:\Users\*backdoor* C:\Users\*rootkit* 2>nul >> %temp%\exploits.txt
	
	echo.
	
	for %%A in (%temp%\exploits.txt) do set filesize=%%~zA
	if %filesize% GTR 0 (
		echo WARNING: Potential exploit scripts/hacking tools found!
		echo.
		start notepad %temp%\exploits.txt
		echo.
		echo Review the list in Notepad. Common exploits:
		echo - shellshock-exploit.py
		echo - Any files with "exploit" in the name
		echo - Metasploit framework files
		echo.
		set /p delete=Delete all found exploit scripts? [y/n]: 
		if /I "!delete!"=="y" (
			echo.
			echo Deleting exploit scripts...
			for /f "delims=" %%F in (%temp%\exploits.txt) do (
				del /f /q "%%F" 2>nul
				if %errorlevel%==0 (
					echo Deleted: %%F
				) else (
					echo Failed: %%F
				)
			)
			echo.
			echo Deletion complete.
		) else (
			echo Files not deleted.
		)
	) else (
		echo No exploit scripts found.
	)
	
	del %temp%\exploits.txt 2>nul
	pause
	goto :menu

:serverHardening
	echo "============== SERVER HARDENING =============="
	echo.
	echo This checks and hardens common server applications.
	echo.
	echo "1) Harden Apache HTTP Server"
	echo "2) Harden IIS (Internet Information Services)"
	echo "3) Harden FTP Server"
	echo "4) Back to main menu"
	echo.
	set /p choice=Select an option: 
	
	if "%choice%"=="1" goto :hardenApache
	if "%choice%"=="2" goto :hardenIIS
	if "%choice%"=="3" goto :hardenFTP
	if "%choice%"=="4" goto :menu
	
	echo Invalid option.
	pause
	goto :serverHardening

:hardenApache
	echo "============== APACHE HARDENING =============="
	echo.
	echo Checking for Apache installation...
	echo.
	
	if exist "C:\Apache24\conf\httpd.conf" (
		echo Apache found at C:\Apache24
		echo.
		echo Recommended security settings:
		echo - ServerSignature Off
		echo - ServerTokens Prod
		echo - TraceEnable Off
		echo.
		set /p auto=Automatically apply these settings? [y/n]: 
		
		if /I "!auto!"=="y" (
			echo.
			echo Backing up httpd.conf...
			copy "C:\Apache24\conf\httpd.conf" "C:\Apache24\conf\httpd.conf.backup" >nul
			
			echo Applying security settings...
			powershell -Command "(Get-Content 'C:\Apache24\conf\httpd.conf') -replace 'ServerSignature On', 'ServerSignature Off' | Set-Content 'C:\Apache24\conf\httpd.conf'"
			powershell -Command "(Get-Content 'C:\Apache24\conf\httpd.conf') -replace 'ServerTokens Full', 'ServerTokens Prod' | Set-Content 'C:\Apache24\conf\httpd.conf'"
			
			echo.
			echo Apache hardened! Restart Apache for changes to take effect.
		) else (
			echo.
			echo Opening httpd.conf in Notepad...
			echo.
			echo Manually change:
			echo - ServerSignature On  TO  ServerSignature Off
			echo - ServerTokens Full   TO  ServerTokens Prod
			echo.
			start notepad "C:\Apache24\conf\httpd.conf"
		)
	) else if exist "C:\Program Files\Apache\conf\httpd.conf" (
		echo Apache found at C:\Program Files\Apache
		echo Please manually edit: C:\Program Files\Apache\conf\httpd.conf
		echo Set ServerSignature Off and ServerTokens Prod
		start notepad "C:\Program Files\Apache\conf\httpd.conf"
	) else (
		echo Apache not found in common locations.
		echo If Apache is installed, manually locate httpd.conf and set:
		echo - ServerSignature Off
		echo - ServerTokens Prod
	)
	
	pause
	goto :serverHardening

:hardenIIS
	echo "============== IIS HARDENING =============="
	echo.
	echo Checking for IIS installation...
	echo.
	
	sc query W3SVC >nul 2>&1
	if %errorlevel%==0 (
		echo IIS detected.
		echo.
		echo Opening IIS Manager...
		echo.
		echo Recommended manual steps:
		echo 1. Remove unused IIS features
		echo 2. Disable directory browsing
		echo 3. Enable request filtering
		echo 4. Set custom error pages
		echo 5. Disable WebDAV if not needed
		echo.
		pause
		inetmgr
	) else (
		echo IIS not installed or not running.
	)
	
	pause
	goto :serverHardening

:hardenFTP
	echo "============== FTP SERVER HARDENING =============="
	echo.
	echo Recommended: Disable FTP entirely if not required!
	 echo.
	echo FTP transmits credentials in plaintext.
	echo Consider using SFTP (SSH File Transfer Protocol) instead.
	echo.
	set /p disable=Disable FTP service? [y/n]: 
	
	if /I "!disable!"=="y" (
		sc stop ftpsvc
		sc config ftpsvc start= disabled
		echo FTP service disabled!
	) else (
		echo FTP service left enabled.
	)
	
	pause
	goto :serverHardening
endlocal
