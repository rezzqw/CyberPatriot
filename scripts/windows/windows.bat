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
	echo "5)Group management   		6)Services Mangement"
	echo "7)Windows Features 		8)Remote Desktop Configuration"
	echo "9)ScreenSaver Config  	10)User Account Control"
	echo "11)Disable Auto Play      12)Enable Firewall & Config"
	echo "13)Windows Updates/Auto   14)Detect and delete Prohibited Files"
	echo "15)RDP & RPC Config  		16)Disable IPv6"
	echo "69)Exit				    70)Reboot"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	set /p answer=Please choose an option: 
		if "%answer%"=="1" goto :accountPolicies
		if "%answer%"=="2" goto :localPolicies
		if "%answer%"=="3" goto :disableGuest
		if "%answer%"=="4" goto :userManagement
		if "%answer%"=="5" goto :groupManagement
		if "%answer%"=="6" goto :servicesManagement
		if "%answer%"=="7" goto :windowsFeatures
		if "%answer%"=="8" goto :remDesk
		if "%answer%"=="9" goto :screensaver
		if "%answer%"=="10" goto :uacConfig
		if "%answer%"=="11" goto :autoPlayConfig
		if "%answer%"=="12" goto :firewallConfig
		if "%answer%"=="13" goto :autoUpdate
		if "%answer%"=="14" goto :badFiles
		if "%answer%"=="15" goto :rpcRdpEncryption
		if "%answer%"=="16" goto :disableIPv6
		rem turn on screensaver
		rem password complexity
		if "%answer%"=="69" exit
		if "%answer%"=="70" shutdown /r
	pause


:accountPolicies
	echo Configuring Account Policies...
	echo.
	
	rem Password Policy
	echo Setting Password Policy...
	net accounts /minpwlen:14
	net accounts /maxpwage:30
	net accounts /minpwage:3
	net accounts /uniquepw:24
	
	rem Enable password complexity requirements
	secedit /export /cfg %temp%\secpol.cfg
	(echo [Unicode]&echo Unicode=yes&echo [System Access]&echo PasswordComplexity = 1&echo PasswordHistorySize = 24&echo [Version]&echo signature="$CHICAGO$"&echo Revision=1) > %temp%\secpol.cfg
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
	
	rem MS network client - Digitally sign communications (disabled per checklist)
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnableSecuritySignature /t REG_DWORD /d 0 /f
	
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
	echo Setting user properties...
	echo.
	echo Configuring:
	echo - User must change password at next logon
	echo - User CAN change password
	echo - Password DOES expire
	echo - Account is NOT disabled
	echo.
	
	wmic UserAccount set PasswordExpires=True
	wmic UserAccount set PasswordChangeable=True
	wmic UserAccount set PasswordRequired=True
	
	echo User properties set successfully!
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
	if /I "%answer%"=="n" goto :userManagement
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
	set /p grp=What group would you like to add a user to? (or type 'back' to cancel): 
	if /I "!grp!"=="back" goto :groupManagement
	
	echo.
	echo Current members of !grp!:
	net localgroup "!grp!"
	echo.
	
	set /p userAdd=Enter the username to add: 
	net localgroup "!grp!" "!userAdd!" /add
	
	if %errorlevel%==0 (
		echo !userAdd! has been added to !grp!
	) else (
		echo Failed to add !userAdd! to !grp!
	)
	
	pause
	
	set /p answer=Add another user to a group?[y/n]: 
	if /I "%answer%"=="y" goto :addToGroup
	goto :groupManagement

:removeFromGroup
	cls
	echo Current groups:
	net localgroup
	echo.
	set /p grp=What group would you like to remove a user from? (or type 'back' to cancel): 
	if /I "!grp!"=="back" goto :groupManagement
	
	echo.
	echo Current members of !grp!:
	net localgroup "!grp!"
	echo.
	
	set /p userRem=Enter the username to remove: 
	net localgroup "!grp!" "!userRem!" /delete
	
	if %errorlevel%==0 (
		echo !userRem! has been removed from !grp!
	) else (
		echo Failed to remove !userRem! from !grp!
	)
	
	pause
	
	set /p answer=Remove another user from a group?[y/n]: 
	if /I "%answer%"=="y" goto :removeFromGroup
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
	
	echo "Invalid option. Please try again.""
	pause
	goto :servicesManagement

:disableCommonServices
	echo Disabling common unnecessary services...
	echo.
	echo NOTE: Check the README for any critical services before disabling!
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
	echo Removing common unnecessary Windows features...
	echo.
	echo This will remove: FTP, Simple TCP/IP Services, Telnet Client, SMB 1.x
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
	echo "3) Open Windows Defender Firewall Advanced Security""
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
	dir /s /b C:\*.png C:\*.jpg C:\*.gif C:\*.mp3 C:\*.mp4 C:\*.mov 2>nul > %temp%\mediafiles.txt
	
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
				if !errorlevel!==0 (
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

endlocal