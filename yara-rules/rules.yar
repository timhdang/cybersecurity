rule WaferFamily
{
    strings:
        $signature1 = /(parseInt)(.{350,500})(parseInt)(.*)(;)/
        $signature2 = /(push)(.{,16})(shift)/
        $signature3 = "pipedream"
        $signature4 = "swipingDirection"
    condition: 
        any of them
}
rule discord_stealer 
{
    meta:
		description = "Detects the best Discord Password Stealer."
        author = "Tim Dang"
        date = "2022-09-13"
    strings: 
        $s1 = "api.deltastealer.xyz"
        $s2 = "data.new_password"
        $s3 = "data[\"card[number]\"]"
        $s4 = "passwordChanged"
        $s5 = "emailChanged"
        $s6 = "process.env.temp"
        $s7 = "deltastealer.xyz"
        $s8 = "https://discord.com/api/v*/users/@me"
        $s9 = "https://discordapp.com/api/v*/users/@me"
        $s10 = "https://*.discord.com/api/v*/users/@me"
        $s11 = "https://discordapp.com/api/v*/auth/login"
        $s12 = "https://discord.com/api/v*/auth/login"
        $s13 = "https://*.discord.com/api/v*/auth/login"
        $s14 = "https://api.stripe.com/v*/tokens"
    condition:
        3 of them
}

rule contact_search
{
    strings:
        $s1 = "heyhtm+1@wearehackerone.com" fullword nocase
        $s2 = "commercialsalesandmarketing/contact-search" fullword nocase
        $s3 = "non-standard text encoding" fullword nocase
        $s4 = "Potential typo squat" fullword nocase
    condition:
        any of them
}
rule deere_i18n
{
    strings: 
        $a1 = "leisure-apis" fullword nocase
        $a2 = "yelp-api" fullword nocase
        $a3 = "media-apis" fullword nocase
        $a4 = "user-agent-api" fullword nocase
        $a5 = "scraper-api" fullword nocase
        $a6 = "twitter-login-api" fullword nocase
        $a7 = "google-login-api" fullword nocase
        $a8 = "search-apis" fullword nocase
        $a9 = "binScriptConfusion" fullword nocase
        $a10 = "high severity" fullword nocase
        $a11 = "CVS" fullword nocase
        $a12 = "eval(" fullword nocase
    condition: 
        2 of them
}

rule dicord_lofy 
{
    strings:
        $a1 = "Carcraftz" fullword nocase
        $a2 = "carcraftz" fullword nocase
        $a3 = "me@carcraftz.dev" fullword nocase
        $a4 = "lofy" fullword nocase
        $a5 = "104.198.14.52" fullword nocase
    condition:
        any of them
}
rule design_system 
{
    meta:
        author = "Tim Dang"
        reference = "https://jfrog.com/blog/testing-resiliency-against-malicious-package-attacks-a-double-edged-sword/"
    strings:
        $a1 = "sky-mavis/design-system" fullword nocase
        $a2 = "QGuLQG5-D-wz8H-a6tREOkBZDn_QpmcTK9n8-aous3rk" fullword nocase
        $a3 = "skymavis.com@gmail.com" fullword nocase
        $a4 = "Qw0JEUN5rYONXn08F8H6F9KzfiAirEf4Z733WDj98u6k" fullword nocase
        $a5 = "{homedir}/.ssh" fullword nocase
        $a6 = "{homedir}/.config" fullword nocase
        $a7 = "{homedir}/.kube" fullword nocase
        $a9 = "{docker}/.docker" fullword nocase
        $a10 = "axiedao" fullword nocase
        $a11 = "zoli4ch" fullword nocase
    condition:
        any of them
}
rule bitcoin_mining_hijacking 
{
    strings:
        $a1 = "0x510aec7f266557b7de753231820571b13eb31b57" fullword nocase
        $a2 = "ubqminer" fullword nocase
        $a3 = "T-Rex" fullword nocase
        $a4 = "ethminer" fullword nocase
        $a5 = "antivirus" fullword nocase
    condition: 
        any of them
}

rule pynput_keyboard_keylogger 
{
    meta:
		description = "Detects NodeRAT."
        author = "Tim Dang"
        date = "2022-09-19"
    strings: 
        $s1 = "pynput.keyboard" fullword nocase
        $s2 = "pynput" fullword nocase
        $s3 = "connected" fullword nocase
        $s4 = "disconnected" fullword nocase
        $s5 = "listening" fullword nocase
        $s6 = "controllerServerURL" fullword nocase
        $s7 = "heroku" fullword nocase
        $s8 = "Heroku" fullword nocase
        $s9 = "socket.io" fullword nocase
        $s10 = "emit" fullword nocase
    condition:
        4 of them
}
rule python_botnet 
{
    meta:
		description = "Detects PythonBot DDOS RAT Bot."
        author = "Tim Dang"
        date = "2022-09-19"
    strings: 
        $s1 = "SIGINT" fullword nocase
        $s2 = "SIGTERM" fullword nocase
        $s3 = "SOCK_STREAM" fullword nocase
        $s4 = "AF_INET" fullword nocase
        $s5 = "SOCK_DGRAM" fullword nocase
        $s6 = "recv(1024)" fullword wide ascii
        $s7 = "ctypes.windll.kernel32" fullword
        $s8 = "attack" fullword wide ascii
        $s9 = "kill" fullword wide ascii
        $s10 = "ping" fullword wide ascii
        $s11 = "BrokenPipeError" nocase wide ascii
    condition:
        4 of them
}

//Adding hash-based rules, some of them are executables that might be included in the packages.
rule ccleaner_compromised_installer {
    meta:
        description = "Inspired from https://blog.nviso.eu/2018/04/09/creating-custom-yara-rules/"
        author = "Tim Dang"
        date = "2022-09-25"
    condition:
        filesize > 9300 and filesize < 9600 
        //and hash.sha256(0, filesize) == "1a4a5123d7b2c534cb3e3168f7032cf9ebf38b9a2a97226d0fdb7933cf6030ff"
}

rule misc_chrome_urls {
    meta: 
        description = "Detect if malwares/virus are poking Chrome logs or settings"
        author = "Tim Dang"
        date = "2022-09-25"
    strings:
        $c1 = "chrome://conflicts" fullword
        $c2 = "chrome://crashes/" fullword
        $c3 = "chrome://device-log/" fullword
        $c4 = "chrome://discards" fullword
        $c4b = "chrome://components" fullword
        $c5 = "chrome://crashes" fullword
        $c6 = "chrome://downloads" fullword
        $c7 = "chrome://extensions" fullword
        $c8 = "chrome://flags" fullword
        $c9 = "chrome://media-internals" fullword
        $c10 = "chrome://nacl" fullword 
        $c11 = "chrome://net-internals" fullword
        $c12 = "chrome://network-error" fullword
        $c13 = "chrome://network-errors" fullword
        $c14 = "chrome://password-manager-internals" fullword
        $c15 = "chrome://process-internals" fullword
        $c16 = "chrome://serviceworker-internals" fullword
        $c17 = "chrome://signin-internals" fullword
        $c18 = "chrome://sync-internals" fullword
        $c19 = "chrome://usb-internals" fullword
        $c20 = "chrome://version" fullword
        $c21 = "chrome://restart" fullword
        $c22 = "chrome://gpuclean" fullword
        $c23 = "chrome://crash" fullword
        $c24 = "chrome://quit" fullword
        $c25 = "chrome://kill" fullword
        $c26 = "chrome://crashdump" fullword
        $c27 = "chrome://hang" fullword
    condition:
        any of them      
}   

rule windows_file_system {
    meta:
        description = "Check if malwares/viruses are poking windows file system"
        reference = "inspired from https://www.makeuseof.com/tag/default-windows-files-folders/"
    strings:
        $w0 = "Program Files"
        $w1 = "Windows/System32" fullword ascii nocase
        $w2 = "pagefile.sys" fullword ascii nocase
        $w3 = "System%20Volume%20Information/" fullword ascii nocase
        $w4 = "Windows/WinSxS" fullword ascii nocase
        $w5 = "AppData/Local" fullword ascii nocase
        $w6 = "Program Files/RUXIM" fullword ascii nocase
    condition:
        any of them
}

rule windows_regedit {
    meta:
        description = "Check if malwares/viruses are poking windows regedit"
        author = "Tim Dang"
    strings:
        $s1 = "HKEY_CLASSES_ROOT" fullword ascii nocase
        $s2 = "HKEY_CURRENT_USER" fullword ascii nocase
        $s3 = "HKEY_LOCAL_MACHINE" fullword ascii nocase
        $s4 = "HKEY_USERS" fullword ascii nocase
        $s5 = "HKEY_CURRENT_CONFIG" fullword ascii nocase     
    condition:
        any of them
}

rule windows_application_service_tools {
    meta: 
        description = " "
        author = "Tim Dang"
        reference = "https://www.cheat-sheets.org/saved-copy/Windows_folders_quickref.pdf"
    strings:
        $s1 = "Bootcfg.exe" fullword ascii nocase
        $s2 = "Depends.exe" fullword ascii nocase
        $s3 = "Dxdiag.exe" fullword ascii nocase
        $s4 = "Drwatsn.exe" fullword ascii nocase
        $s5 = "Eventquery.vbs" fullword ascii nocase
        $s6 = "Eventtriggers.exe" fullword ascii nocase
        $s7 = "Eventtvwr.msc" fullword ascii nocase
        $s8 = "Gflags.exe" fullword ascii nocase
        $s9 = "Gpedit.msc" fullword ascii nocase
        $s10 = "Gpresult.exe" fullword ascii nocase
        $s11 = "Poolmoon.exe" fullword ascii nocase
        $s12 = "Perfmon.msc" fullword ascii nocase
        $s13 = "Regedit.exe" fullword ascii nocase
        $s14 = "Rsop.msc" fullword ascii nocase
        $s15 = "Runas.exe" fullword ascii nocase
        $s16 = "Sc.exe" fullword ascii nocase
        $s17 = "Services.msc" fullword ascii nocase
        $s18 = "Msconfig.exe" fullword ascii nocase
        $s19 = "Msinfo32.exe" fullword ascii nocase
        $s20 = "Systeminfo.exe" fullword ascii nocase
        $s21 = "TsKill.exe" fullword ascii nocase
        $s22 = "Tasklist.exe" fullword ascii nocase
        $s23 = "Taskman.exe" fullword ascii nocase
        $s24 = "Getmac.exe" fullword ascii nocase
        $s25 = "Ipconfig.exe" fullword ascii nocase
        $s26 = "Nbtstat.exe" fullword ascii nocase
        $s27 = "Netsh.exe" fullword ascii nocase
        $s28 = "NetDiag.exe" fullword ascii nocase
        $s29 = "Netcap.exe" fullword ascii nocase 
        $s30 = "NSlookup.exe" fullword ascii nocase
        $s31 = "Pathping.exe" fullword ascii nocase
    condition:
        any of them
}


rule windows_privilege_elevation {
    meta: 
        description = " "
        author = "Tim Dang"
        reference = "https://www.cheat-sheets.org/saved-copy/Windows_folders_quickref.pdf"
    strings:
        $s1 = "SeTcbPrivilege" fullword ascii nocase
        $s2 = "SeMachineAccountPrivilege" fullword ascii nocase
        $s3 = "SeIncreaseQuotaPrivilege" fullword ascii nocase
        $s4 = "SeBackupPrivilege" fullword ascii nocase
        $s5 = "SeChangeNotifyPrivilege" fullword ascii nocase
        $s6 = "SeSystemTimePrivilege" fullword ascii nocase
        $s7 = "SeCreateTokenPrivilege" fullword ascii nocase
        $s8 = "SeCreatePagefilePrivilege" fullword ascii nocase
        $s9 = "SeDebugPrivilege" fullword ascii nocase
        $s10 = "SeEnableDelegationPrivilege" fullword ascii nocase
        $s11 = "SeRemoteShutdownPrivilege" fullword ascii nocase
        $s12 = "SeAuditPrivillege" fullword ascii nocase
        $s13 = "SeIncreaseBasePriorityPrivilege" fullword ascii nocase
        $s14 = "SeLoadDriverPrivilege" fullword ascii nocase
        $s15 = "SeLockMemoryPrivilege" fullword ascii nocase
        $s16 = "SeSecurityPrivilege" fullword ascii nocase
        $s17 = "SeSystemEnvironmentPrivilege" fullword ascii nocase
        $s18 = "SeManageVolumnPrivilage" fullword ascii nocase
        $s19 = "SeProfileSingleProcessPrivilage" fullword ascii nocase
        $s20 = "SeSysmProfilePrivilege" fullword ascii nocase
        $s21 = "SeUndockPrivilege" fullword ascii nocase
        $s22 = "SeAssignPrimaryTokenPrivileage" fullword ascii nocase
        $s23 = "SeRestorePrivileage" fullword ascii nocase
        $s24 = "SeShutdownPrivilege" fullword ascii nocase
        $s25 = "SeSynchAgentPrivilege" fullword ascii nocase
        $s26 = "SeTakeTownershipPrivilege" fullword ascii nocase
    condition:
        any of them
}

rule MITRE_ATTACK_PYTHON_API {
    meta:
        author = "Tim Dang"
        reference = "https://blog.jscrambler.com/mitre-attck-framework"
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = "mitreattack.attackToExcel.attackToExcel" fullword ascii nocase
        $s2 = "mitreattack.attackToExcel.stixToDf" fullword ascii nocase
        $s3 = "mitreattack" fullword ascii nocase
        $s4 = "navlayers" fullword ascii nocase
        $s5 = "attackToExcel" fullword ascii nocase
        $s6 = "collections" fullword ascii nocase
        $s7 = "diffStix" fullword ascii nocase
        $s8 = "enterprise-attack" fullword ascii nocase
        $s9 = "techniquesData" fullword ascii nocase
        $s10 = "techniques" fullword ascii nocase
        $s11 = "procedure examples" fullword ascii nocase
    condition:
        2 of them
}

rule MITTRE_T1595_RECON_ACTIVE_SCANNING {
    meta:
        author = "Tim Dang"
        reference = "https://attack.mitre.org/techniques/T1595/001/ , https://www.caida.org/catalog/media/2012_analysis_stealth_scan_imc/analysis_stealth_scan_imc.pdf"
        description = "Active Scanning: Scanning IP Blocks"
    strings:
        $s1 = "TeamTNT" fullword ascii nocase
        $s2 = "FirstDay" fullword ascii nocase
        $s3 = "NewJob" fullword ascii nocase
        $s4 = "www.whois.net" fullword ascii nocase
        $s5 = "NMAP" fullword ascii nocase
        $s6 = "tracerouter" fullword ascii nocase
        $s7 = "tracert" fullword ascii nocase
        $s8 = "ping" fullword ascii nocase
        $s9 = "scan" fullword ascii nocase
        $s10 = "/0" fullword ascii nocase
        $s11 = "/8" fullword ascii nocase
        $s12 = "/24" fullword ascii nocase
        $s13 = "source" fullword ascii nocase
        $s14 = "destination" fullword ascii nocase
        $s15 = "SIPSCAN" fullword ascii nocase
     condition: 
        3 of them
}


rule MITRE_T1592_RECON_GATHER_VICTIM_HOST_INFORMATION {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = "serenity" fullword ascii nocase
        $s2 = "53R3N16Y" fullword ascii nocase
        $s3 = "--revht" fullword ascii nocase
        $s4 = "mail.webmailgoogle.com" fullword ascii nocase
        $s5 = "js.webmailgoogle.com" fullword ascii nocase
        $s6 = "122.10.9.109"
    condition:
        any of them
}

/*
rule MITRE_T1586_RESOURCE_COMPROMISE_ACCOUNTS {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim's compromised accounts, bought from 3rd party or from phishing."
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}
*/
rule MITRE_T1598_RESOURCE_ESTABLISH_ACCOUNTS {
    meta:
        author = "Tim Dang"
        reference = "https://www.securityweek.com/iranian-hackers-targeted-us-officials-elaborate-social-media-attack-operation"
        description = "Detects cybersecurity attacks based on known fake personas"
    strings:
        $s1 = "Sandra Maler" fullword ascii nocase
        $s2 = "Adia Mitchell" fullword ascii nocase
        $s3 = "Amanda Teyson" fullword ascii nocase
        $s4 = "Sara Mckibben" fullword ascii nocase
        $s5 = "Joseph Nilsson" fullword ascii nocase
        $s6 = "Jane Baker" fullword ascii nocase
        $s7 = "Berna Achando" fullword ascii nocase
        $s8 = "Jeann Maclkin" fullword ascii nocase
        $s9 = "Alfred Nilsson" fullword ascii nocase
        $s10 = "Josh Furie" fullword ascii nocase
        $s11 = "Dorotha Baasch" fullword ascii nocase
        $s12 = "Kenneth Babcock" fullword ascii nocase
        $s13 = "Donnie Eadense" fullword ascii nocase
    condition:
        any of them
}

rule MITRE_T1189_INITIAL_ACCESS_DRIVE_BY_COMPROMISE {
    meta:
        author = "Tim Dang"
        reference = "https://securelist.com/bad-rabbit-ransomware/82851/"
        description = "Detects use of drive-by compromise: Bad Rabit and C0d0so0 group"
    strings:
        $s1 = "jbossas.org" fullword ascii nocase
        $s2 = "supermanbox.org" fullword ascii nocase
        $s3 = "microsoft-cache.com" fullword ascii nocase
        $s4 = "dbgeng.dll" fullword ascii nocase
        $s5 = "fakerx86.exe" fullword ascii nocase
        $s6 = "ASCSTR_C" fullword ascii nocase
        $s7 = "wuservice.dll" fullword ascii nocase
        $s8 = "StartWorker" fullword ascii nocase
        $s9 = "StopWorker" fullword ascii nocase
        $s10 = "WorkerRun" fullword ascii nocase
        $s11 = "DllEntryPoint" fullword ascii nocase
    condition:
        any of them
}
/*
rule MITRE_T1566_INITIAL_ACCESS_PHISHING {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1195_INITIAL_ACCESS_SUPPLY_CHAIN_COMPROMISE {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}
*/
rule MITRE_T1078_INITIAL_ACCESS_VALID_ACCOUNT {
    meta:
        author = "Tim Dang"
        reference = "https://www.cisa.gov/uscert/ncas/alerts/aa22-074a"
        description = "Detects the use of inactive accounts, bought accounts, compromised credentials"
    strings:
        $s1 = "ping.exe" fullword ascii nocase
        $s2 = "regedit.exe" fullword ascii nocase
        $s3 = "rar.exe" fullword ascii nocase
        $s4 = "ntdsutil.exe" fullword ascii nocase
        $s4 = "duosecurity.com" fullword ascii nocase
        $s5 = "45.32.137.94" fullword ascii nocase
        $s6 = "191.96.121.162" fullword ascii nocase
        $s7 = "157.230.81.39" fullword ascii nocase
        $s8 = "157.230.81.46" fullword ascii nocase
        $s9 = "hosts" fullword ascii nocase
        $s10 = "localhost" fullword ascii nocase
    condition:
        2 of them
}
/*
rule MITRE_T1059_EXECUTION_COMMAND_AND_SCRIPTING_INTERPRETER {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1053_EXECUTION_SCHEDULED_TASK_JOB {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1569_EXECUTION_SYSTEM_SERVICES {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}   

rule MITRE_T1098_PERSISTENCE_ACCOUNT_MANIPULATION {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1136_PERSISTENCE_CREATE_ACCOUNT {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}
*/
rule MITRE_T1542_PERSISTENCE_PRE_OS_BOOT {
    meta:
        author = "Tim Dang"
        reference = "https://eclypsium.com/wp-content/uploads/2020/12/TrickBot-Now-Offers-TrickBoot-Persist-Brick-Profit.pdf"
        description = "Detects the use of bootkit"
    strings:
        $s1 = "permaDll32" fullword ascii nocase
        $s2 = "TrickBot" fullword ascii nocase
        $s3 = "Perma" fullword ascii nocase
        $s4 = "user_platform_check.dll" fullword ascii nocase
        $s5 = "MosaicRegressor" fullword ascii nocase
        $s6 = "PCH" fullword ascii nocase
        $s7 = "Not Admin" fullword ascii nocase
        $s8 = "subloop" fullword ascii nocase
        $s9 = "xorloop" fullword ascii nocase
        $s10 = "xoraddloop" fullword ascii nocase
        $s11 = "decodeloop" fullword ascii nocase
        $s12 = "libfwexok_rwdrv" fullword ascii nocase
        $s13 = "uefi_expl_port_read" fullword ascii nocase
        $s14 = "uefi_expl_port_write" fullword ascii nocase
        $s15 = "uefi_expl_phys_mem_read" fullword ascii nocase
        $s16 = "uefi_expl_phys_mem_write" fullword ascii nocase
        $s17 = "pci_read_reg" fullword ascii nocase
        $s18 = "pci_write_reg" fullword ascii nocase
        $s19 = "SPIBAR" fullword ascii nocase
        $s20 = "PRO-PR4" fullword ascii nocase
    condition:
        3 of them
}

rule MITRE_T1137_PERSISTENCE_OFFICE_APPLICATION_STARTUP {
    meta:
        author = "Tim Dang"
        reference = "https://labs.withsecure.com/publications/add-in-opportunities-for-office-persistence"
        description = "Detects the unauthorized starts of Microsoft Office-based applications"
    strings:
        $s1 = "StartUp" fullword ascii nocase
        $s2 = "dll" fullword ascii nocase
        $s3 = "wll" fullword ascii nocase
        $s4 = "AddIns" fullword ascii nocase
        $s5 = "%appdata%" fullword ascii nocase
        $s6 = "XLSTART" fullword ascii nocase
        $s7 = "regasm.exe" fullword ascii nocase
        $s8 = "-ep bypass -C" fullword ascii nocase
        $s9 = "HKEY_LOCAL_USER" fullword ascii nocase
        $s10 = "/s" fullword ascii nocase
        $s11 = "/i" fullword ascii nocase
        $s12 = "VSTOInstaller" fullword ascii nocase
        $s13 = "ThisAddIn-Startup" fullword ascii nocase
    condition:
        3 of them
}
/*
rule MITRE_T1134_PRIVILEGE_ESCALATION_ACCESS_TOKEN_MANIPULATION {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1611_PRIVILEGE_ESCALATION_ESCAPE_TO_HOST {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1564_DEFENSE_INVASION_HIDE_ARTIFACTS {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1497_DEFENSE_INVASION_VIRTUALIZATION_SANDBOX_EVASION {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1548_DEFENSE_EVASION_ABUSE_ELEVATION_CONTROL_MECHANISM {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1557_CREDENTIAL_ACCESS_ADVERSARY_IN_THE_MIDDLE {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1606_CREDENTIAL_ACCESS_FORGED_WEB_CREDENTIALS {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1056_CREDENTIAL_ACCESS_INPUT_CAPTURE {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1003_CREDENTIAL_ACCESS_CREDENTIAL_DUMPING {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1539_CREDENTIAL_ACCESS_STEAL_WEB_SESSION_COOKIE {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1087_DISCOVERY_ACCOUNT_DISCOVERY {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1217_DISCOVERY_BROWSER_BOOKMARK_DISCOVERY {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1021_REMOTE_SERVICES{
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1210_EXPLOITATION_OF_REMOTE_SERVICE {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1115_COLLECTION_CLIPBOARD_DATA {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1114_COLLECTION_EMAIL_COLLECTION {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1001_COMMAND_AND_CONTROL_DATA_OBFUSCATION {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1571_COMMAND_AND_CONTROL_NON_STANDARD_PORT {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1132_COMMAND_AND_CONTROL_DATA_ENCODING {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1030_EXFILTRATION_DATA_TRANSFER_SIZE_LIMITS {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1531_IMPACT_ACCOUNT_ACCESS_REMOVAL {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1485_IMPACT_DATA_DESTRUCTION {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1529_IMPACT_SYSTEM_SHUTDOWN_REBOOT {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}

rule MITRE_T1561_IMPACT_DISK_WIPE {
    meta:
        author = "Tim Dang"
        reference = " "
        description = "Detects the gathering of victim host information"
    strings:
        $s1 = ""
        $s2 = ""
        $s3 = ""

    condition:
        any of them
}
*/
