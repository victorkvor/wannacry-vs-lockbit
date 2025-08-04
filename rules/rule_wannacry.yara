rule Wannacry_victorK
{
    meta:
        author = "Victor Kravchuk Vorkevych"
        source = "TFG - Ingeniería Inversa de Malware: Análisis y Técnicas de evasión"
        sharing = "TLP:WHITE"
        status = "RELEASED"
        description = "Detects Wannacry ransomware based on reverse engineering findings"
        category = "MALWARE"
        creation_date = "2025-06-06"
        malware_family = "Wannacry"
        version = "1.0"

    strings:
        // Eternal Blue MS17-010
        $eblue1 = "__USERID_PLACEHOLDER__" fullword ascii
        $eblue2 = "__TREEID_PLACEHOLDER__" fullword ascii
        $eblue3 = "PC NETWORK PROGRAM 1.0" fullword ascii
        $eblue4 = "LANMAN1.0" fullword ascii
        $eblue5 = "Windows for Workgroups 3.1a" fullword ascii
        $eblue6 = "LANMAN2.1" fullword ascii
        $payload_eblue = { 68 36 61 67 4c 43 71 50 71 56 79 58 69 32 56 53 51 38 4f 36 59 62 39 69 6a 42 58 35 34 6a } // Eternal Blue payload at DAT_0041bbb0
    
        // General Wannacry strings
        $s1 = "mssecsvc.exe" fullword ascii
        $s2 = "Microsoft Security Center (2.0) Service" fullword ascii
        $s3 = "%s -m security" fullword ascii
        $s4 = "C:\\%s\\qeriuwjhrf" fullword ascii
        $s5 = "tasksche.exe" fullword ascii
        $s6 = "mssecsvc2.0" fullword ascii
        $s7 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii

        // Wannacry strings at resource 1831
        $1831_taskdl = { 74 61 73 6b 64 6c } // taskdl
        $1831_taskse = { 74 61 73 6b 73 65 } // taskse
        $1831_c_wnry = { 63 2e 77 6e 72 79 } // c.wnry
        $1831_t_wnry = { 74 2e 77 6e 72 79 } // t.wnry
        $1831_icacls = { 69 63 61 63 6c 73 20 2e 20 2f 67 72 61 6e 74 20 45 76 65 72 79 6f 6e 65 3a 46 20 2f 54 20 2f 43 20 2f 51 } // icacls . /grant Everyone:F /T /C /Q
        $1831_attrib_h = { 61 74 74 72 69 62 20 2b 68 20 2e } // attrib +h .
        $1831_wncry2ol7 = { 57 4e 63 72 79 40 32 6f 6c 37 } // WNcry@2ol7
        $1831_taskstart = { 54 61 73 6b 53 74 61 72 74 } // TaskStart
        $1831_wanacry = { 57 41 4e 41 43 52 59 21 } // WanaCry!
        $1831_wanacrypt0r = { 57 00 61 00 6e 00 61 00 43 00 72 00 79 00 70 00 74 00 30 00 72 } // WanaCrypt0r
        $1831_mutex = { 47 6c 6f 62 61 6c 5c 4d 73 57 69 6e 5a 6f 6e 65 73 43 61 63 68 65 43 6f 75 6e 74 65 72 4d 75 74 65 78 41 } // Global\\MsWinZonesCacheCounterMutexA
    condition:
        (uint16(0) == 0x5A4D and ((3 of ($1831*)) or (2 of ($s*) or ($payload_eblue and 1 of ($eblue*)))))
}