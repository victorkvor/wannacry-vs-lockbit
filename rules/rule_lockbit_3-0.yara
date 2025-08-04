rule LockBit_3_0_victorK
{
    meta:
        author = "Victor Kravchuk Vorkevych"
        source = "TFG - Ingeniería Inversa de Malware: Análisis y Técnicas de evasión"
        sharing = "TLP:WHITE"
        status = "RELEASED"
        description = "Detects LockBit 3.0 ransomware based on reverse engineering findings"
        category = "MALWARE"
        creation_date = "2025-06-06"
        malware_family = "LockBit 3.0"
        version = "1.0"

    strings:
        // Weird header unique data
        $header1 = ".xyz" wide ascii
        $header2 = ".rdata$zzzdbg" wide ascii
        $header3 = ".text$mn" wide ascii

        // Hashing function from custom_hashing_function
        $core_hash = { 02 F1 2A F1 [2-18] D3 CA 03 D0 }

        // Trampolines for API from load_apis_func
        $core_tramp1 = { 35 ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? 8B D8 6A 10 6A 00 ?? ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? 81 F1 ?? ?? ?? ?? 39 48 10 }
        $core_tramp2 = { C6 00 B8 8B D0 ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8B C8 D3 C3 89 5A 01 66 C7 42 05 C1 C8 88 4A 07 66 C7 42 08 FF E0 }
        $core_tramp3 = { 8B C8 D3 CB 89 5A 01 66 C7 42 05 C1 C0 88 4A 07 66 C7 42 08 FF E0 }
        $core_tramp4 = { B8 FF 5F 03 10 33 D8 89 5A 01 C6 42 05 35 89 42 06 66 C7 42 0A FF E0 }
        $core_tramp5 = { 8B C8 B8 FF 5F 03 10 33 D8 D3 C3 89 5A 01 66 C7 42 05 C1 C8 88 4A 07 C6 42 08 35 89 42 09 66 C7 42 0D FF E0 }
        $core_tramp6 = { 8B C8 B8 FF 5F 03 10 33 D8 D3 CB 89 5A 01 66 C7 42 05 C1 C0 88 4A 07 C6 42 08 35 89 42 09 66 C7 42 0D FF E0 }

        // Anti-debug techniques
        $core_antidbg1 = { 8B 40 18 F7 40 44 00 00 00 40 ?? ?? D1 C? }
        $core_antidbg2 = { 8B 40 40 C1 E8 1C A8 04 ?? ?? D1 C? }
        $core_antidbg3 = { 33 C0 40 40 8D 0C C5 01 00 00 00 83 7D 08 00 ?? ?? F7 D8 }

        // Custom base64
        $core_customb64 = { 3C 2B ?? ?? B0 78 ?? ?? 3C 2F ?? ?? B0 69 ?? ?? 3C 3D ?? ?? B0 7A }

        // Language whitelist
        $core_lang_whitelist_func = { BB 01 00 00 00 C1 E3 0A 80 F3 01 C0 E3 04 80 F3 09 66 3B DE }

        // Bypass UAC
        $core_uac1 = { ?? ?? 74 CD 21 81 ?? ?? ?? 07 60 89 A1 ?? ?? ?? B7 CA 19 9B ?? ?? ?? 09 35 1E A3 }
        $core_uac2 = { ?? ?? 45 A0 90 EF ?? ?? ?? 65 A0 8A EF ?? ?? ?? 61 A0 88 EF ?? ?? ?? 69 A0 93 EF }

        // AD exploitation SYSVOL
        $core_adexp = { ?? ?? 5C A0 A0 EF ?? ?? ?? 25 A0 8F EF ?? ?? ?? 5C A0 8F EF ?? ?? ?? 79 A0 8F EF }

    condition:
        (uint16(0) == 0x5A4D and filesize < 200KB and filesize > 100KB)
        and (
            4 of ($core*) or
            (all of ($header*) and 1 of ($core*))
        )
}
