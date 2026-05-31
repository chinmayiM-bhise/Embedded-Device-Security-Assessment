rule Gafgyt_Bashlite {
    meta:
        description = "Detects Gafgyt (Bashlite) IoT botnet"
        author = "IoT Security Scanner"
    strings:
        $s1 = "Gafgyt" ascii nocase
        $s2 = "BASHLITE" ascii nocase
        $s3 = "BUILD %s" ascii
        $s4 = "PONG" ascii
        $s5 = "PING" ascii
    condition:
        (all of ($s1, $s2)) or 
        ($s1 and 2 of ($s3, $s4, $s5))
}

rule Hajime {
    meta:
        description = "Detects Hajime IoT worm"
    strings:
        $s1 = "hajime" ascii nocase
        $s2 = "/dev/watchdog" ascii
        $s3 = "HTCP" ascii
    condition:
        all of them
}

rule Tsunami_Kaiten {
    meta:
        description = "Detects Tsunami (Kaiten) IRC botnet"
    strings:
        $s1 = "TSUNAMI" ascii nocase
        $s2 = "KAITEN" ascii nocase
        $s3 = "NICK %s" ascii
        $s4 = "USER %s %s %s :%s" ascii
    condition:
        2 of them
}

rule UPX_Compressed {
    meta:
        description = "Detects UPX compressed binaries (often used by malware)"
    strings:
        $s1 = "UPX!" ascii
    condition:
        $s1 at 0 or $s1 in (0..1024)
}
