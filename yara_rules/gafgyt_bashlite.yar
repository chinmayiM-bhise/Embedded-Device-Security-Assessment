rule Gafgyt_Bashlite_Core {
    meta:
        description = "Detects Gafgyt / BASHLITE / Lizkebab IoT botnets"
        author = "IoT Security Scanner"
        severity = "Critical"
    strings:
        $s1 = "Gafgyt" ascii nocase
        $s2 = "BASHLITE" ascii nocase
        $s3 = "BUILD %s" ascii
        $s4 = "PONG" ascii
        $s5 = "PING" ascii
        $s6 = "KILL_PROCESS" ascii
        $s7 = "SCANNER ON" ascii
        $s8 = "GETLOCALIP" ascii
    condition:
        (all of ($s1, $s2)) or ($s1 and 2 of ($s3, $s4, $s5, $s6, $s7, $s8))
}

rule Qbot_Torlus_Scanner {
    meta:
        description = "Detects Qbot / Torlus IRC payload and command loops"
        author = "IoT Security Scanner"
        severity = "High"
    strings:
        $q1 = "!* SH " ascii
        $q2 = "!* STD " ascii
        $q3 = "!* UDP " ascii
        $q4 = "!* TCP " ascii
        $q5 = "!* HTTP " ascii
        $q6 = "ADMIN %s" ascii
    condition:
        3 of them
}
