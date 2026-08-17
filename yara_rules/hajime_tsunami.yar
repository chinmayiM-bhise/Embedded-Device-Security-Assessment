rule Hajime_IoT_Worm {
    meta:
        description = "Detects Hajime BitTorrent-based IoT worm"
        author = "IoT Security Scanner"
        severity = "Critical"
    strings:
        $h1 = "hajime" ascii nocase
        $h2 = "/dev/watchdog" ascii
        $h3 = "HTCP" ascii
        $h4 = "ATK_VEC" ascii
    condition:
        3 of them
}

rule Tsunami_Kaiten_Botnet {
    meta:
        description = "Detects Tsunami / Kaiten IRC botnet variants"
        author = "IoT Security Scanner"
        severity = "Critical"
    strings:
        $t1 = "TSUNAMI" ascii nocase
        $t2 = "KAITEN" ascii nocase
        $t3 = "NICK %s" ascii
        $t4 = "USER %s %s %s :%s" ascii
        $t5 = "NOTICE %s :Tsunami" ascii
        $t6 = "PRIVMSG %s :[PAN]" ascii
    condition:
        2 of ($t1, $t2) or ($t1 and 2 of ($t3, $t4, $t5, $t6)) or 3 of them
}
