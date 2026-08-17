rule Mirai_Botnet_Core {
    meta:
        description = "Detects Mirai IoT botnet core routines and network strings"
        author = "IoT Security Scanner"
        severity = "Critical"
    strings:
        $s1 = "POST /cdn-cgi/" ascii
        $s2 = "X-Target: " ascii
        $s3 = "X-Token: " ascii
        $s4 = "X-Forwarded-For: " ascii
        $s5 = "/bin/busybox MIRAI" ascii
        $s6 = "mirai" ascii nocase
        $s7 = "dvrHelper" ascii nocase
        $s8 = "listen 0.0.0.0:" ascii
    condition:
        3 of ($s*)
}

rule Mirai_Variant_Satori_Okiru {
    meta:
        description = "Detects Mirai variants Satori and Okiru"
        author = "IoT Security Scanner"
        severity = "Critical"
    strings:
        $v1 = "Satori" ascii nocase
        $v2 = "Okiru" ascii nocase
        $v3 = "Echobot" ascii nocase
        $v4 = "Moobot" ascii nocase
        $c1 = "/bin/busybox rm -rf" ascii
        $c2 = "wget http://" ascii
        $c3 = "/dev/watchdog" ascii
    condition:
        (1 of ($v*)) and (2 of ($c*))
}

rule Mirai_Telnet_Bruteforce_List {
    meta:
        description = "Detects Mirai hardcoded default credential dictionary"
        author = "IoT Security Scanner"
        severity = "High"
    strings:
        $c1 = "root:xc3511" ascii
        $c2 = "root:vizxv" ascii
        $c3 = "admin:admin" ascii
        $c4 = "root:888888" ascii
        $c5 = "root:xmhdipc" ascii
        $c6 = "root:default" ascii
        $c7 = "root:juantech" ascii
        $c8 = "root:123456" ascii
        $c9 = "root:54321" ascii
    condition:
        3 of them
}
