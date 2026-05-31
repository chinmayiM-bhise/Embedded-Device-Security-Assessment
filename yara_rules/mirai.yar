rule Mirai_Botnet {
    meta:
        description = "Detects Mirai IoT Botnet"
        author = "IoT Scanner"
    strings:
        $s1 = "POST /cdn-cgi/"
        $s2 = "X-Target: "
        $s3 = "X-Token: "
        $s4 = "X-Forwarded-For: "
        $s5 = "/bin/busybox MIRAI"
        $s6 = "mirai" nocase
    condition:
        3 of them
}

rule IoT_Malware_General {
    meta:
        description = "Detects general IoT malware patterns with high confidence"
    strings:
        $s1 = "chmod +x"
        $s2 = "wget http://"
        $s3 = "curl -O http://"
        $s4 = "/dev/watchdog"
        $s5 = "/dev/misc"
        $s6 = "rm -rf /"
        $s7 = "busybox" nocase
        $s8 = "iptables -A"
    condition:
        4 of them
}

