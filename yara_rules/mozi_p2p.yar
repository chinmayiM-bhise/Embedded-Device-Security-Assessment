rule Mozi_P2P_Botnet {
    meta:
        description = "Detects Mozi P2P IoT Worm and Botnet"
        author = "IoT Security Scanner"
        severity = "Critical"
    strings:
        $m1 = "[hpldf]" ascii
        $m2 = "[ss] " ascii
        $m3 = "8:count64:" ascii
        $m4 = "1:v4:id20:" ascii
        $m5 = "d1:ad2:id20:" ascii
        $m6 = "/proc/net/dev" ascii
        $m7 = "Mozi.m" ascii nocase
        $m8 = "Mozi.a" ascii nocase
    condition:
        3 of them
}
