rule Insecure_Reverse_Shell {
    meta:
        description = "Detects embedded netcat or bash reverse shell commands"
        author = "IoT Security Scanner"
        severity = "High"
    strings:
        $r1 = /nc\s+(-e|-c)\s+\/(bin|sbin|usr)\/(sh|bash)/ ascii
        $r2 = /bash\s+-i\s+>&?\s+\/dev\/tcp\// ascii
        $r3 = /telnet\s+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s+[0-9]+\s+\|\s+\/bin\/sh/ ascii
        $r4 = /rm\s+-f\s+\/tmp\/f;\s*mkfifo\s+\/tmp\/f/ ascii
    condition:
        any of them
}

rule Suspicious_Remote_Execution {
    meta:
        description = "Detects payload fetching and direct execution pipelines"
        author = "IoT Security Scanner"
        severity = "High"
    strings:
        $e1 = /wget\s+https?:\/\/[^\s]+\s+(-O|-q|-P)\s+[^\s]+\s+&&\s+chmod\s+\+x/ ascii
        $e2 = /curl\s+(-s|-k|-O)\s+https?:\/\/[^\s]+\s+\|\s+(sh|bash)/ ascii
        $e3 = /tftp\s+-g\s+-r\s+[^\s]+\s+[0-9.]+\s+&&\s+chmod/ ascii
    condition:
        any of them
}

rule UPX_Packed_Binary {
    meta:
        description = "Detects UPX packed binary payloads frequently used by IoT malware"
        author = "IoT Security Scanner"
        severity = "Medium"
    strings:
        $u1 = "UPX!" ascii
        $u2 = "UPX0" ascii
        $u3 = "UPX1" ascii
    condition:
        $u1 at 0 or (2 of them)
}
