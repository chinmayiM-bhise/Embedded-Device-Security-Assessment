import os

def create_mock_firmware(target_dir):
    """Creates a mock extracted firmware directory with intentional vulnerabilities."""
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    # 1. Create a file with secrets
    with open(os.path.join(target_dir, "config.php"), "w") as f:
        f.write("<?php\n")
        f.write("$db_user = 'admin';\n")
        f.write("$db_pass = 'SuperSecretPassword123!';\n")
        f.write("$api_key = 'AIzaSyA-1234567890abcdefGHIJKLmnopQRSTU';\n")
        f.write("?>")

    # 2. Create a sensitive system file
    etc_dir = os.path.join(target_dir, "etc")
    os.makedirs(etc_dir, exist_ok=True)
    with open(os.path.join(etc_dir, "shadow"), "w") as f:
        f.write("root:$1$abc$12345:12345:0:99999:7:::\n")
    
    with open(os.path.join(etc_dir, "passwd"), "w") as f:
        f.write("root:x:0:0:root:/root:/bin/sh\n")

    # 3. Create a file with component version strings
    usr_bin_dir = os.path.join(target_dir, "usr", "bin")
    os.makedirs(usr_bin_dir, exist_ok=True)
    with open(os.path.join(usr_bin_dir, "busybox"), "w") as f:
        f.write("BusyBox v1.33.1 (2021-01-01 00:00:00 UTC) multi-call binary\n")
    
    with open(os.path.join(usr_bin_dir, "openssl"), "w") as f:
        f.write("OpenSSL 1.1.1f  31 Mar 2020\n")

    # 4. Create an SSH key
    ssh_dir = os.path.join(target_dir, "root", ".ssh")
    os.makedirs(ssh_dir, exist_ok=True)
    with open(os.path.join(ssh_dir, "id_rsa"), "w") as f:
        f.write("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA75...\n-----END RSA PRIVATE KEY-----")

    # 5. Create a mock binary with dangerous functions (v1.1 test)
    bin_dir = os.path.join(target_dir, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    with open(os.path.join(bin_dir, "vulnerable_app"), "wb") as f:
        # Simulate an ELF-like string with dangerous functions
        f.write(b"\x7fELF" + b"some random data " + b"strcpy" + b" junk " + b"system" + b" more junk")

    # 6. Create a suspicious malware-like file (v1.1 Malware Test)
    tmp_dir = os.path.join(target_dir, "tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    with open(os.path.join(tmp_dir, "bot.sh"), "w") as f:
        f.write("#!/bin/sh\nrm -rf /\n")

    print(f"Mock firmware created at: {target_dir}")



if __name__ == "__main__":
    create_mock_firmware("test_firmware_data")
