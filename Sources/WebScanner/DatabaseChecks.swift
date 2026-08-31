import Foundation

enum DatabaseChecks {

    struct WebPath {
        let path: String
        let title: String
        let severity: Severity
        let category: String

        let signatures: [String]

        let negatives: [String]

        let binaryIsHit: Bool
        let scanForSecrets: Bool
        let exploit: String
        let remediation: String
        let reference: String?

        init(_ path: String, _ title: String, _ severity: Severity, category: String,
             signatures: [String] = [], negatives: [String] = [],
             binaryIsHit: Bool = false, scanForSecrets: Bool = false,
             exploit: String, remediation: String, reference: String? = nil) {
            self.path = path
            self.title = title
            self.severity = severity
            self.category = category
            self.signatures = signatures.map { $0.lowercased() }
            self.negatives = negatives.map { $0.lowercased() }
            self.binaryIsHit = binaryIsHit
            self.scanForSecrets = scanForSecrets
            self.exploit = exploit
            self.remediation = remediation
            self.reference = reference
        }

        func confirmed(_ r: HTTPResponse) -> Bool {
            guard r.status == 200 || r.status == 206, r.body.count > 0 else { return false }
            let lower = r.text.lowercased()
            for n in negatives where lower.contains(n) { return false }
            if !signatures.isEmpty, signatures.contains(where: { lower.contains($0) }) { return true }
            if binaryIsHit {
                let ct = r.contentType.lowercased()
                let looksHTML = lower.contains("<html") || lower.contains("<!doctype html")
                let binaryCT = ["octet", "application/sql", "x-sql", "sqlite", "zip",
                                "gzip", "x-rdb", "download"].contains { ct.contains($0) }
                if binaryCT || !looksHTML { return true }
            }
            return false
        }
    }

    static let adminTools: [WebPath] = [
        WebPath("phpmyadmin/", "phpMyAdmin exposed", .high, category: "Database Admin Tool",
                signatures: ["phpmyadmin", "pma_", "pmahomme"],
                exploit: "A reachable phpMyAdmin login is a prime brute-force / exploit target: default or weak MySQL credentials, or an unpatched phpMyAdmin CVE, yield full database takeover.",
                remediation: "Restrict phpMyAdmin to trusted IPs / a VPN, require strong authentication, disable it in production, and keep it patched.",
                reference: "CWE-284: Improper Access Control"),
        WebPath("pma/", "phpMyAdmin exposed (/pma)", .high, category: "Database Admin Tool",
                signatures: ["phpmyadmin", "pma_", "pmahomme"],
                exploit: "phpMyAdmin reachable at an aliased path is a direct database-takeover target via weak credentials or known CVEs.",
                remediation: "Restrict to trusted IPs, require strong auth, remove from production, and patch.",
                reference: "CWE-284"),
        WebPath("adminer.php", "Adminer database tool exposed", .high, category: "Database Admin Tool",
                signatures: ["adminer", "login", "password"],
                exploit: "Adminer is a full single-file web database client (MySQL, PostgreSQL, MongoDB, …). If reachable it grants direct DB access to anyone with valid or guessable credentials, and old builds carry SSRF/file-read CVEs.",
                remediation: "Delete Adminer from production, or lock it behind authentication + IP allow-listing and keep it updated.",
                reference: "CWE-284"),
        WebPath("adminer/", "Adminer database tool exposed (/adminer)", .high, category: "Database Admin Tool",
                signatures: ["adminer", "login", "password"],
                exploit: "A reachable Adminer instance is a direct database client - weak credentials or an Adminer CVE lead to full data access.",
                remediation: "Remove Adminer from production or restrict it to trusted IPs behind auth.",
                reference: "CWE-284"),
        WebPath("phppgadmin/", "phpPgAdmin exposed", .high, category: "Database Admin Tool",
                signatures: ["phppgadmin", "postgresql", "login"],
                exploit: "phpPgAdmin is a web client for PostgreSQL. Reachable, it invites credential brute-forcing and known-CVE exploitation for database takeover.",
                remediation: "Restrict to trusted IPs, require strong auth, remove from production, and patch.",
                reference: "CWE-284"),
        WebPath("pgadmin4/", "pgAdmin 4 exposed", .high, category: "Database Admin Tool",
                signatures: ["pgadmin", "postgresql", "login"],
                exploit: "pgAdmin is a full PostgreSQL management console. Exposed, it is a brute-force target and several versions carry RCE/path-traversal CVEs.",
                remediation: "Keep pgAdmin off the public internet (VPN/allow-list), require strong auth + MFA, and patch.",
                reference: "CWE-284"),
        WebPath("mongo-express/", "Mongo Express exposed", .high, category: "Database Admin Tool",
                signatures: ["mongo express", "mongo-express", "mongodb"],
                exploit: "Mongo Express is a web admin UI for MongoDB. Default installs ship with well-known admin credentials (admin/pass) and versions have RCE CVEs - trivial full-database access.",
                remediation: "Never expose Mongo Express publicly; change default credentials, require auth, and update it.",
                reference: "CWE-1188: Insecure Default Initialization"),
        WebPath("phpredisadmin/", "phpRedisAdmin exposed", .high, category: "Database Admin Tool",
                signatures: ["phpredisadmin", "redis"],
                exploit: "phpRedisAdmin is a web UI onto a Redis server. Reachable, it exposes and lets an attacker modify all cached data and keys.",
                remediation: "Remove from production or restrict to trusted IPs behind authentication.",
                reference: "CWE-284"),
        WebPath("_plugin/head/", "Elasticsearch Head plugin exposed", .high, category: "Database Admin Tool",
                signatures: ["elasticsearch", "es-head", "cluster health"],
                exploit: "The Elasticsearch Head plugin is a browser UI onto the cluster. Reachable without auth it lets anyone read, query, and delete every index.",
                remediation: "Put Elasticsearch behind authentication (X-Pack/Search Guard) and a firewall; do not expose management plugins.",
                reference: "CWE-306: Missing Authentication for Critical Function"),
        WebPath("phpmyadmin/index.php", "phpMyAdmin login exposed", .high, category: "Database Admin Tool",
                signatures: ["phpmyadmin", "pma_", "pmahomme"],
                exploit: "A reachable phpMyAdmin login is a direct database-takeover target via weak MySQL credentials or an unpatched phpMyAdmin CVE.",
                remediation: "Restrict phpMyAdmin to trusted IPs / a VPN, require strong auth, remove from production, and patch.",
                reference: "CWE-284"),
        WebPath("phpMyAdmin/", "phpMyAdmin exposed (mixed-case path)", .high, category: "Database Admin Tool",
                signatures: ["phpmyadmin", "pma_", "pmahomme"],
                exploit: "phpMyAdmin reachable at a case-variant path is a direct database-takeover target via weak credentials or known CVEs.",
                remediation: "Restrict to trusted IPs, require strong auth, remove from production, and patch.",
                reference: "CWE-284"),
        WebPath("dbadmin/", "Database admin panel exposed (/dbadmin)", .high, category: "Database Admin Tool",
                signatures: ["adminer", "phpmyadmin", "login", "password", "database"],
                exploit: "A web database admin panel at /dbadmin grants direct DB access to anyone with valid or guessable credentials, or via a known CVE.",
                remediation: "Remove the admin panel from production or restrict it to trusted IPs behind strong auth.",
                reference: "CWE-284"),
        WebPath("phpmyadmin/setup/index.php", "phpMyAdmin setup script exposed", .high, category: "Database Admin Tool",
                signatures: ["phpmyadmin", "setup", "new server"],
                exploit: "The phpMyAdmin setup script lets an attacker add server configs and, on vulnerable versions, achieve SSRF/RCE (CVE-2009-1151-style) - a direct route to the database and host.",
                remediation: "Delete the /setup directory in production; it is only needed during installation.",
                reference: "CWE-284"),
        WebPath("sqladmin/", "SQL admin panel exposed (/sqladmin)", .high, category: "Database Admin Tool",
                signatures: ["login", "password", "database", "sql"],
                negatives: ["<!doctype html", "not found"],
                exploit: "A reachable SQL admin panel is a direct database client - weak credentials or a known CVE lead to full data access.",
                remediation: "Remove from production or restrict to trusted IPs behind authentication.",
                reference: "CWE-284"),
        WebPath("cloudbeaver/", "CloudBeaver database console exposed", .high, category: "Database Admin Tool",
                signatures: ["cloudbeaver", "dbeaver"],
                exploit: "CloudBeaver is a browser SQL console for many engines. Exposed, it is a brute-force target and grants full multi-database access on valid login.",
                remediation: "Keep CloudBeaver off the public internet (VPN/allow-list), require strong auth, and patch.",
                reference: "CWE-284"),
        WebPath("rediscommander/", "Redis Commander exposed", .high, category: "Database Admin Tool",
                signatures: ["redis commander", "redis-commander"],
                exploit: "Redis Commander is a web UI onto Redis. Reachable, it exposes and lets an attacker modify all cached keys, sessions and tokens.",
                remediation: "Remove from production or restrict to trusted IPs behind authentication.",
                reference: "CWE-284"),
    ]

    static let configFiles: [WebPath] = [
        WebPath(".env", "Exposed .env with database credentials", .critical, category: "Database Credential Exposure",
                signatures: ["db_password", "database_url", "db_connection", "db_host", "mysql_", "postgres_", "redis_url", "mongo_uri", "mongodb_uri"],
                negatives: ["<!doctype html", "<html", "<head"], scanForSecrets: true,
                exploit: "A served .env exposes the application's live database connection - host, username and password in cleartext - letting an attacker connect directly to the database and read or destroy everything.",
                remediation: "Never place .env inside the web root; block dotfiles at the server (deny /\\.env), rotate every exposed credential immediately, and load secrets from the environment or a secrets manager.",
                reference: "CWE-538: File and Directory Information Exposure"),
        WebPath(".env.local", "Exposed .env.local with database credentials", .critical, category: "Database Credential Exposure",
                signatures: ["db_password", "database_url", "db_connection", "db_host", "mysql_", "postgres_", "mongo_uri"],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "A served .env.local leaks live database credentials, letting an attacker connect straight to the database.",
                remediation: "Keep env files out of the web root, block dotfiles at the server, and rotate exposed credentials.",
                reference: "CWE-538"),
        WebPath(".env.production", "Exposed .env.production with database credentials", .critical, category: "Database Credential Exposure",
                signatures: ["db_password", "database_url", "db_connection", "db_host", "mysql_", "postgres_", "mongo_uri"],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "A served production env file leaks the live database host, user and password - direct database access.",
                remediation: "Keep env files out of the web root, block dotfiles at the server, and rotate exposed credentials.",
                reference: "CWE-538"),
        WebPath(".env.bak", "Exposed .env backup with database credentials", .critical, category: "Database Credential Exposure",
                signatures: ["db_password", "database_url", "db_connection", "db_host", "mysql_", "postgres_"],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "A backup of the env file leaks live database credentials just like the original.",
                remediation: "Delete backup env files from served directories and rotate exposed credentials.",
                reference: "CWE-538"),
        WebPath("wp-config.php.bak", "Exposed wp-config backup (database credentials)", .critical, category: "Database Credential Exposure",
                signatures: ["db_password", "db_name", "db_user", "db_host", "define("],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "A WordPress wp-config.php backup is served as text (not executed), exposing DB_USER, DB_PASSWORD and DB_HOST - the live database login - plus the WordPress auth salts.",
                remediation: "Remove wp-config.php.bak/.save/.old/~ from the web root, block those extensions, and rotate the database password and salts.",
                reference: "CWE-538"),
        WebPath("wp-config.php.save", "Exposed wp-config backup (database credentials)", .critical, category: "Database Credential Exposure",
                signatures: ["db_password", "db_name", "db_user", "define("],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "A wp-config.php.save file is served as text, exposing the WordPress database login and auth salts.",
                remediation: "Remove editor backup files from the web root and rotate the database password.",
                reference: "CWE-538"),
        WebPath("wp-config.php.old", "Exposed wp-config backup (database credentials)", .critical, category: "Database Credential Exposure",
                signatures: ["db_password", "db_name", "db_user", "define("],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "An old wp-config.php copy is served as text, exposing the WordPress database login.",
                remediation: "Remove old config copies from the web root and rotate the database password.",
                reference: "CWE-538"),
        WebPath("config.php.bak", "Exposed PHP config backup (database credentials)", .critical, category: "Database Credential Exposure",
                signatures: ["password", "dbpass", "db_pass", "mysql", "pdo", "mysqli", "database"],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "A config.php backup is served as source text, typically exposing the database host, username and password used by the application.",
                remediation: "Remove *.php.bak/.save/~ from the web root, block backup extensions, and rotate exposed credentials.",
                reference: "CWE-538"),
        WebPath("configuration.php.bak", "Exposed Joomla config backup (database credentials)", .critical, category: "Database Credential Exposure",
                signatures: ["public $password", "public $user", "public $db", "$password ="],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "A Joomla configuration.php backup is served as text, exposing the $user/$password/$db database credentials.",
                remediation: "Remove config backups from the web root and rotate the database password.",
                reference: "CWE-538"),
        WebPath("config/database.yml", "Exposed Rails database.yml (credentials)", .critical, category: "Database Credential Exposure",
                signatures: ["adapter:", "password:", "database:", "username:"],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "The Rails config/database.yml lists the adapter, host, username and password for every environment - a direct database login.",
                remediation: "Never serve config/ - it must be outside the public/ web root. Rotate any exposed credentials and use encrypted credentials / ENV vars.",
                reference: "CWE-538"),
        WebPath("database.yml", "Exposed database.yml (credentials)", .critical, category: "Database Credential Exposure",
                signatures: ["adapter:", "password:", "database:", "username:"],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "A served database.yml exposes the database adapter, host, username and password.",
                remediation: "Move config files outside the web root and rotate exposed credentials.",
                reference: "CWE-538"),
        WebPath("application.properties", "Exposed application.properties (datasource credentials)", .critical, category: "Database Credential Exposure",
                signatures: ["spring.datasource", "jdbc:", "datasource.password", "datasource.username"],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "A served Spring application.properties exposes spring.datasource.url / username / password - the live JDBC database login.",
                remediation: "Keep application.properties outside the served directory, externalize secrets, and rotate exposed credentials.",
                reference: "CWE-538"),
        WebPath("application.yml", "Exposed application.yml (datasource credentials)", .critical, category: "Database Credential Exposure",
                signatures: ["datasource:", "jdbc:", "password:", "spring:"],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "A served Spring application.yml exposes the datasource JDBC URL, username and password.",
                remediation: "Keep application.yml outside the served directory and rotate exposed credentials.",
                reference: "CWE-538"),
        WebPath("config/database.php", "Exposed Laravel database config (credentials)", .high, category: "Database Credential Exposure",
                signatures: ["'password'", "'username'", "'database'", "db_password", "mysql"],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "A served Laravel config/database.php exposes the connection array (host, database, username, password) when returned as source text.",
                remediation: "Serve only the public/ directory; keep config/ above the web root. Rotate exposed credentials.",
                reference: "CWE-538"),
        WebPath(".pgpass", "Exposed PostgreSQL password file (.pgpass)", .critical, category: "Database Credential Exposure",
                signatures: [":5432:", ":*:*:", "postgres"],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "A .pgpass file stores host:port:database:user:password lines in cleartext - a ready-to-use PostgreSQL login.",
                remediation: "Never place .pgpass in the web root; block dotfiles at the server and rotate the password.",
                reference: "CWE-538"),
        WebPath(".my.cnf", "Exposed MySQL client config (.my.cnf)", .critical, category: "Database Credential Exposure",
                signatures: ["[client]", "password", "[mysql]", "user="],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "A .my.cnf file typically stores the MySQL user and password under [client], giving an attacker a direct database login.",
                remediation: "Never place .my.cnf in the web root; block dotfiles and rotate the MySQL password.",
                reference: "CWE-538"),
        WebPath("docker-compose.yml", "Exposed docker-compose.yml (database passwords)", .high, category: "Database Credential Exposure",
                signatures: ["mysql_root_password", "postgres_password", "mongo_initdb_root_password", "mysql_password", "redis_password"],
                negatives: ["<!doctype html", "<html"], scanForSecrets: true,
                exploit: "A served docker-compose.yml commonly hard-codes MYSQL_ROOT_PASSWORD / POSTGRES_PASSWORD in its environment block, leaking the database root credentials.",
                remediation: "Keep compose files out of the web root, move secrets to a .env/secret store, and rotate exposed passwords.",
                reference: "CWE-538"),
    ]

    static let exposedFiles: [WebPath] = [
        WebPath("backup.sql", "Exposed SQL dump (backup.sql)", .critical, category: "Database File Exposure",
                signatures: ["insert into", "create table", "drop table", "mysql dump", "-- mysqldump", "postgresql database dump"],
                binaryIsHit: true, scanForSecrets: true,
                exploit: "A downloadable SQL dump is a full copy of the database - every table, user account, password hash and PII - readable offline by anyone who requests the URL.",
                remediation: "Delete database dumps from the web root, block *.sql at the server, and store backups outside any served directory.",
                reference: "CWE-538: File and Directory Information Exposure"),
        WebPath("database.sql", "Exposed SQL dump (database.sql)", .critical, category: "Database File Exposure",
                signatures: ["insert into", "create table", "drop table", "mysql dump", "-- mysqldump", "postgresql database dump"],
                binaryIsHit: true, scanForSecrets: true,
                exploit: "A downloadable SQL dump exposes the entire database offline - accounts, hashes and PII.",
                remediation: "Remove SQL dumps from served directories and block *.sql at the server.",
                reference: "CWE-538"),
        WebPath("dump.sql", "Exposed SQL dump (dump.sql)", .critical, category: "Database File Exposure",
                signatures: ["insert into", "create table", "drop table", "mysql dump", "-- mysqldump", "postgresql database dump"],
                binaryIsHit: true, scanForSecrets: true,
                exploit: "A downloadable SQL dump exposes the entire database offline - accounts, hashes and PII.",
                remediation: "Remove SQL dumps from served directories and block *.sql at the server.",
                reference: "CWE-538"),
        WebPath("db.sql", "Exposed SQL dump (db.sql)", .critical, category: "Database File Exposure",
                signatures: ["insert into", "create table", "drop table", "mysqldump"],
                binaryIsHit: true, scanForSecrets: true,
                exploit: "A downloadable SQL dump exposes the entire database offline.",
                remediation: "Remove SQL dumps from served directories and block *.sql at the server.",
                reference: "CWE-538"),
        WebPath("dump.sql.gz", "Exposed compressed SQL dump (dump.sql.gz)", .critical, category: "Database File Exposure",
                binaryIsHit: true,
                exploit: "A compressed SQL dump is a full database backup; decompressed it exposes every table, credential and PII record.",
                remediation: "Store backups outside the web root and block backup extensions (.sql, .gz, .bak) at the server.",
                reference: "CWE-538"),
        WebPath("backup.sql.gz", "Exposed compressed SQL dump (backup.sql.gz)", .critical, category: "Database File Exposure",
                binaryIsHit: true,
                exploit: "A compressed SQL dump is a full database backup exposing every table, credential and PII record.",
                remediation: "Store backups outside the web root and block backup extensions at the server.",
                reference: "CWE-538"),
        WebPath("db.sqlite3", "Exposed SQLite database (db.sqlite3)", .critical, category: "Database File Exposure",
                signatures: ["sqlite format 3"], binaryIsHit: true, scanForSecrets: true,
                exploit: "A downloadable SQLite file is your entire database - user accounts, password hashes, sessions and PII - readable offline in any SQLite browser.",
                remediation: "Move SQLite database files out of the web root (Django/Rails default to serving them by accident) and deny access to *.sqlite*/.db at the server.",
                reference: "CWE-538"),
        WebPath("database.sqlite", "Exposed SQLite database (database.sqlite)", .critical, category: "Database File Exposure",
                signatures: ["sqlite format 3"], binaryIsHit: true, scanForSecrets: true,
                exploit: "A downloadable SQLite file exposes the entire database offline - accounts, hashes and PII.",
                remediation: "Move SQLite files out of the web root and deny *.sqlite/.db at the server.",
                reference: "CWE-538"),
        WebPath("data.db", "Exposed database file (data.db)", .critical, category: "Database File Exposure",
                signatures: ["sqlite format 3"], binaryIsHit: true, scanForSecrets: true,
                exploit: "A downloadable database file exposes the entire dataset offline.",
                remediation: "Move database files out of the web root and deny *.db at the server.",
                reference: "CWE-538"),
        WebPath("dump.rdb", "Exposed Redis snapshot (dump.rdb)", .high, category: "Database File Exposure",
                signatures: ["redis"], binaryIsHit: true,
                exploit: "A Redis RDB snapshot contains every cached key/value - sessions, tokens and cached records - restorable into an attacker's own Redis for offline inspection.",
                remediation: "Keep the Redis working directory out of the web root and block dump.rdb at the server.",
                reference: "CWE-538"),
        WebPath("backup.sql.bak", "Exposed SQL dump backup (backup.sql.bak)", .critical, category: "Database File Exposure",
                signatures: ["insert into", "create table", "drop table", "mysqldump"],
                binaryIsHit: true, scanForSecrets: true,
                exploit: "A .bak SQL dump is a full database backup exposing every table, credential and PII record.",
                remediation: "Store backups outside the web root and block backup extensions (.sql, .bak, .gz) at the server.",
                reference: "CWE-538"),
        WebPath("backup.tar.gz", "Exposed archive backup (backup.tar.gz)", .high, category: "Database File Exposure",
                binaryIsHit: true,
                exploit: "A downloadable site/database archive often bundles the database dump, config files and source - a complete offline copy of the application and its data.",
                remediation: "Never store backup archives in the web root; block .tar/.gz/.zip/.bak at the server and keep backups off-host.",
                reference: "CWE-538"),
        WebPath("www.sql", "Exposed SQL dump (www.sql)", .critical, category: "Database File Exposure",
                signatures: ["insert into", "create table", "drop table", "mysqldump"],
                binaryIsHit: true, scanForSecrets: true,
                exploit: "A downloadable SQL dump exposes the entire database offline - accounts, hashes and PII.",
                remediation: "Remove SQL dumps from served directories and block *.sql at the server.",
                reference: "CWE-538"),
        WebPath("mysql.sql", "Exposed SQL dump (mysql.sql)", .critical, category: "Database File Exposure",
                signatures: ["insert into", "create table", "drop table", "mysqldump"],
                binaryIsHit: true, scanForSecrets: true,
                exploit: "A downloadable SQL dump exposes the entire database offline.",
                remediation: "Remove SQL dumps from served directories and block *.sql at the server.",
                reference: "CWE-538"),
        WebPath("users.sql", "Exposed SQL dump (users.sql)", .critical, category: "Database File Exposure",
                signatures: ["insert into", "create table", "values", "password"],
                binaryIsHit: true, scanForSecrets: true,
                exploit: "A users table dump is the highest-value target - usernames, email addresses and password hashes ready for offline cracking and credential stuffing.",
                remediation: "Remove SQL dumps from served directories and block *.sql at the server; rotate any exposed credentials.",
                reference: "CWE-538"),
        WebPath("database.sqlite3", "Exposed SQLite database (database.sqlite3)", .critical, category: "Database File Exposure",
                signatures: ["sqlite format 3"], binaryIsHit: true, scanForSecrets: true,
                exploit: "A downloadable SQLite file exposes the entire database offline - accounts, hashes and PII.",
                remediation: "Move SQLite files out of the web root and deny *.sqlite*/.db at the server.",
                reference: "CWE-538"),
        WebPath("app.db", "Exposed database file (app.db)", .critical, category: "Database File Exposure",
                signatures: ["sqlite format 3"], binaryIsHit: true, scanForSecrets: true,
                exploit: "A downloadable database file exposes the entire dataset offline.",
                remediation: "Move database files out of the web root and deny *.db at the server.",
                reference: "CWE-538"),
        WebPath("mongod.log", "Exposed MongoDB log (mongod.log)", .medium, category: "Database File Exposure",
                signatures: ["mongod", "waiting for connections", "networkinterface"],
                exploit: "A served MongoDB log leaks the server version, bind address, database and collection names and query patterns - reconnaissance that aids targeted attacks.",
                remediation: "Keep database log files out of the web root and restrict access to operators.",
                reference: "CWE-538"),
    ]

    static func finding(_ wp: WebPath, _ r: HTTPResponse, capturedContent: String? = nil) -> Finding {
        Finding(
            title: wp.title,
            severity: wp.severity,
            category: wp.category,
            location: r.finalURL.absoluteString,
            detail: "A request to /\(wp.path) returned readable content (HTTP \(r.status), \(r.body.count) bytes) that matched a database signature.",
            evidence: "URL: \(r.finalURL.absoluteString)\nHTTP \(r.status), \(r.body.count) bytes, \(r.contentType.isEmpty ? "no content-type" : r.contentType)",
            exploit: wp.exploit,
            remediation: wp.remediation,
            reference: wp.reference,
            reproduction: "curl -s \"\(r.finalURL.absoluteString)\"",
            capturedContent: capturedContent)
    }

    private static let credentialPatterns: [NSRegularExpression] = [

        try! NSRegularExpression(pattern: "(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\\+srv)?|redis|rediss|amqp|mssql|sqlserver)://[^\\s\"'<>]+", options: [.caseInsensitive]),
        try! NSRegularExpression(pattern: "jdbc:[a-z0-9]+://[^\\s\"'<>]+", options: [.caseInsensitive]),

        try! NSRegularExpression(pattern: "(?:DB_PASSWORD|DB_PASS|DATABASE_URL|DB_CONNECTION|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|REDIS_PASSWORD|spring\\.datasource\\.password)\\s*[=:]\\s*\\S+", options: [.caseInsensitive]),

        try! NSRegularExpression(pattern: "define\\(\\s*['\"]DB_(?:PASSWORD|USER|HOST|NAME)['\"]\\s*,\\s*['\"][^'\"]*['\"]", options: [.caseInsensitive]),
    ]

    static func credentialLeak(in text: String) -> String? {
        let ns = text as NSString
        let range = NSRange(location: 0, length: min(ns.length, 100_000))
        for re in credentialPatterns {
            guard let m = re.firstMatch(in: text, range: range) else { continue }
            var hit = ns.substring(with: m.range).trimmingCharacters(in: .whitespacesAndNewlines)
            if hit.count > 160 { hit = String(hit.prefix(160)) + "…" }
            return hit
        }
        return nil
    }

    static func credentialFinding(_ wp: WebPath, _ r: HTTPResponse, leak: String?,
                                  capturedContent: String? = nil) -> Finding {
        var evidence = "URL: \(r.finalURL.absoluteString)\nHTTP \(r.status), \(r.body.count) bytes, \(r.contentType.isEmpty ? "no content-type" : r.contentType)"
        if let leak { evidence += "\nLeaked credential: \(leak)" }
        return Finding(
            title: wp.title,
            severity: wp.severity,
            category: wp.category,
            location: r.finalURL.absoluteString,
            detail: "A request to /\(wp.path) returned a configuration file containing live database credentials (HTTP \(r.status), \(r.body.count) bytes). The file is served as text instead of being kept outside the web root.",
            evidence: evidence,
            exploit: wp.exploit,
            remediation: wp.remediation,
            reference: wp.reference,
            reproduction: "curl -s \"\(r.finalURL.absoluteString)\"",
            capturedContent: capturedContent)
    }

    struct HTTPService {
        let name: String
        let ports: [Int]
        let scheme: String
        let probePath: String

        let signatures: [String]
        let severity: Severity
        let exploit: String
        let remediation: String
        let reference: String

        let poc: String
    }

    static let httpServices: [HTTPService] = [
        HTTPService(name: "Elasticsearch", ports: [9200], scheme: "http",
                    probePath: "_cat/indices?v",
                    signatures: ["health", "index", "docs.count", "store.size", "\"cluster_name\""],
                    severity: .critical,
                    exploit: "Elasticsearch answers cluster/index queries with no authentication. An attacker can read, search, and delete every document, and abuse the cluster for further attacks.",
                    remediation: "Enable authentication (X-Pack security / Search Guard), bind Elasticsearch to localhost or a private interface, and firewall port 9200 from untrusted networks.",
                    reference: "CWE-306: Missing Authentication for Critical Function",
                    poc: "curl http://{host}:{port}/_cat/indices?v"),
        HTTPService(name: "CouchDB", ports: [5984], scheme: "http",
                    probePath: "_all_dbs",
                    signatures: ["_users", "_replicator", "[\"", "couchdb"],
                    severity: .critical,
                    exploit: "CouchDB lists and serves every database without authentication (\"admin party\" mode). An attacker can read and modify all documents and create admin users.",
                    remediation: "Set an admin password (leave admin party), bind CouchDB to localhost, and firewall port 5984.",
                    reference: "CWE-306",
                    poc: "curl http://{host}:{port}/_all_dbs"),
        HTTPService(name: "ClickHouse", ports: [8123], scheme: "http",
                    probePath: "?query=SHOW+DATABASES",
                    signatures: ["information_schema"],
                    severity: .critical,
                    exploit: "The ClickHouse HTTP interface executes arbitrary SQL with no credentials. An attacker can read every table and, via table functions, read local files.",
                    remediation: "Require a password for the default user, bind ClickHouse to localhost/a private network, and firewall ports 8123/9000.",
                    reference: "CWE-306",
                    poc: "curl \"http://{host}:{port}/?query=SHOW+DATABASES\""),
        HTTPService(name: "InfluxDB", ports: [8086], scheme: "http",
                    probePath: "query?q=SHOW+DATABASES",
                    signatures: ["\"results\"", "\"series\"", "databases"],
                    severity: .high,
                    exploit: "The InfluxDB HTTP API returns query results without authentication, exposing all time-series data and letting an attacker drop measurements.",
                    remediation: "Enable authentication (auth-enabled = true), bind InfluxDB to localhost, and firewall port 8086.",
                    reference: "CWE-306",
                    poc: "curl \"http://{host}:{port}/query?q=SHOW+DATABASES\""),
        HTTPService(name: "Neo4j", ports: [7474], scheme: "http",
                    probePath: "db/data/",
                    signatures: ["\"neo4j_version\"", "\"data\"", "\"management\"", "bolt"],
                    severity: .high,
                    exploit: "The Neo4j REST/HTTP endpoint responds without authentication, exposing the graph database and allowing Cypher queries against all data.",
                    remediation: "Enable auth (dbms.security.auth_enabled=true), change the default neo4j/neo4j password, bind to localhost, and firewall ports 7474/7687.",
                    reference: "CWE-306",
                    poc: "curl http://{host}:{port}/db/data/"),
        HTTPService(name: "MongoDB (HTTP)", ports: [28017], scheme: "http",
                    probePath: "",
                    signatures: ["mongodb", "db version", "replset", "buildinfo"],
                    severity: .high,
                    exploit: "The legacy MongoDB HTTP status interface is exposed, leaking server internals and database names without authentication.",
                    remediation: "Disable the HTTP interface (it is removed in modern MongoDB), enable authentication, bind mongod to localhost, and firewall its ports.",
                    reference: "CWE-306",
                    poc: "curl http://{host}:{port}/"),
    ]

    static func httpServiceFinding(_ s: HTTPService, host: String, port: Int, r: HTTPResponse) -> Finding {
        let cmd = s.poc
            .replacingOccurrences(of: "{host}", with: host)
            .replacingOccurrences(of: "{port}", with: "\(port)")
        return Finding(
            title: "Unauthenticated \(s.name) access (port \(port))",
            severity: s.severity,
            category: "Exposed Database",
            location: "\(host):\(port)",
            detail: "The \(s.name) HTTP interface on port \(port) answered a data query without any credentials. The store is readable (and likely writable) by anyone who can reach it.",
            evidence: "GET \(r.finalURL.absoluteString) → HTTP \(r.status)\nResponse: \(snippet(r.text, max: 240))",
            exploit: s.exploit,
            remediation: s.remediation,
            reference: s.reference,
            reproduction: cmd)
    }

    static func confirms(_ s: HTTPService, _ r: HTTPResponse) -> Bool {
        guard r.status == 200, r.body.count > 0 else { return false }
        let lower = r.text.lowercased()
        return s.signatures.contains { lower.contains($0.lowercased()) }
    }

    static func protocolUnauthFinding(_ r: DatabaseProbe.Result, host: String) -> Finding {
        let svc = PortCatalog.service(for: r.port)
        let cmd = svc?.command?
            .replacingOccurrences(of: "{host}", with: host)
            .replacingOccurrences(of: "{port}", with: "\(r.port)")
        var evidence = "Port \(r.port)/tcp answered a \(r.service) request with no credentials."
        if let v = r.version { evidence += "\nVersion: \(v)" }
        if !r.evidence.isEmpty { evidence += "\nServer response:\n\(snippet(r.evidence, max: 280))" }
        return Finding(
            title: "Unauthenticated \(r.service) access (port \(r.port))",
            severity: .critical,
            category: "Exposed Database",
            location: "\(host):\(r.port)",
            detail: "\(r.service) on port \(r.port) accepted a command without any authentication. The data store is readable - and on most engines writable - by anyone who can reach the port.",
            evidence: evidence,
            exploit: svc?.why ?? "An unauthenticated data store lets an attacker read, alter, or destroy all stored data, and frequently pivot to the host (e.g. Redis RCE, Mongo dump).",
            remediation: svc?.fix ?? "Require authentication, bind the service to localhost / a private network, and firewall the port from untrusted networks.",
            reference: svc?.reference ?? "CWE-306: Missing Authentication for Critical Function",
            reproduction: cmd)
    }

    static func dbmsErrorFinding(url: URL, dbms: String, sample: String) -> Finding {
        Finding(
            title: "Database error message exposed (\(dbms))",
            severity: .medium,
            category: "Database Error Disclosure",
            location: url.absoluteString,
            detail: "The response contains a raw \(dbms) error message. Leaked database errors reveal the DBMS, table/column names and query structure, and usually signal that user input reaches SQL - a strong SQL-injection indicator.",
            evidence: "URL: \(url.absoluteString)\nDBMS: \(dbms)\nExcerpt: \(snippet(sample, max: 220))",
            exploit: "Verbose SQL errors hand an attacker the database type and schema hints needed to craft injection payloads, and confirm that queries are built from user input.",
            remediation: "Return generic error pages in production, log details server-side only, and use parameterized queries so input never reaches SQL as code.",
            reference: "CWE-209: Generation of Error Message Containing Sensitive Information")
    }
}
