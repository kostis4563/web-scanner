import Foundation

struct SensitivePath {
    let path: String
    let title: String
    let severity: Severity
    let category: String

    let mustContain: [String]

    let mustContainRegex: String?

    let mustNotContain: [String]

    let scanForSecrets: Bool
    let exploit: String
    let remediation: String
    let reference: String?

    init(_ path: String, _ title: String, _ severity: Severity, category: String,
         mustContain: [String] = [], regex: String? = nil, mustNotContain: [String] = ["<!doctype html", "<html"],
         scanForSecrets: Bool = false, exploit: String, remediation: String, reference: String? = nil) {
        self.path = path
        self.title = title
        self.severity = severity
        self.category = category
        self.mustContain = mustContain
        self.mustContainRegex = regex
        self.mustNotContain = mustNotContain
        self.scanForSecrets = scanForSecrets
        self.exploit = exploit
        self.remediation = remediation
        self.reference = reference
    }
}

extension SensitivePath {
    static let all: [SensitivePath] = [

        SensitivePath(".env", "Exposed .env file", .critical, category: "Exposed Secret File",
            regex: "(?m)^[A-Z][A-Z0-9_]{2,}\\s*=", scanForSecrets: true,
            exploit: "The .env file typically holds database passwords, API keys, and app secrets in plaintext. An attacker downloads it directly and gains full credentials to your backend, database, and third-party services.",
            remediation: "Never place .env inside the web root. Block dotfiles at the web server (deny access to /\\.(?!well-known) ). Rotate every credential in the file immediately - assume it is compromised.",
            reference: "CWE-538: File and Directory Information Exposure"),

        SensitivePath(".env.local", "Exposed .env.local file", .critical, category: "Exposed Secret File",
            regex: "(?m)^[A-Z][A-Z0-9_]{2,}\\s*=", scanForSecrets: true,
            exploit: "Local override env files often contain real production credentials copied for debugging. Directly downloadable, they hand an attacker your secrets.",
            remediation: "Remove env files from the deploy artifact and deny dotfile access at the web server. Rotate exposed secrets.",
            reference: "CWE-538"),

        SensitivePath(".env.production", "Exposed .env.production file", .critical, category: "Exposed Secret File",
            regex: "(?m)^[A-Z][A-Z0-9_]{2,}\\s*=", scanForSecrets: true,
            exploit: "Production environment secrets exposed to anyone. Full compromise of connected services is likely.",
            remediation: "Deny dotfile access; keep secrets in a secrets manager, not files in the web root. Rotate all values.",
            reference: "CWE-538"),

        SensitivePath(".env.backup", "Exposed .env backup", .critical, category: "Exposed Secret File",
            regex: "(?m)^[A-Z][A-Z0-9_]{2,}\\s*=", scanForSecrets: true,
            exploit: "A backup copy of the env file leaks the same live secrets.",
            remediation: "Delete stray backups from the web root and rotate secrets.",
            reference: "CWE-538"),

        SensitivePath(".aws/credentials", "Exposed AWS credentials", .critical, category: "Exposed Secret File",
            mustContain: ["aws_access_key_id", "aws_secret_access_key", "[default]"], scanForSecrets: true,
            exploit: "AWS access keys grant programmatic control of your cloud account - spin up servers, read S3 buckets, exfiltrate data, or rack up huge bills.",
            remediation: "Deactivate and delete the exposed keys in IAM now. Never store credential files under the web root. Use IAM roles instead of long-lived keys.",
            reference: "CWE-522: Insufficiently Protected Credentials"),

        SensitivePath(".npmrc", "Exposed .npmrc (registry token)", .high, category: "Exposed Secret File",
            mustContain: ["_authtoken", "_auth", "registry="], scanForSecrets: true,
            exploit: "An npm auth token lets an attacker publish malicious versions of your private packages (supply-chain attack) or read private code.",
            remediation: "Revoke the token in your npm/registry account, remove the file from the web root, and rotate.",
            reference: "CWE-522"),

        SensitivePath(".htpasswd", "Exposed .htpasswd", .high, category: "Exposed Secret File",
            regex: "(?m)^[^:\\s]+:[^:\\s]+$", mustNotContain: ["<html"],
            exploit: "Contains usernames and hashed passwords for HTTP auth. Attackers crack the hashes offline to log in.",
            remediation: "Move .htpasswd outside the web root and deny access to it. Reset affected passwords.",
            reference: "CWE-538"),

        SensitivePath("id_rsa", "Exposed SSH private key", .critical, category: "Exposed Secret File",
            mustContain: ["-----BEGIN", "PRIVATE KEY"], scanForSecrets: true,
            exploit: "A leaked SSH private key lets an attacker authenticate to your servers as you.",
            remediation: "Remove the key, revoke it from all authorized_keys, and generate a new keypair.",
            reference: "CWE-522"),

        SensitivePath(".git/config", "Exposed .git repository", .high, category: "Source Code Exposure",
            mustContain: ["[core]", "repositoryformatversion", "[remote"],
            exploit: "An exposed .git directory lets an attacker reconstruct your entire source tree (git-dumper), revealing hardcoded secrets, business logic, and vulnerabilities.",
            remediation: "Deny access to /.git in the web server and deploy from a build artifact, not a working git checkout.",
            reference: "CWE-527: Exposure of Version-Control Repository"),

        SensitivePath(".git/HEAD", "Exposed .git/HEAD", .high, category: "Source Code Exposure",
            mustContain: ["ref:", "refs/heads"],
            exploit: "Confirms a downloadable .git directory - the full repository and its history can be rebuilt.",
            remediation: "Block /.git at the web server; deploy without the .git folder.",
            reference: "CWE-527"),

        SensitivePath(".svn/entries", "Exposed .svn metadata", .medium, category: "Source Code Exposure",
            mustNotContain: ["<html"],
            exploit: "Subversion metadata can reveal file paths and allow source reconstruction.",
            remediation: "Deny access to /.svn and deploy without VCS metadata.",
            reference: "CWE-527"),

        SensitivePath(".gitignore", "Exposed .gitignore", .info, category: "Information Disclosure",
            mustNotContain: ["<html"],
            exploit: "Lists file/paths the developers considered sensitive - a map of where to probe next (e.g. env files, keys, dumps).",
            remediation: "Not sensitive by itself, but its presence often means the whole repo is exposed. Deny dotfiles.",
            reference: "CWE-538"),

        SensitivePath("wp-config.php.bak", "Exposed wp-config backup", .critical, category: "Exposed Secret File",
            mustContain: ["db_password", "db_user", "define(", "auth_key"], scanForSecrets: true,
            exploit: "A backup of wp-config.php served as plaintext reveals the WordPress database credentials and secret keys - full site and DB takeover.",
            remediation: "Delete the backup, rotate DB credentials and WordPress salts, and block .bak/.old/~ files at the web server.",
            reference: "CWE-530: Exposure of Backup File"),

        SensitivePath("config.php.bak", "Exposed config backup (.bak)", .high, category: "Exposed Secret File",
            mustNotContain: ["<html"], scanForSecrets: true,
            exploit: "Editor/backup copies of config files are served as plaintext (not executed), leaking DB credentials and secrets.",
            remediation: "Remove backup files and deny access to .bak/.old/.orig/.save/~ extensions.",
            reference: "CWE-530"),

        SensitivePath("configuration.php.bak", "Exposed Joomla config backup", .high, category: "Exposed Secret File",
            mustNotContain: ["<html"], scanForSecrets: true,
            exploit: "Joomla configuration backup reveals database credentials and secret keys.",
            remediation: "Delete backups, rotate credentials, deny backup extensions.",
            reference: "CWE-530"),

        SensitivePath("web.config", "Exposed web.config", .medium, category: "Information Disclosure",
            mustContain: ["<configuration", "<system.web", "<appsettings", "connectionstring"],
            exploit: "IIS web.config can leak connection strings, app settings, and secrets if served as text.",
            remediation: "Ensure IIS returns 404 for web.config requests; move secrets to protected configuration or a secrets store.",
            reference: "CWE-538"),

        SensitivePath("docker-compose.yml", "Exposed docker-compose.yml", .high, category: "Exposed Secret File",
            mustContain: ["services:", "image:", "environment:"], scanForSecrets: true,
            exploit: "Compose files frequently embed database passwords and env secrets, and reveal internal service topology.",
            remediation: "Do not deploy compose files to the web root; keep secrets out of them (use secret stores). Rotate any exposed values.",
            reference: "CWE-538"),

        SensitivePath("Dockerfile", "Exposed Dockerfile", .low, category: "Information Disclosure",
            mustContain: ["FROM ", "RUN ", "COPY ", "ENV "], scanForSecrets: true,
            exploit: "Reveals base images, build steps, and sometimes hardcoded ENV secrets or tokens.",
            remediation: "Keep build files out of the web root; never bake secrets into images.",
            reference: "CWE-538"),

        SensitivePath("backup.sql", "Exposed SQL dump", .critical, category: "Data Exposure",
            mustContain: ["insert into", "create table", "drop table", "mysql dump"], scanForSecrets: true,
            exploit: "A database dump is your entire dataset - user records, password hashes, PII - downloadable by anyone.",
            remediation: "Delete the dump from the web root immediately and rotate any credentials/hashes it contained. Store backups off the public server.",
            reference: "CWE-530"),

        SensitivePath("database.sql", "Exposed SQL dump (database.sql)", .critical, category: "Data Exposure",
            mustContain: ["insert into", "create table", "drop table"], scanForSecrets: true,
            exploit: "Full database contents exposed for download.",
            remediation: "Remove the dump and rotate exposed secrets; keep backups off the public web root.",
            reference: "CWE-530"),

        SensitivePath("dump.sql", "Exposed SQL dump (dump.sql)", .critical, category: "Data Exposure",
            mustContain: ["insert into", "create table", "drop table"], scanForSecrets: true,
            exploit: "Full database contents exposed for download.",
            remediation: "Remove the dump and rotate exposed secrets.",
            reference: "CWE-530"),

        SensitivePath("backup.zip", "Exposed backup archive (.zip)", .high, category: "Data Exposure",
            exploit: "A full-site or database backup archive downloadable by anyone - often contains source, configs, and dumps.",
            remediation: "Remove archives from the web root; store backups in private storage with access control.",
            reference: "CWE-530"),

        SensitivePath("backup.tar.gz", "Exposed backup archive (.tar.gz)", .high, category: "Data Exposure",
            exploit: "A full-site or database backup archive downloadable by anyone.",
            remediation: "Remove archives from the web root; store backups privately.",
            reference: "CWE-530"),

        SensitivePath("phpinfo.php", "Exposed phpinfo()", .medium, category: "Information Disclosure",
            mustContain: ["phpinfo()", "php version", "php credits"],
            exploit: "phpinfo reveals server paths, loaded modules, environment variables (sometimes secrets), and versions - a reconnaissance goldmine.",
            remediation: "Delete phpinfo/info test scripts from production.",
            reference: "CWE-200: Exposure of Sensitive Information"),

        SensitivePath("info.php", "Exposed phpinfo() (info.php)", .medium, category: "Information Disclosure",
            mustContain: ["phpinfo()", "php version"],
            exploit: "Reveals server configuration and environment for reconnaissance.",
            remediation: "Delete the file from production.",
            reference: "CWE-200"),

        SensitivePath("actuator/env", "Spring Boot Actuator /env exposed", .critical, category: "Information Disclosure",
            mustContain: ["\"activeprofiles\"", "systemproperties", "propertysources", "\"systemenvironment\""], scanForSecrets: true,
            exploit: "An unauthenticated Actuator /env endpoint dumps environment variables and configuration, frequently including passwords and API keys. Combined with /actuator/heapdump it can be catastrophic.",
            remediation: "Secure Actuator endpoints with authentication and expose only /health. Set management.endpoints.web.exposure.include appropriately.",
            reference: "CWE-200"),

        SensitivePath("actuator/health", "Spring Boot Actuator exposed", .low, category: "Information Disclosure",
            mustContain: ["\"status\":\"up\"", "\"status\": \"up\"", "\"status\":\"down\""],
            exploit: "Confirms Spring Boot Actuator is reachable; probe for /env, /heapdump, /mappings which leak far more.",
            remediation: "Restrict Actuator exposure and require authentication for all but essential health checks.",
            reference: "CWE-200"),

        SensitivePath("server-status", "Apache server-status exposed", .medium, category: "Information Disclosure",
            mustContain: ["apache server status", "server uptime", "requests currently being processed"],
            exploit: "mod_status reveals active requests, client IPs, and URLs being served - leaks traffic and can aid attacks.",
            remediation: "Restrict <Location /server-status> to localhost/trusted IPs only.",
            reference: "CWE-200"),

        SensitivePath("wp-json/wp/v2/users", "WordPress user enumeration", .medium, category: "Information Disclosure",
            mustContain: ["\"slug\"", "\"name\"", "\"id\""],
            exploit: "The REST API lists valid usernames/slugs, giving attackers exact login names to brute-force or phish.",
            remediation: "Disable or restrict the users endpoint (security plugin or filter rest_endpoints), and enforce strong passwords + rate limiting on wp-login.",
            reference: "CWE-200"),

        SensitivePath("xmlrpc.php", "WordPress XML-RPC enabled", .low, category: "Attack Surface",
            mustContain: ["xml-rpc server accepts post requests only", "xmlrpc"],
            exploit: "xmlrpc.php enables amplified brute-force (system.multicall) and can be abused for pingback DDoS.",
            remediation: "Disable XML-RPC if unused, or block xmlrpc.php at the web server / with a security plugin.",
            reference: "CWE-799"),

        SensitivePath(".vscode/settings.json", "Exposed .vscode settings", .low, category: "Information Disclosure",
            mustContain: ["{", "\""], scanForSecrets: true,
            exploit: "Editor settings can leak internal paths and occasionally tokens or connection strings.",
            remediation: "Deny access to dotfolders and keep IDE metadata out of deploys.",
            reference: "CWE-538"),

        SensitivePath(".idea/workspace.xml", "Exposed JetBrains .idea", .low, category: "Information Disclosure",
            mustContain: ["<project", "<component"],
            exploit: "IDE project metadata reveals structure, file paths, and sometimes run configs with secrets.",
            remediation: "Deny access to /.idea and exclude it from deploys.",
            reference: "CWE-538"),

        SensitivePath(".DS_Store", "Exposed .DS_Store", .low, category: "Information Disclosure",
            mustContain: ["Bud1", "bud1"], mustNotContain: ["<html"],
            exploit: ".DS_Store leaks the list of filenames in the directory, helping attackers discover hidden files and endpoints.",
            remediation: "Deny access to .DS_Store and avoid uploading macOS metadata to servers.",
            reference: "CWE-538"),

        SensitivePath("composer.lock", "Exposed composer.lock", .info, category: "Information Disclosure",
            mustContain: ["\"packages\"", "\"content-hash\""],
            exploit: "Pins exact dependency versions, letting attackers look up known CVEs for your stack.",
            remediation: "Optional: block dependency manifests from the web root. Keep dependencies patched.",
            reference: "CWE-200"),

        SensitivePath(".well-known/security.txt", "security.txt present", .info, category: "Information Disclosure",
            mustContain: ["contact:", "contact :"],
            exploit: "Not a vulnerability - this is good practice. Noted for completeness.",
            remediation: "No action needed. Keep it up to date.",
            reference: "RFC 9116"),

        SensitivePath(".env.dev", "Exposed .env.dev", .critical, category: "Exposed Secret File",
            regex: "(?m)^[A-Z][A-Z0-9_]{2,}\\s*=", scanForSecrets: true,
            exploit: "Development env file with real credentials, downloadable directly.",
            remediation: "Deny dotfile access at the web server and rotate any exposed secrets.",
            reference: "CWE-538"),

        SensitivePath(".env.save", "Exposed .env.save", .critical, category: "Exposed Secret File",
            regex: "(?m)^[A-Z][A-Z0-9_]{2,}\\s*=", scanForSecrets: true,
            exploit: "Editor save of the env file leaks live secrets as plaintext.",
            remediation: "Remove the file and rotate secrets; block backup extensions.",
            reference: "CWE-530"),

        SensitivePath("app/etc/env.php", "Exposed Magento env.php", .critical, category: "Exposed Secret File",
            mustContain: ["'key' =>", "crypt", "db", "password"], scanForSecrets: true,
            exploit: "Magento's env.php holds the DB credentials and crypt key - full store/database compromise.",
            remediation: "Ensure app/etc is not web-accessible and rotate the credentials/crypt key.",
            reference: "CWE-538"),

        SensitivePath("config/database.yml", "Exposed Rails database.yml", .critical, category: "Exposed Secret File",
            mustContain: ["adapter:", "password:", "database:"], scanForSecrets: true,
            exploit: "Rails database configuration with credentials, served as plaintext.",
            remediation: "Keep config/ out of the public root and rotate DB credentials.",
            reference: "CWE-538"),

        SensitivePath("config/secrets.yml", "Exposed Rails secrets.yml", .critical, category: "Exposed Secret File",
            mustContain: ["secret_key_base", "secret"], scanForSecrets: true,
            exploit: "Rails secret_key_base can be used to forge session cookies and achieve RCE via deserialization.",
            remediation: "Remove from the web root and rotate secret_key_base immediately.",
            reference: "CWE-798"),

        SensitivePath(".env.example", "Exposed .env.example", .info, category: "Information Disclosure",
            mustNotContain: ["<html"],
            exploit: "Template env file - reveals which secret variables the app expects, guiding attackers.",
            remediation: "Harmless if it holds no real values, but its presence implies real env files may also be reachable.",
            reference: "CWE-200"),

        SensitivePath(".gitlab-ci.yml", "Exposed GitLab CI config", .medium, category: "Information Disclosure",
            mustContain: ["stages:", "script:", "image:"], scanForSecrets: true,
            exploit: "CI config can expose deploy scripts, internal hosts, and hardcoded tokens.",
            remediation: "Keep CI files out of the web root; store CI secrets in the CI variable store.",
            reference: "CWE-538"),

        SensitivePath(".github/workflows/deploy.yml", "Exposed GitHub Actions workflow", .low, category: "Information Disclosure",
            mustContain: ["jobs:", "runs-on:", "uses:"], scanForSecrets: true,
            exploit: "Workflow files reveal build/deploy pipeline and sometimes embedded secrets.",
            remediation: "Do not deploy .github/ to the web root; use encrypted Actions secrets.",
            reference: "CWE-538"),

        SensitivePath(".circleci/config.yml", "Exposed CircleCI config", .low, category: "Information Disclosure",
            mustContain: ["version:", "jobs:", "workflows:"], scanForSecrets: true,
            exploit: "Reveals CI pipeline configuration and possibly secrets.",
            remediation: "Keep CI config out of the web root.",
            reference: "CWE-538"),

        SensitivePath("Jenkinsfile", "Exposed Jenkinsfile", .low, category: "Information Disclosure",
            mustContain: ["pipeline", "stage(", "sh '", "node {"], scanForSecrets: true,
            exploit: "Pipeline definition can leak credentials and internal infrastructure details.",
            remediation: "Keep the Jenkinsfile out of the public web root.",
            reference: "CWE-538"),

        SensitivePath(".travis.yml", "Exposed Travis CI config", .low, category: "Information Disclosure",
            mustContain: ["language:", "script:", "install:"], scanForSecrets: true,
            exploit: "Reveals CI configuration and potentially secrets.",
            remediation: "Keep CI files out of the web root.",
            reference: "CWE-538"),

        SensitivePath(".dockercfg", "Exposed Docker registry auth", .high, category: "Exposed Secret File",
            mustContain: ["auth", "\"https://", "registry"], scanForSecrets: true,
            exploit: "Docker registry credentials let an attacker pull/push private images.",
            remediation: "Remove from the web root and rotate registry credentials.",
            reference: "CWE-522"),

        SensitivePath(".kube/config", "Exposed Kubernetes kubeconfig", .critical, category: "Exposed Secret File",
            mustContain: ["apiversion", "clusters:", "client-certificate", "token:"], scanForSecrets: true,
            exploit: "A kubeconfig grants control of your Kubernetes cluster - full workload compromise.",
            remediation: "Remove immediately, rotate the cluster credentials, and restrict API access.",
            reference: "CWE-522"),

        SensitivePath("terraform.tfstate", "Exposed Terraform state", .critical, category: "Exposed Secret File",
            mustContain: ["\"terraform_version\"", "\"resources\"", "\"outputs\""], scanForSecrets: true,
            exploit: "Terraform state often stores secrets (DB passwords, keys) in plaintext and maps your whole infrastructure.",
            remediation: "Never serve tfstate from the web; use a remote encrypted backend. Rotate exposed secrets.",
            reference: "CWE-538"),

        SensitivePath("swagger.json", "Exposed Swagger/OpenAPI (swagger.json)", .low, category: "API Surface",
            mustContain: ["\"swagger\"", "\"openapi\"", "\"paths\""],
            exploit: "The full API specification is exposed - every endpoint, parameter, and schema, giving attackers a complete map to probe.",
            remediation: "Restrict API docs to authenticated internal users or disable in production.",
            reference: "CWE-200"),

        SensitivePath("openapi.json", "Exposed OpenAPI (openapi.json)", .low, category: "API Surface",
            mustContain: ["\"openapi\"", "\"paths\"", "\"components\""],
            exploit: "Full API specification exposed, mapping all endpoints for attackers.",
            remediation: "Restrict or disable public API docs in production.",
            reference: "CWE-200"),

        SensitivePath("api/swagger.json", "Exposed Swagger (api/swagger.json)", .low, category: "API Surface",
            mustContain: ["\"swagger\"", "\"openapi\"", "\"paths\""],
            exploit: "Full API specification exposed.",
            remediation: "Restrict or disable public API docs in production.",
            reference: "CWE-200"),

        SensitivePath("v2/api-docs", "Exposed Springfox API docs", .low, category: "API Surface",
            mustContain: ["\"swagger\"", "\"paths\"", "\"basepath\""],
            exploit: "Spring API documentation exposed, mapping all endpoints.",
            remediation: "Disable springfox/swagger UI in production.",
            reference: "CWE-200"),

        SensitivePath("graphql", "GraphQL endpoint present", .info, category: "API Surface",
            mustContain: ["\"data\"", "\"errors\"", "graphql", "must provide query"],
            exploit: "A reachable GraphQL endpoint - if introspection is enabled it reveals the full schema (tested separately).",
            remediation: "Disable introspection in production and enforce authentication/rate limits.",
            reference: "CWE-200"),

        SensitivePath("adminer.php", "Adminer database tool exposed", .high, category: "Attack Surface",
            mustContain: ["adminer", "login", "password"],
            exploit: "Adminer is a full web database client. If reachable (and weakly protected) it can grant direct DB access.",
            remediation: "Remove Adminer from production or lock it behind authentication/IP allow-listing.",
            reference: "CWE-284"),

        SensitivePath("phpmyadmin/", "phpMyAdmin exposed", .medium, category: "Attack Surface",
            mustContain: ["phpmyadmin", "pma_", "log in"],
            exploit: "A reachable phpMyAdmin login is a prime brute-force / exploit target for database takeover.",
            remediation: "Restrict phpMyAdmin to trusted IPs, require strong auth, and keep it patched.",
            reference: "CWE-284"),

        SensitivePath(".git/index", "Exposed .git/index", .high, category: "Source Code Exposure",
            mustContain: ["dircache", "DIRC"], mustNotContain: ["<html"],
            exploit: "The git index lists every tracked file; combined with the objects, the full source can be reconstructed.",
            remediation: "Block /.git at the web server and deploy without VCS metadata.",
            reference: "CWE-527"),

        SensitivePath(".netrc", "Exposed .netrc", .high, category: "Exposed Secret File",
            mustContain: ["machine", "login", "password"], scanForSecrets: true,
            exploit: ".netrc stores login/password pairs for remote machines in plaintext - directly usable by an attacker.",
            remediation: "Remove .netrc from the web root and rotate the credentials it contained.",
            reference: "CWE-522"),

        SensitivePath(".pgpass", "Exposed .pgpass", .high, category: "Exposed Secret File",
            regex: "(?m)^[^:\\n]*:[^:\\n]*:[^:\\n]*:[^:\\n]*:.+$", mustNotContain: ["<html"], scanForSecrets: true,
            exploit: "PostgreSQL's .pgpass holds host:port:db:user:password lines in plaintext - full database access.",
            remediation: "Remove .pgpass from anything web-reachable and rotate the database password.",
            reference: "CWE-522"),

        SensitivePath(".my.cnf", "Exposed MySQL client config", .high, category: "Exposed Secret File",
            mustContain: ["[client]", "password", "user"], scanForSecrets: true,
            exploit: ".my.cnf commonly stores the MySQL user and password in plaintext - direct database access.",
            remediation: "Remove the file from the web root and rotate the MySQL credentials.",
            reference: "CWE-522"),

        SensitivePath("secrets.yaml", "Exposed secrets.yaml", .critical, category: "Exposed Secret File",
            mustContain: ["password", "secret", "token", "key"], scanForSecrets: true,
            exploit: "A secrets manifest served as plaintext leaks passwords, API keys, and tokens for the app.",
            remediation: "Never deploy secrets manifests to the web root; use a secrets manager. Rotate every value.",
            reference: "CWE-538"),

        SensitivePath("secrets.yml", "Exposed secrets.yml", .critical, category: "Exposed Secret File",
            mustContain: ["password", "secret", "token", "key"], scanForSecrets: true,
            exploit: "A secrets manifest served as plaintext leaks passwords, API keys, and tokens.",
            remediation: "Remove from the web root and rotate every value.",
            reference: "CWE-538"),

        SensitivePath("credentials.yml", "Exposed credentials.yml", .critical, category: "Exposed Secret File",
            mustContain: ["password", "secret", "aws", "key"], scanForSecrets: true,
            exploit: "A credentials manifest exposes usernames, passwords, and cloud keys as plaintext.",
            remediation: "Remove from the web root and rotate the credentials.",
            reference: "CWE-538"),

        SensitivePath("serviceAccountKey.json", "Exposed GCP service-account key", .critical, category: "Exposed Secret File",
            mustContain: ["\"private_key\"", "\"service_account\"", "\"client_email\""], scanForSecrets: true,
            exploit: "A Google service-account JSON key can impersonate the service account - broad access to your GCP project.",
            remediation: "Disable/rotate the key in IAM and remove the file from the web root immediately.",
            reference: "CWE-798"),

        SensitivePath("firebase-service-account.json", "Exposed Firebase service-account key", .critical, category: "Exposed Secret File",
            mustContain: ["\"private_key\"", "\"service_account\"", "\"client_email\""], scanForSecrets: true,
            exploit: "A Firebase/GCP service-account key grants admin access to your Firebase project and data.",
            remediation: "Rotate the key in the Firebase/GCP console and remove it from the web root.",
            reference: "CWE-798"),

        SensitivePath(".env.vault", "Exposed .env.vault", .medium, category: "Exposed Secret File",
            mustContain: ["DOTENV_VAULT", "dotenv"], scanForSecrets: true,
            exploit: "A dotenv-vault file is exposed; while encrypted, it reveals your env structure and is worth removing.",
            remediation: "Do not serve .env.vault from the web root; keep the decryption key private.",
            reference: "CWE-538"),

        SensitivePath(".git/logs/HEAD", "Exposed .git reflog", .high, category: "Source Code Exposure",
            regex: "[0-9a-f]{40} [0-9a-f]{40} ", mustNotContain: ["<html"],
            exploit: "The git reflog lists commit hashes and author identities and confirms a downloadable .git directory - the full source history can be reconstructed with git-dumper.",
            remediation: "Block /.git at the web server and deploy from a build artifact, not a working checkout.",
            reference: "CWE-527"),

        SensitivePath(".vscode/sftp.json", "Exposed VS Code SFTP config (credentials)", .critical, category: "Exposed Secret File",
            mustContain: ["\"host\"", "\"password\"", "\"username\"", "\"privatekeypath\"", "\"remotepath\""], scanForSecrets: true,
            exploit: "The VS Code SFTP extension stores the deploy server's host, username, and password (or key path) in plaintext - directly usable to log into your server and modify the site.",
            remediation: "Delete .vscode/sftp.json from the web root, rotate the SFTP/SSH credentials it held, and exclude editor folders from deploys.",
            reference: "CWE-522"),

        SensitivePath("WEB-INF/web.xml", "Exposed Java web.xml deployment descriptor", .medium, category: "Information Disclosure",
            mustContain: ["<web-app", "<servlet", "<servlet-mapping", "<display-name"],
            exploit: "WEB-INF should never be web-served. A readable web.xml exposes servlet mappings, filters, and sometimes credentials/params - a map of the app's internals.",
            remediation: "Ensure the container denies access to /WEB-INF (it normally does); fix any reverse-proxy/static-serving rule that exposes it.",
            reference: "CWE-538"),

        SensitivePath("_ignition/health-check", "Laravel Ignition debug endpoint exposed", .high, category: "Information Disclosure",
            mustContain: ["can_execute_commands", "\"can_execute_commands\""], scanForSecrets: true,
            exploit: "The Laravel Ignition debug endpoint is reachable. With debug mode on, Ignition's execute-solution feature has led to unauthenticated remote code execution (CVE-2021-3129); at minimum it confirms a debug-enabled environment leaking internals.",
            remediation: "Set APP_DEBUG=false in production, remove/disable facade-ignition, and upgrade to a patched Laravel/Ignition version.",
            reference: "CVE-2021-3129 / CWE-489: Active Debug Code"),

        SensitivePath("telescope/requests", "Laravel Telescope exposed", .high, category: "Information Disclosure",
            mustContain: ["laravel telescope", "window.telescope", "telescope-hidden", "id=\"telescope\""], mustNotContain: [], scanForSecrets: true,
            exploit: "Laravel Telescope records requests, DB queries, jobs, mail, and cache - often including tokens, session data, and PII. Left public it hands an attacker a live feed of application internals.",
            remediation: "Restrict Telescope to local/authenticated access (TelescopeServiceProvider gate) or disable it in production.",
            reference: "CWE-200"),

        SensitivePath("elmah.axd", "ELMAH error log exposed (ASP.NET)", .medium, category: "Information Disclosure",
            mustContain: ["error log for", "powered by elmah", "elmah"], mustNotContain: [],
            exploit: "ELMAH's web log lists every unhandled exception with stack traces, request details, and sometimes cookies/credentials - reconnaissance and occasionally direct secret leakage.",
            remediation: "Restrict elmah.axd to authenticated admins or disable remote access (<security allowRemoteAccess=\"0\">).",
            reference: "CWE-200"),

        SensitivePath("wp-content/debug.log", "Exposed WordPress debug.log", .medium, category: "Information Disclosure",
            regex: "(?i)php (?:notice|warning|fatal error|deprecated)|stack trace|wp-content", mustNotContain: ["<html"], scanForSecrets: true,
            exploit: "WP_DEBUG_LOG writes errors (with file paths, plugin internals, and occasionally query data or secrets) to a world-readable file in the web root.",
            remediation: "Turn off WP_DEBUG_LOG in production, delete the log, and deny access to debug.log at the web server.",
            reference: "CWE-532: Insertion of Sensitive Information into Log File"),
    ]
}
