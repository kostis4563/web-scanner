import Foundation

enum Wordlist {

    static func parse(_ raw: String) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for rawLine in raw.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            var line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            while line.hasPrefix("/") { line.removeFirst() }
            guard !line.isEmpty else { continue }
            if seen.insert(line).inserted { out.append(line) }
        }
        return out
    }

    static func load(spec: String, http: HTTPClient) async -> [String] {
        let trimmed = spec.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return defaultPaths }

        var combined = ""
        var inlineWords: [String] = []
        for rawItem in trimmed.split(separator: ",") {
            let item = rawItem.trimmingCharacters(in: .whitespaces)
            guard !item.isEmpty else { continue }
            if item.hasPrefix("http://") || item.hasPrefix("https://") {
                if let u = URL(string: item), let r = await http.fetch(u), r.status == 200 {
                    combined += "\n" + r.text
                }
            } else {
                let path = (item as NSString).expandingTildeInPath
                if FileManager.default.fileExists(atPath: path),
                   let contents = try? String(contentsOfFile: path, encoding: .utf8) {
                    combined += "\n" + contents
                } else {
                    inlineWords.append(item)
                }
            }
        }
        var words = parse(combined)
        words.append(contentsOf: inlineWords)
        return words.isEmpty ? defaultPaths : dedupe(words)
    }

    static func loadFile(_ path: String) -> [String]? {
        let expanded = (path as NSString).expandingTildeInPath
        guard let contents = try? String(contentsOfFile: expanded, encoding: .utf8) else { return nil }
        return parse(contents)
    }

    static func parseExtensions(_ raw: String) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for rawItem in raw.split(whereSeparator: { $0 == "," || $0 == " " }) {
            var ext = rawItem.trimmingCharacters(in: .whitespaces)
            guard !ext.isEmpty else { continue }
            if !ext.hasPrefix(".") { ext = "." + ext }
            if seen.insert(ext).inserted { out.append(ext) }
        }
        return out
    }

    private static func dedupe(_ words: [String]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for w in words where seen.insert(w).inserted { out.append(w) }
        return out
    }

    static let defaultPaths: [String] = [

        "admin", "administrator", "login", "wp-admin", "wp-login.php", "dashboard",
        "panel", "cpanel", "webmail", "portal", "manage", "manager", "console",
        "backend", "cms", "api", "api/v1", "api/v2", "graphql", "rest", "app",
        "assets", "static", "public", "uploads", "upload", "files", "images", "img",
        "media", "download", "downloads", "docs", "doc", "documentation", "help",
        "test", "tests", "testing", "dev", "development", "staging", "stage",
        "demo", "beta", "old", "new", "tmp", "temp", "backup", "backups", "bak",
        "archive", "archives", "data", "db", "database", "sql", "logs", "log",
        "config", "conf", "configuration", "settings", "setup", "install",
        "includes", "inc", "lib", "libs", "vendor", "node_modules", "src", "dist",
        "build", "cache", "private", "secret", "secrets", "internal", "intranet",
        "server-status", "server-info", "phpmyadmin", "pma", "adminer", "mysql",
        "status", "health", "healthz", "metrics", "debug", "info", "version",
        "user", "users", "account", "accounts", "profile", "register", "signup",
        "signin", "logout", "auth", "oauth", "sso", "reset", "forgot",
        "search", "cart", "checkout", "order", "orders", "payment", "billing",

        ".env", ".env.local", ".env.production", ".env.backup", ".env.example",
        ".git/config", ".git/HEAD", ".gitignore", ".svn/entries", ".hg/",
        ".htaccess", ".htpasswd", "web.config", "robots.txt", "sitemap.xml",
        "crossdomain.xml", "humans.txt", "security.txt", ".well-known/security.txt",
        "config.php", "config.inc.php", "configuration.php", "wp-config.php",
        "settings.php", "database.php", "db.php", "connect.php", "conn.php",
        "config.json", "config.yml", "config.yaml", "settings.json", "app.config",
        "appsettings.json", "package.json", "package-lock.json", "composer.json",
        "composer.lock", "Gemfile", "Gemfile.lock", "requirements.txt", "yarn.lock",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore",
        "phpinfo.php", "info.php", "test.php", "shell.php", "cmd.php", "upload.php",
        "backup.zip", "backup.tar.gz", "backup.sql", "database.sql", "dump.sql",
        "www.zip", "site.zip", "public_html.zip", "backup.rar", "db.sqlite",
        "credentials.json", "secrets.json", "id_rsa", "id_rsa.pub", ".DS_Store",
        "error.log", "access.log", "debug.log", "app.log", "README.md", "CHANGELOG.md",
        "LICENSE", "swagger.json", "openapi.json", "swagger-ui.html", "api-docs",
        "actuator", "actuator/health", "actuator/env", "actuator/heapdump",
        ".vscode/settings.json", ".idea/workspace.xml", "Thumbs.db", "sitemap.txt",
    ]
}
