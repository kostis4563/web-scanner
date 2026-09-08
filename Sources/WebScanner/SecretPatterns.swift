import Foundation

struct SecretPattern {
    let name: String
    let severity: Severity
    let regex: NSRegularExpression

    let captureGroup: Int
    let fix: String

    init(_ name: String, _ severity: Severity, _ pattern: String, capture: Int = 0,
         options: NSRegularExpression.Options = [], fix: String) {
        self.name = name
        self.severity = severity
        self.regex = try! NSRegularExpression(pattern: pattern, options: options)
        self.captureGroup = capture
        self.fix = fix
    }
}

enum SecretScanner {

    static var revealSecrets = false

    static let patterns: [SecretPattern] = [

        SecretPattern("AWS Access Key ID", .critical,
            "\\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\\b",
            fix: "Deactivate the key in AWS IAM immediately and rotate. Never embed AWS keys in client-side code; use temporary role credentials."),

        SecretPattern("AWS Secret Access Key", .critical,
            "(?i)aws_secret_access_key\\s*[:=]\\s*['\\\"]?([A-Za-z0-9/+=]{40})['\\\"]?", capture: 1,
            fix: "Rotate this secret key now - it pairs with an access key ID to fully control your AWS account."),

        SecretPattern("Azure Storage Account Key", .critical,
            "(?i)AccountKey\\s*=\\s*([A-Za-z0-9+/=]{80,})", capture: 1,
            fix: "Regenerate the storage account key in Azure and update dependents; the key grants full blob/table/queue access."),

        SecretPattern("Google API Key", .high,
            "\\bAIza[0-9A-Za-z\\-_]{35}\\b",
            fix: "Restrict the key (HTTP referrer / API / IP restrictions) in Google Cloud Console, or rotate it. Unrestricted keys can be abused and billed to you."),

        SecretPattern("Google OAuth Access Token", .high,
            "\\bya29\\.[0-9A-Za-z\\-_]{20,}\\b",
            fix: "Revoke the token; it grants access to the user's Google resources until expiry."),

        SecretPattern("GCP Service Account", .critical,
            "\"type\"\\s*:\\s*\"service_account\"",
            fix: "A Google service-account JSON is exposed. Disable/rotate the key in IAM and remove it from the web root - it can impersonate the service account."),

        SecretPattern("DigitalOcean Token", .high,
            "\\bdop_v1_[a-f0-9]{64}\\b",
            fix: "Revoke the DigitalOcean personal access token; it can control your droplets and account."),

        SecretPattern("Heroku API Key", .high,
            "(?i)heroku[a-z0-9_ .\\-,]*[:=]\\s*['\\\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\\\"]", capture: 1,
            fix: "Rotate the Heroku API key; it controls your apps and add-ons."),

        SecretPattern("Cloudflare API Token", .high,
            "(?i)(?:cloudflare|cf)[a-z0-9_ .\\-]*(?:token|key)[\"'\\s:=]+([A-Za-z0-9_-]{40})", capture: 1,
            fix: "Roll the Cloudflare token; it can modify DNS and security settings."),

        SecretPattern("Stripe Live Secret Key", .critical,
            "\\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\\b",
            fix: "Roll the key in the Stripe dashboard immediately - a live secret key can move real money and read customer data."),

        SecretPattern("Stripe Test Secret Key", .low,
            "\\b(?:sk|rk)_test_[0-9a-zA-Z]{20,}\\b",
            fix: "Test keys are lower risk but should not ship to production; rotate and keep server-side."),

        SecretPattern("Square Access Token", .high,
            "\\b(?:sq0atp-[0-9A-Za-z\\-_]{22}|EAAA[0-9A-Za-z\\-_]{60})\\b",
            fix: "Revoke the Square token; it can access payment and account data."),

        SecretPattern("PayPal/Braintree Token", .high,
            "\\baccess_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}\\b",
            fix: "Revoke the Braintree production token; it can process payments."),

        SecretPattern("Shopify Token", .high,
            "\\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\\b",
            fix: "Revoke the Shopify access token; it can read/modify store data and orders."),

        SecretPattern("GitHub Token", .critical,
            "\\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\\b",
            fix: "Revoke the token in GitHub settings now; it can access/modify repositories."),

        SecretPattern("GitHub Fine-grained Token", .critical,
            "\\bgithub_pat_[0-9A-Za-z_]{22,}\\b",
            fix: "Revoke the fine-grained PAT immediately."),

        SecretPattern("GitLab Personal Access Token", .high,
            "\\bglpat-[0-9A-Za-z\\-_]{20,}\\b",
            fix: "Revoke the token in GitLab; it grants API/repo access."),

        SecretPattern("npm Access Token", .high,
            "\\bnpm_[0-9A-Za-z]{36}\\b",
            fix: "Revoke the npm token; it can publish/modify your packages (supply-chain risk)."),

        SecretPattern("PyPI Upload Token", .high,
            "\\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\\-_]{50,}\\b",
            fix: "Revoke the PyPI token; it can publish malicious releases of your packages."),

        SecretPattern("Slack Token", .high,
            "\\bxox[baprs]-[0-9A-Za-z-]{10,48}\\b",
            fix: "Revoke the token in Slack; it can read/post messages and access workspace data."),

        SecretPattern("Slack Webhook URL", .medium,
            "https://hooks\\.slack\\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+",
            fix: "Delete and regenerate the incoming webhook; anyone with the URL can post into your channel."),

        SecretPattern("Discord Bot Token", .high,

            "\\b[MNO][A-Za-z0-9_-]{22,25}\\.[A-Za-z0-9_-]{6,7}\\.[A-Za-z0-9_-]{27,40}\\b",
            fix: "Reset the Discord bot token; it grants full control of the bot."),

        SecretPattern("Discord Webhook URL", .medium,
            "https://(?:ptb\\.|canary\\.)?discord(?:app)?\\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,}",
            fix: "Delete the Discord webhook; anyone with the URL can post to the channel."),

        SecretPattern("Telegram Bot Token", .high,

            "(?<![0-9])[0-9]{8,12}:[A-Za-z0-9_-]{33,40}(?![A-Za-z0-9_-])",
            fix: "Revoke the Telegram bot token via BotFather; it grants full bot control."),

        SecretPattern("Matrix Access Token", .high,
            "\\bsyt_[A-Za-z0-9_-]{20,}_[A-Za-z0-9]{6,}\\b",
            fix: "Invalidate the Matrix/Synapse access token (log the device out); it grants full control of the bot/user account on the homeserver."),

        SecretPattern("Microsoft Teams Webhook URL", .medium,
            "https://[a-z0-9-]+\\.webhook\\.office\\.com/webhookb2/[0-9a-fA-F-]{36}@[0-9a-fA-F-]{36}/IncomingWebhook/[0-9a-fA-F]{32}/[0-9a-fA-F-]{36}",
            fix: "Delete and recreate the Teams incoming webhook connector; anyone with the URL can post messages into the channel."),

        SecretPattern("Google Chat Webhook URL", .medium,
            "https://chat\\.googleapis\\.com/v1/spaces/[A-Za-z0-9_-]+/messages\\?key=[A-Za-z0-9_-]{10,}&token=[A-Za-z0-9_-]{10,}",
            fix: "Regenerate the Google Chat webhook; the embedded key+token let anyone post into the space."),

        SecretPattern("Twilio API Key", .high,
            "\\bSK[0-9a-fA-F]{32}\\b",
            fix: "Rotate the Twilio key; it can send messages/calls billed to you."),

        SecretPattern("Twilio Account SID", .low,
            "\\bAC[0-9a-fA-F]{32}\\b",
            fix: "The Account SID pairs with an auth token; ensure the token is not also exposed."),

        SecretPattern("SendGrid API Key", .high,
            "\\bSG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43}\\b",
            fix: "Delete and recreate the SendGrid key; it can send email as your domain."),

        SecretPattern("Mailgun API Key", .high,
            "\\bkey-[0-9a-f]{32}\\b",
            fix: "Rotate the Mailgun key."),

        SecretPattern("Mailchimp API Key", .medium,
            "\\b[0-9a-f]{32}-us[0-9]{1,2}\\b",
            fix: "Revoke the Mailchimp API key; it can access your audience data."),

        SecretPattern("OpenAI API Key", .high,
            "\\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\\b",
            fix: "Revoke the OpenAI key in your account; usage is billed to you."),

        SecretPattern("Anthropic API Key", .high,
            "\\bsk-ant-[A-Za-z0-9_\\-]{20,}\\b",
            fix: "Revoke the Anthropic API key in the console; usage is billed to you."),

        SecretPattern("New Relic Key", .medium,
            "\\bNRAK-[A-Z0-9]{27}\\b",
            fix: "Rotate the New Relic API key."),

        SecretPattern("Postman API Key", .medium,
            "\\bPMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}\\b",
            fix: "Revoke the Postman API key."),

        SecretPattern("Mapbox Secret Token", .high,
            "\\bsk\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{20,}\\b",
            fix: "Rotate the Mapbox secret token (sk.*); it can manage account resources. Public pk.* tokens are lower risk."),

        SecretPattern("Algolia Admin Key", .high,
            "(?i)algolia[a-z0-9_ .\\-]*(?:admin|api)[a-z0-9_ .\\-]*key[\"'\\s:=]+([a-f0-9]{32})", capture: 1,
            fix: "Rotate the Algolia Admin API key; it can modify/delete indices. Use a search-only key in the browser."),

        SecretPattern("Private Key Block", .critical,
            "-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
            fix: "A private key is exposed. Revoke/rotate the corresponding key or certificate immediately and investigate for misuse."),

        SecretPattern("JSON Web Token (JWT)", .medium,
            "\\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b",
            fix: "If this is a signed session/access token, treat it as leaked and invalidate it. Do not embed long-lived JWTs in client code."),

        SecretPattern("Firebase Cloud Messaging Key", .high,
            "\\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}\\b",
            fix: "Rotate the FCM server key; it can send push notifications to your users."),

        SecretPattern("Database Connection String", .high,
            "(?i)\\b(?:postgres|postgresql|mysql|mongodb(?:\\+srv)?|redis|amqp|mssql)://[^:@\\s/]+:([^@\\s/'\\\"]{3,})@[^\\s/'\\\"]+", capture: 1,
            fix: "A database URI with an embedded password is exposed. Rotate the password and never ship connection strings to the client."),

        SecretPattern("Bearer Token", .medium,
            "(?i)authorization[\"'\\s:=]+bearer\\s+([A-Za-z0-9._\\-]{16,})", capture: 1,
            fix: "A bearer token is embedded in client-visible content. Treat it as leaked and rotate; keep tokens server-side."),

        SecretPattern("Basic Auth in URL", .high,
            "https?://[^/\\s:@]+:([^/\\s:@]{3,})@[A-Za-z0-9.-]+", capture: 1,
            fix: "Credentials embedded in a URL leak via logs, referrers, and history. Remove them and rotate the password."),

        SecretPattern("Generic Password Assignment", .medium,
            "(?i)(?:password|passwd|pwd|passphrase|db_?pass(?:word)?|user_?pass(?:word)?|admin_?pass(?:word)?)[\"']?\\s*[:=]\\s*['\\\"]([^'\\\"\\s]{5,})['\\\"]", capture: 1,
            fix: "Remove the hardcoded password from client-side/source files and rotate it. Load secrets server-side from a secrets manager."),

        SecretPattern("Generic API Key/Secret Assignment", .medium,
            "(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|app[_-]?secret|secret[_-]?token|refresh[_-]?token|session[_-]?token|access[_-]?key)[\"']?\\s*[:=]\\s*['\\\"]([A-Za-z0-9_\\-\\.]{12,})['\\\"]", capture: 1,
            fix: "Do not ship API keys/secrets to the browser. Move the call server-side and rotate the exposed value."),

        SecretPattern("Password field default value", .medium,
            "(?i)<input\\b(?=[^>]{0,400}\\btype\\s*=\\s*[\"']?password\\b)[^>]{0,400}?\\bvalue\\s*=\\s*[\"']([^\"']{3,})[\"']", capture: 1,
            fix: "A password input ships with a hardcoded default value in the HTML. Remove it - it is visible to anyone viewing the page source - and rotate the credential."),

        SecretPattern("Environment Secret Assignment", .high,
            "(?im)^\\s*(?:[A-Z0-9_]*(?:PASS(?:WORD)?|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CLIENT_?SECRET|DB_?PASS[A-Z_]*|AUTH))\\s*=\\s*[\"']?([^\\s\"'#]{5,})[\"']?", capture: 1,
            fix: "A secret is assigned in a KEY=VALUE line (e.g. an .env file). Remove it from anything web-reachable and rotate the value immediately."),

        SecretPattern("HashiCorp Vault Token", .high,
            "\\bhvs\\.[A-Za-z0-9_-]{20,120}\\b",
            fix: "Revoke the Vault token; it can read secrets stored in HashiCorp Vault."),

        SecretPattern("Databricks Token", .high,
            "\\bdapi[0-9a-f]{32}\\b",
            fix: "Revoke the Databricks personal access token; it can run jobs and read data."),

        SecretPattern("Notion Integration Token", .high,
            "\\b(?:secret_|ntn_)[A-Za-z0-9]{36,50}\\b",
            fix: "Revoke the Notion integration token; it can read/write your workspace content."),

        SecretPattern("Linear API Key", .high,
            "\\blin_api_[A-Za-z0-9]{40}\\b",
            fix: "Revoke the Linear API key; it can access your issues and team data."),

        SecretPattern("Slack App-Level Token", .high,
            "\\bxapp-[0-9]-[A-Za-z0-9-]{10,}\\b",
            fix: "Revoke the Slack app-level token; it grants socket-mode access to your app."),

        SecretPattern("Twitter/X Bearer Token", .medium,
            "\\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%_-]{20,}\\b",
            fix: "Regenerate the Twitter/X bearer token; it can call the API on your app's behalf."),

        SecretPattern("Sentry DSN", .low,
            "\\bhttps://[0-9a-f]{32}@[a-z0-9.\\-]+/[0-9]+\\b",
            fix: "A Sentry DSN is exposed. It lets others send events to your project; rotate it if it is a secret (backend) DSN."),

        SecretPattern("Basic Auth Header", .medium,
            "(?i)authorization[\"'\\s:=]+basic\\s+([A-Za-z0-9+/=]{16,})", capture: 1,
            fix: "A base64 Basic-auth credential is embedded in client-visible content. Decode reveals user:password - rotate it and keep credentials server-side."),

        SecretPattern("JDBC Password", .high,
            "(?i)jdbc:[a-z0-9]+:[^\\s\"';]*(?:password|pwd)=([^\\s\"';&]{3,})", capture: 1,
            fix: "A JDBC connection string embeds a database password. Rotate it and never ship connection strings to the client."),

        SecretPattern("Secret in URL query", .medium,
            "(?i)[?&](?:api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password|pwd)=([A-Za-z0-9%._\\-]{8,})", capture: 1,
            fix: "A credential is passed in a URL query string, where it leaks via logs, history, and the Referer header. Move it to a header/body and rotate."),

        SecretPattern("Google OAuth Client Secret", .high,
            "\\bGOCSPX-[A-Za-z0-9_-]{28}\\b",
            fix: "Rotate the OAuth client secret in the Google Cloud Console; it can be used to impersonate your app during the OAuth flow."),

        SecretPattern("OpenAI Service Account Key", .high,
            "\\bsk-svcacct-[A-Za-z0-9_-]{20,}\\b",
            fix: "Revoke the OpenAI service-account key; usage is billed to you and it can call the API on your org's behalf."),

        SecretPattern("Hugging Face Token", .high,
            "\\bhf_[A-Za-z0-9]{34,40}\\b",
            fix: "Revoke the Hugging Face access token; it can read/write your models, datasets, and Spaces."),

        SecretPattern("Groq API Key", .high,
            "\\bgsk_[A-Za-z0-9]{52}\\b",
            fix: "Revoke the Groq API key; usage is billed to you."),

        SecretPattern("Replicate API Token", .high,
            "\\br8_[A-Za-z0-9]{37,40}\\b",
            fix: "Revoke the Replicate token; it can run models and is billed to you."),

        SecretPattern("Stripe Webhook Secret", .high,
            "\\bwhsec_[A-Za-z0-9]{32,}\\b",
            fix: "Roll the Stripe webhook signing secret; leaking it lets attackers forge webhook events to your endpoint."),

        SecretPattern("Stripe Publishable Key", .low,
            "\\bpk_live_[0-9A-Za-z]{20,}\\b",
            fix: "A Stripe publishable key is meant to be public, but its presence confirms live Stripe use - ensure no matching secret (sk_live_) key is also exposed."),

        SecretPattern("Atlassian API Token", .high,
            "\\bATATT3[A-Za-z0-9_\\-=]{20,}\\b",
            fix: "Revoke the Atlassian/Jira/Confluence API token; it grants API access to your Atlassian data."),

        SecretPattern("Contentful Management Token", .high,
            "\\bCFPAT-[A-Za-z0-9_-]{40,}\\b",
            fix: "Revoke the Contentful management token; it can read/modify all content in your spaces."),

        SecretPattern("HubSpot Private App Token", .high,
            "\\bpat-(?:na|eu)[0-9]-[0-9a-fA-F-]{36}\\b",
            fix: "Rotate the HubSpot private-app token; it can read/write CRM data."),

        SecretPattern("Airtable Personal Access Token", .high,
            "\\bpat[A-Za-z0-9]{14}\\.[0-9a-f]{64}\\b",
            fix: "Revoke the Airtable PAT; it can read/modify your bases."),

        SecretPattern("Doppler Token", .high,
            "\\bdp\\.(?:pt|st|ct|sa|scim)\\.[A-Za-z0-9]{40,44}\\b",
            fix: "Revoke the Doppler token; it can read the project's secrets."),

        SecretPattern("PlanetScale Password", .high,
            "\\bpscale_pw_[A-Za-z0-9_\\-\\.]{32,}\\b",
            fix: "Delete the PlanetScale database password; it grants direct database access."),

        SecretPattern("PlanetScale API Token", .high,
            "\\bpscale_tkn_[A-Za-z0-9_\\-\\.]{32,}\\b",
            fix: "Revoke the PlanetScale service token; it can manage your databases."),

        SecretPattern("Supabase Personal Token", .high,
            "\\bsbp_[a-f0-9]{40}\\b",
            fix: "Revoke the Supabase personal access token; it can manage your projects and data."),

        SecretPattern("Grafana Service Account Token", .high,
            "\\bglsa_[A-Za-z0-9]{32}_[a-f0-9]{8}\\b",
            fix: "Revoke the Grafana service-account token; it can read/modify dashboards and data sources."),

        SecretPattern("Grafana Cloud Token", .medium,
            "\\bglc_[A-Za-z0-9+/=_-]{32,}\\b",
            fix: "Revoke the Grafana Cloud access policy token."),

        SecretPattern("Docker Hub Personal Access Token", .high,
            "\\bdckr_pat_[A-Za-z0-9_-]{20,}\\b",
            fix: "Revoke the Docker Hub PAT; it can pull/push your images (supply-chain risk)."),

        SecretPattern("RubyGems API Key", .high,
            "\\brubygems_[a-f0-9]{48}\\b",
            fix: "Revoke the RubyGems API key; it can publish gem versions (supply-chain risk)."),

        SecretPattern("Terraform Cloud Token", .high,
            "\\b[A-Za-z0-9]{14}\\.atlasv1\\.[A-Za-z0-9\\-_=]{60,}\\b",
            fix: "Revoke the Terraform Cloud/Enterprise token; it can read state (often full of secrets) and run applies."),

        SecretPattern("Figma Personal Access Token", .high,
            "\\bfigd_[A-Za-z0-9_-]{40,}\\b",
            fix: "Revoke the Figma personal access token; it can read your files and projects."),

        SecretPattern("SonarQube Token", .medium,
            "\\bsq[apu]_[a-f0-9]{40}\\b",
            fix: "Revoke the SonarQube/SonarCloud token; it can read your projects and analysis."),

        SecretPattern("Dropbox Access Token", .high,
            "\\bsl\\.[A-Za-z0-9_-]{130,}\\b",
            fix: "Revoke the Dropbox access token; it can read/write the linked account's files."),

        SecretPattern("Facebook Access Token", .medium,
            "\\bEAA[A-Za-z0-9]{90,}\\b",
            fix: "Revoke the Facebook/Meta access token; it can call the Graph API on the user's/app's behalf."),

        SecretPattern("Datadog API Key", .medium,
            "(?i)datadog[a-z0-9_ .\\-]*(?:api|app)[_-]?key[\"'\\s:=]+([a-f0-9]{32,40})", capture: 1,
            fix: "Rotate the Datadog API/APP key; it can submit or read monitoring data for your org."),

        SecretPattern("Okta API Token", .high,
            "(?i)okta[a-z0-9_ .\\-]*(?:api[_-]?)?token[\"'\\s:=]+([A-Za-z0-9_-]{40,})", capture: 1,
            fix: "Revoke the Okta API token; it can administer users and access in your Okta org."),

        SecretPattern("Cloudinary URL (embedded API secret)", .high,
            "cloudinary://[0-9]{12,}:([A-Za-z0-9_-]{20,})@[a-z0-9]+", capture: 1,
            fix: "Rotate the Cloudinary API secret; the URL grants upload/admin access to your media. Use unsigned/signed uploads from the client instead of shipping the secret."),

        SecretPattern("Sentry Auth Token", .medium,
            "\\bsntry[su]_[A-Za-z0-9+/=_.\\-]{40,}\\b",
            fix: "Revoke the Sentry auth token; it can read/modify your Sentry projects and issues."),

        SecretPattern("Amazon MWS Auth Token", .high,
            "\\bamzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b",
            fix: "Rotate the Amazon MWS/Marketplace token; it can access seller/marketplace data."),

        SecretPattern("age Secret Key", .high,
            "\\bAGE-SECRET-KEY-1[A-Za-z0-9]{58}\\b",
            fix: "An age encryption secret key is exposed. Re-encrypt affected data with a new key and remove this one from anything web-reachable."),

        SecretPattern("Tailscale Auth Key", .high,
            "\\btskey-(?:auth|api|client|k8s)-[A-Za-z0-9]{6,}-?[A-Za-z0-9]{10,}\\b",
            fix: "Revoke the Tailscale key in the admin console; it can join or manage nodes on your tailnet."),

        SecretPattern("Segment Write Key (in JS)", .low,
            "(?i)analytics\\.load\\s*\\(\\s*[\"']([A-Za-z0-9]{20,32})[\"']",
            capture: 1,
            fix: "Segment write keys are meant to be client-side but allow anyone to send arbitrary events into your Segment source; rotate if abused and consider server-side ingestion for sensitive data."),

        SecretPattern("Fly.io API Token", .high,
            "FlyV1[ +]fm2_[A-Za-z0-9+/=_-]{30,}",
            fix: "Revoke the Fly.io token (fly tokens revoke); it can deploy and control your apps and machines."),

        SecretPattern("Render API Key", .high,
            "\\brnd_[A-Za-z0-9]{28,}\\b",
            fix: "Revoke the Render API key in Account Settings; it can manage your services and deploys."),

        SecretPattern("Perplexity API Key", .high,
            "\\bpplx-[A-Za-z0-9]{32,}\\b",
            fix: "Revoke the Perplexity API key; usage is billed to you."),

        SecretPattern("xAI API Key", .high,
            "\\bxai-[A-Za-z0-9]{60,}\\b",
            fix: "Revoke the xAI (Grok) API key; usage is billed to you."),

        SecretPattern("OpenRouter API Key", .high,
            "\\bsk-or-v1-[0-9a-f]{64}\\b",
            fix: "Revoke the OpenRouter key; it can call any routed model and is billed to you."),

        SecretPattern("Plaid Access Token", .high,
            "\\baccess-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b",
            fix: "Rotate the Plaid access token; it can pull the linked user's bank account and transaction data."),

        SecretPattern("Brevo (Sendinblue) API Key", .high,
            "\\bx(?:keysib|smtpsib)-[a-f0-9]{64}-[A-Za-z0-9]{16}\\b",
            fix: "Revoke the Brevo API/SMTP key; it can send email as your domain and read contacts."),

        SecretPattern("Resend API Key", .high,
            "\\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,36}\\b",
            fix: "Revoke the Resend API key; it can send email as your verified domain."),

        SecretPattern("PostHog Project API Key", .low,
            "\\bphc_[A-Za-z0-9]{40,}\\b",
            fix: "A PostHog project key is client-side by design, but confirms your project; anyone can capture events into it - rotate if abused and use reverse-proxy/ingest controls."),

        SecretPattern("PostHog Personal API Key", .high,
            "\\bphx_[A-Za-z0-9]{40,}\\b",
            fix: "Revoke the PostHog personal API key; it grants admin access to your project data and settings."),

        SecretPattern("LaunchDarkly SDK/API Key", .medium,
            "\\b(?:sdk|mob|api)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b",
            fix: "Rotate the LaunchDarkly key; an api-* access token can administer flags, while sdk-*/mob-* keys should stay server-/app-side."),

        SecretPattern("Razorpay Key ID", .medium,
            "\\brzp_(?:live|test)_[A-Za-z0-9]{14,}\\b",
            fix: "This Razorpay key id confirms live payment use; ensure the paired key secret is not also exposed and rotate both if so."),

        SecretPattern("Flutterwave Secret Key", .critical,
            "\\bFLWSECK(?:_TEST)?-[A-Za-z0-9]{12,}\\b",
            fix: "Roll the Flutterwave secret key in the dashboard immediately; it can initiate and refund real payments."),

        SecretPattern("Alibaba Cloud AccessKey ID", .high,
            "\\bLTAI[A-Za-z0-9]{16,24}\\b",
            fix: "Disable/rotate the Alibaba Cloud AccessKey in RAM; paired with its secret it controls your cloud resources."),

        SecretPattern("Tencent Cloud SecretId", .high,
            "\\bAKID[A-Za-z0-9]{28,40}\\b",
            fix: "Rotate the Tencent Cloud SecretId/SecretKey pair in CAM; it controls your cloud account."),

        SecretPattern("Akamai EdgeGrid Token", .medium,
            "\\bakab-[A-Za-z0-9]{12,}-[A-Za-z0-9]{12,}\\b",
            fix: "Invalidate the Akamai EdgeGrid credential in Control Center; it can call the Akamai management APIs."),

        SecretPattern("JFrog Artifactory API Key", .high,
            "\\bAKCp[A-Za-z0-9]{50,90}\\b",
            fix: "Revoke the Artifactory API key; it can read/publish artifacts (supply-chain risk)."),

        SecretPattern("Pulumi Access Token", .high,
            "\\bpul-[a-f0-9]{40}\\b",
            fix: "Revoke the Pulumi access token; it can read stack state (often full of secrets) and run updates."),

        SecretPattern("Sourcegraph Access Token", .high,
            "\\bsgp_(?:[A-Za-z0-9]{16,}_)?[a-f0-9]{40}\\b",
            fix: "Revoke the Sourcegraph access token; it can read your code and search across repositories."),

        SecretPattern("EasyPost API Key", .high,
            "\\bEZ(?:AK|TK|PK)[A-Za-z0-9]{40,60}\\b",
            fix: "Revoke the EasyPost API key; a production key can buy shipping labels billed to you."),

        SecretPattern("Typeform Personal Access Token", .medium,
            "\\btfp_[A-Za-z0-9_-]{40,}\\b",
            fix: "Revoke the Typeform personal access token; it can read your forms and responses."),

        SecretPattern("CircleCI Personal Token", .high,
            "\\bCCIPAT_[A-Za-z0-9]{22}_[0-9a-f]{40}\\b",
            fix: "Revoke the CircleCI personal API token; it can read/modify pipelines and project settings."),

        SecretPattern("ClickUp API Token", .high,
            "\\bpk_[0-9]{6,}_[A-Z0-9]{32}\\b",
            fix: "Revoke the ClickUp personal API token; it can read/modify your tasks and workspaces."),

        SecretPattern("Adafruit IO Key", .medium,
            "\\baio_[A-Za-z0-9]{28}\\b",
            fix: "Regenerate the Adafruit IO key; it can read/write your feeds and dashboards."),

        SecretPattern("New Relic License Key", .high,
            "\\b[a-f0-9]{36}NRAL\\b",
            fix: "Rotate the New Relic license/ingest key; it can submit telemetry to your account and inflate your bill."),

        SecretPattern("Netlify Personal Access Token", .high,
            "\\bnfp_[A-Za-z0-9]{32,}\\b",
            fix: "Revoke the Netlify PAT in User Settings > Applications; it can deploy and reconfigure your sites."),

        SecretPattern("Postmark Server Token", .high,
            "(?i)postmark[a-z0-9_ .\\-]*(?:server[_-]?)?token[\"'\\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", capture: 1,
            fix: "Rotate the Postmark server token; it can send email through that server as your domain."),

        SecretPattern("Cloudflare Global API Key", .critical,
            "(?i)cloudflare[a-z0-9_ .\\-]*(?:global|api)[_-]?key[\"'\\s:=]+([0-9a-f]{37})(?![0-9a-f])", capture: 1,
            fix: "Roll the Cloudflare Global API Key immediately; it grants full account access. Prefer scoped API tokens instead."),

        SecretPattern("Fastly API Token", .high,
            "(?i)fastly[a-z0-9_ .\\-]*(?:api[_-]?)?(?:token|key)[\"'\\s:=]+([A-Za-z0-9_-]{32})(?![A-Za-z0-9_-])", capture: 1,
            fix: "Revoke the Fastly API token; it can purge cache and modify service configuration."),

        SecretPattern("Linode API Token", .high,
            "(?i)linode[a-z0-9_ .\\-]*(?:api[_-]?)?(?:token|key)[\"'\\s:=]+([a-f0-9]{64})", capture: 1,
            fix: "Revoke the Linode personal access token; it can control your Linodes and account."),

        SecretPattern("Azure Storage SAS Token", .high,
            "(?i)sv=20\\d\\d-\\d\\d-\\d\\d&[^\"'\\s]{0,300}?sig=([A-Za-z0-9%]{40,})", capture: 1,
            fix: "Revoke the Azure Storage SAS (rotate the account key or stored access policy); the signature grants time-limited blob/container access."),
    ]

    private static let denyList: Set<String> = [
        "password", "changeme", "example", "your_password", "yourpassword",
        "placeholder", "xxxxxxxx", "test", "secret", "api_key", "apikey",
        "your_api_key", "undefined", "null", "none", "true", "false",
        "process.env", "your-token-here", "insert_here", "redacted",
    ]

    private static func looksFake(_ value: String) -> Bool {
        let low = value.lowercased()
        if denyList.contains(low) { return true }
        if low.contains("example") || low.contains("xxxx") || low.contains("placeholder") { return true }
        if low.hasPrefix("your_") || low.hasPrefix("your-") || low.hasPrefix("<") { return true }

        if value.contains("${") || value.contains("{{") || low.contains("process.env") { return true }
        return false
    }

    private static let publicNameMarkers: [String] = [
        "public", "clientid", "client_id", "client-id", "applicationserverkey",
        "vapid", "measurementid", "measurement_id", "senderid", "sender_id",
        "appid", "app_id", "projectid", "project_id", "integrity",
        "sha256", "sha384", "sha512", "publickey", "publishablekey", "publishable",
    ]
    private static func looksPublicValue(name: String, value: String) -> Bool {
        let n = name.lowercased()
        if publicNameMarkers.contains(where: { n.contains($0) }) { return true }
        let v = value.lowercased()

        if v.contains("apps.googleusercontent.com") { return true }
        if v.hasPrefix("pk_live_") || v.hasPrefix("pk_test_") || v.hasPrefix("pubkey") { return true }
        return false
    }

    static func scan(_ text: String, source: String) -> [Finding] {
        var findings: [Finding] = []
        var seenValues = Set<String>()
        let ns = text as NSString
        let full = NSRange(location: 0, length: ns.length)

        for pattern in patterns {
            let matches = pattern.regex.matches(in: text, options: [], range: full)
            for m in matches.prefix(25) {
                let secretRange = (pattern.captureGroup > 0 && pattern.captureGroup < m.numberOfRanges)
                    ? m.range(at: pattern.captureGroup) : m.range
                guard secretRange.location != NSNotFound,
                      secretRange.location + secretRange.length <= ns.length else { continue }
                let secret = ns.substring(with: secretRange)

                if looksFake(secret) { continue }
                guard seenValues.insert(secret).inserted else { continue }

                findings.append(makeFinding(
                    name: pattern.name, severity: pattern.severity, fix: pattern.fix,
                    secret: secret, matchRange: m.range, ns: ns, source: source))
                if findings.count > 200 {
                    return findings + CustomDetections.scanContent(text, source: source)
                }
            }
        }

        findings += entropyScan(text, source: source, alreadySeen: seenValues)
        findings += CustomDetections.scanContent(text, source: source)
        return findings
    }

    private static let entropyRegex = try! NSRegularExpression(
        pattern: "(?i)(?:secret|token|key|passw|api|auth|credential|private|access|client|bearer|session)[A-Za-z0-9_]*[\"']?\\s*[:=]\\s*['\\\"]([A-Za-z0-9+/_\\-=\\.]{20,120})['\\\"]",
        options: [])

    private static func entropyScan(_ text: String, source: String, alreadySeen: Set<String>) -> [Finding] {
        var findings: [Finding] = []
        var seen = alreadySeen
        let ns = text as NSString
        let matches = entropyRegex.matches(in: text, options: [],
                                           range: NSRange(location: 0, length: ns.length))
        for m in matches.prefix(40) {
            guard m.numberOfRanges > 1 else { continue }
            let r = m.range(at: 1)
            guard r.location != NSNotFound, r.location + r.length <= ns.length else { continue }
            let value = ns.substring(with: r)
            if looksFake(value) { continue }

            let preStart = max(0, r.location - 64)
            let keyContext = ns.substring(with: NSRange(location: preStart, length: r.location - preStart))
            if looksPublicValue(name: keyContext, value: value) { continue }
            guard shannonEntropy(value) >= 3.8,
                  hasLetter(value), hasDigit(value) else { continue }
            guard seen.insert(value).inserted else { continue }

            findings.append(makeFinding(
                name: "High-entropy secret",
                severity: .medium,
                fix: "A high-entropy value is assigned to a secret-like name in client-visible content. Verify it - if it is a real credential, rotate it and move it server-side. (May be a non-sensitive hash; confirm manually.)",
                secret: value, matchRange: m.range, ns: ns, source: source))
            if findings.count > 60 { break }
        }
        return findings
    }

    private static func makeFinding(name: String, severity: Severity, fix: String,
                                    secret: String, matchRange: NSRange, ns: NSString,
                                    source: String) -> Finding {
        let start = max(0, matchRange.location - 24)
        let len = min(ns.length - start, matchRange.length + 48)
        let context = len > 0 ? ns.substring(with: NSRange(location: start, length: len)) : secret
        let shownValue = revealSecrets ? secret : redact(secret)
        return Finding(
            title: "Exposed secret: \(name)",
            severity: severity,
            category: "Leaked Secret",
            location: source,
            detail: "A value matching a \(name) pattern is present in content served to the browser.",
            evidence: "Value: \(shownValue)\nContext: ...\(snippet(context, max: 120))...",
            exploit: "Anyone who views the page source can copy this secret and use it directly against the associated service - no authentication bypass required.",
            remediation: fix,
            reference: "CWE-798: Use of Hard-coded Credentials")
    }

    private static func shannonEntropy(_ s: String) -> Double {
        guard !s.isEmpty else { return 0 }
        var freq: [Character: Int] = [:]
        for c in s { freq[c, default: 0] += 1 }
        let len = Double(s.count)
        var e = 0.0
        for (_, count) in freq {
            let p = Double(count) / len
            e -= p * log2(p)
        }
        return e
    }

    private static func hasLetter(_ s: String) -> Bool { s.contains { $0.isLetter } }
    private static func hasDigit(_ s: String) -> Bool { s.contains { $0.isNumber } }
}
