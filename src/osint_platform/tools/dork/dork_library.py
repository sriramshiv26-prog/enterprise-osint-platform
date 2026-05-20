"""
Google Dork Library — categorized dork templates for OSINT investigations.

Each dork has:
  - name: Human-readable name
  - description: What this dork finds
  - query: The google search query template (use {target} for variable substitution)
  - category: Category group
  - risk_level: How sensitive the exposed data is
  - severity: Severity indicator for findings
"""
from typing import Dict, List, Optional

# ─── Dork Categories ─────────────────────────────────────────────────────────

class DorkCategory:
    """Category constants for dork organization."""
    ADMIN_PANELS = "admin_panels"
    DATABASES = "databases"
    CONFIG_FILES = "config_files"
    LOG_FILES = "log_files"
    BACKUP_FILES = "backup_files"
    LOGIN_PAGES = "login_pages"
    SENSITIVE_DIRECTORIES = "sensitive_directories"
    FILE_UPLOAD = "file_upload"
    PASSWORD_FILES = "password_files"
    EXPOSED_DOCUMENTS = "exposed_documents"
    CAMERAS = "cameras"
    WEB_SERVERS = "web_servers"
    ERROR_MESSAGES = "error_messages"
    NETWORK_DEVICES = "network_devices"
    SHODAN = "shodan"
    IOT_DEVICES = "iot_devices"
    SUBDOMAINS = "subdomains"
    EMAIL = "email"
    SOCIAL_MEDIA = "social_media"
    CLOUD_STORAGE = "cloud_storage"
    CODE_REPOS = "code_repositories"
    PERSONAL_INFO = "personal_information"


CATEGORY_DESCRIPTIONS = {
    DorkCategory.ADMIN_PANELS: "Admin login panels and management interfaces",
    DorkCategory.DATABASES: "Exposed database interfaces and files",
    DorkCategory.CONFIG_FILES: "Configuration files exposing credentials and settings",
    DorkCategory.LOG_FILES: "Log files with sensitive information",
    DorkCategory.BACKUP_FILES: "Backup archives containing sensitive data",
    DorkCategory.LOGIN_PAGES: "Login pages and authentication portals",
    DorkCategory.SENSITIVE_DIRECTORIES: "Sensitive directory listings",
    DorkCategory.FILE_UPLOAD: "File upload interfaces and forms",
    DorkCategory.PASSWORD_FILES: "Files containing passwords or password hashes",
    DorkCategory.EXPOSED_DOCUMENTS: "Exposed documents (PDFs, spreadsheets, etc.)",
    DorkCategory.CAMERAS: "Publicly accessible cameras and webcams",
    DorkCategory.WEB_SERVERS: "Web server version and configuration info",
    DorkCategory.ERROR_MESSAGES: "Error messages revealing system information",
    DorkCategory.NETWORK_DEVICES: "Network device interfaces",
    DorkCategory.SHODAN: "Shodan-related dorks for IoT and device identification",
    DorkCategory.IOT_DEVICES: "IoT device interfaces and dashboards",
    DorkCategory.SUBDOMAINS: "Subdomain discovery via Google",
    DorkCategory.EMAIL: "Email address discovery",
    DorkCategory.SOCIAL_MEDIA: "Social media profile discovery",
    DorkCategory.CLOUD_STORAGE: "Exposed cloud storage buckets and files",
    DorkCategory.CODE_REPOS: "Source code repositories and code snippets",
    DorkCategory.PERSONAL_INFO: "Personally identifiable information exposure",
}


# ─── Dork Definitions ────────────────────────────────────────────────────────

DorkRecord = Dict[str, str]


def _d(name: str, desc: str, query: str, category: str, risk: str = "MEDIUM") -> DorkRecord:
    """Helper to create a dork record."""
    return {
        "name": name,
        "description": desc,
        "query": query,
        "category": category,
        "risk_level": risk,
    }


# All dorks organized by category
DORKS_BY_CATEGORY: Dict[str, List[DorkRecord]] = {

    DorkCategory.ADMIN_PANELS: [
        _d("Generic Admin", "Generic admin panel", "site:{target} inurl:admin", DorkCategory.ADMIN_PANELS, "HIGH"),
        _d("Admin Login", "Standard admin login page", "site:{target} inurl:login", DorkCategory.ADMIN_PANELS, "HIGH"),
        _d("cPanel Login", "cPanel control panel", "site:{target} inurl:cpanel", DorkCategory.ADMIN_PANELS, "HIGH"),
        _d("Webmail Login", "Webmail login portal", "site:{target} inurl:webmail", DorkCategory.ADMIN_PANELS, "MEDIUM"),
        _d("phpMyAdmin", "phpMyAdmin database admin", "site:{target} inurl:phpmyadmin", DorkCategory.ADMIN_PANELS, "CRITICAL"),
        _d("Admin Panel 2", "Various admin paths", "site:{target} intitle:admin intitle:login", DorkCategory.ADMIN_PANELS, "HIGH"),
        _d("Dashboard", "Admin dashboard interfaces", "site:{target} inurl:dashboard", DorkCategory.ADMIN_PANELS, "HIGH"),
    ],

    DorkCategory.CONFIG_FILES: [
        _d("Config PHP", "PHP configuration file", "site:{target} ext:php inurl:config", DorkCategory.CONFIG_FILES, "CRITICAL"),
        _d("Config DB", "Database configuration", "site:{target} ext:php inurl:dbconfig", DorkCategory.CONFIG_FILES, "CRITICAL"),
        _d("Config ASP", "ASP config file", "site:{target} ext:asp inurl:config", DorkCategory.CONFIG_FILES, "CRITICAL"),
        _d("htaccess", "Apache htaccess file", "site:{target} ext:htaccess", DorkCategory.CONFIG_FILES, "CRITICAL"),
        _d("htpasswd", "Apache htpasswd credential file", "site:{target} ext:htpasswd", DorkCategory.CONFIG_FILES, "CRITICAL"),
        _d("Env File", "Environment configuration", "site:{target} ext:env .env", DorkCategory.CONFIG_FILES, "CRITICAL"),
        _d("YAML Config", "YAML configuration", "site:{target} ext:yml inurl:config", DorkCategory.CONFIG_FILES, "HIGH"),
        _d("JSON Config", "JSON configuration", "site:{target} ext:json inurl:config", DorkCategory.CONFIG_FILES, "HIGH"),
        _d("XML Config", "XML configuration", "site:{target} ext:xml inurl:config", DorkCategory.CONFIG_FILES, "HIGH"),
        _d("INI Config", "INI configuration file", "site:{target} ext:ini", DorkCategory.CONFIG_FILES, "HIGH"),
        _d("Tomcat Config", "Tomcat server configuration", "site:{target} ext:xml inurl:tomcat", DorkCategory.CONFIG_FILES, "HIGH"),
    ],

    DorkCategory.DATABASES: [
        _d("SQL File", "SQL dump files", "site:{target} ext:sql", DorkCategory.DATABASES, "CRITICAL"),
        _d("SQLite DB", "SQLite database file", "site:{target} ext:db", DorkCategory.DATABASES, "CRITICAL"),
        _d("MDB File", "MS Access database", "site:{target} ext:mdb", DorkCategory.DATABASES, "CRITICAL"),
        _d("MongoDB Interface", "MongoDB admin interface", "site:{target} intitle:MongoDB intitle:admin", DorkCategory.DATABASES, "CRITICAL"),
        _d("SQL Dump", "SQL dump (insert statements)", "site:{target} \"INSERT INTO\" \"VALUES\" ext:sql", DorkCategory.DATABASES, "CRITICAL"),
        _d("PhpPgAdmin", "PostgreSQL web admin", "site:{target} inurl:phppgadmin", DorkCategory.DATABASES, "HIGH"),
        _d("Adminer", "Adminer database admin", "site:{target} inurl:adminer", DorkCategory.DATABASES, "HIGH"),
    ],

    DorkCategory.LOG_FILES: [
        _d("Error Log", "Generic error log", "site:{target} ext:log", DorkCategory.LOG_FILES, "HIGH"),
        _d("Access Log", "Web server access log", "site:{target} ext:log inurl:access", DorkCategory.LOG_FILES, "HIGH"),
        _d("Apache Log", "Apache error/access log", "site:{target} intitle:index.of access.log", DorkCategory.LOG_FILES, "HIGH"),
        _d("Debug Log", "Debug log file", "site:{target} ext:log inurl:debug", DorkCategory.LOG_FILES, "HIGH"),
        _d("Syslog", "System log", "site:{target} ext:log inurl:syslog", DorkCategory.LOG_FILES, "HIGH"),
    ],

    DorkCategory.BACKUP_FILES: [
        _d("Tar Backup", "Tar archive backup", "site:{target} ext:tar inurl:backup", DorkCategory.BACKUP_FILES, "HIGH"),
        _d("Zip Backup", "Zip archive backup", "site:{target} ext:zip inurl:backup", DorkCategory.BACKUP_FILES, "HIGH"),
        _d("SQL Backup", "SQL backup file", "site:{target} ext:sql inurl:backup", DorkCategory.BACKUP_FILES, "CRITICAL"),
        _d("Bak File", "Bak backup file", "site:{target} ext:bak", DorkCategory.BACKUP_FILES, "HIGH"),
        _d("Old File", "Old file (copy/old suffix)", "site:{target} ext:old", DorkCategory.BACKUP_FILES, "MEDIUM"),
        _d("Rar Backup", "RAR archive backup", "site:{target} ext:rar inurl:backup", DorkCategory.BACKUP_FILES, "HIGH"),
        _d("Gzip Backup", "GZip archive", "site:{target} ext:gz inurl:backup", DorkCategory.BACKUP_FILES, "HIGH"),
    ],

    DorkCategory.LOGIN_PAGES: [
        _d("Standard Login", "Generic login page", "site:{target} intitle:login", DorkCategory.LOGIN_PAGES, "MEDIUM"),
        _d("Sign In", "Sign in page", "site:{target} intitle:\"sign in\"", DorkCategory.LOGIN_PAGES, "MEDIUM"),
        _d("User Login", "User panel login", "site:{target} inurl:user inurl:login", DorkCategory.LOGIN_PAGES, "MEDIUM"),
        _d("Portal Login", "Portal login page", "site:{target} intitle:portal intitle:login", DorkCategory.LOGIN_PAGES, "HIGH"),
        _d("WordPress Login", "WordPress admin login", "site:{target} inurl:wp-admin inurl:login", DorkCategory.LOGIN_PAGES, "HIGH"),
        _d("Member Login", "Member area login", "site:{target} intitle:\"member login\"", DorkCategory.LOGIN_PAGES, "MEDIUM"),
    ],

    DorkCategory.PASSWORD_FILES: [
        _d("Passwd File", "Unix passwd file", "site:{target} ext:passwd", DorkCategory.PASSWORD_FILES, "CRITICAL"),
        _d("Shadow File", "Unix shadow password file", "site:{target} ext:shadow", DorkCategory.PASSWORD_FILES, "CRITICAL"),
        _d("Password TXT", "Password text file", "site:{target} ext:txt inurl:password", DorkCategory.PASSWORD_FILES, "CRITICAL"),
        _d("Password PHP", "PHP file with passwords", "site:{target} ext:php inurl:passwd", DorkCategory.PASSWORD_FILES, "CRITICAL"),
        _d("Dump Credentials", "Credential dump", "site:{target} \"password\" \"username\" ext:txt", DorkCategory.PASSWORD_FILES, "CRITICAL"),
        _d("Key File", "SSH/SSL key file", "site:{target} ext:key \"PRIVATE KEY\"", DorkCategory.PASSWORD_FILES, "CRITICAL"),
        _d("PEM Key", "PEM private key", "site:{target} ext:pem \"PRIVATE\"", DorkCategory.PASSWORD_FILES, "CRITICAL"),
    ],

    DorkCategory.SENSITIVE_DIRECTORIES: [
        _d("Index Of", "Directory listing (generic)", "site:{target} intitle:index.of", DorkCategory.SENSITIVE_DIRECTORIES, "MEDIUM"),
        _d("Server Status", "Server status page", "site:{target} intitle:\"server status\"", DorkCategory.SENSITIVE_DIRECTORIES, "MEDIUM"),
        _d("Apache Status", "Apache server status", "site:{target} inurl:server-status", DorkCategory.SENSITIVE_DIRECTORIES, "MEDIUM"),
        _d("Test Directory", "Test/development directory", "site:{target} inurl:test", DorkCategory.SENSITIVE_DIRECTORIES, "MEDIUM"),
        _d("Temp Directory", "Temporary files directory", "site:{target} inurl:temp", DorkCategory.SENSITIVE_DIRECTORIES, "MEDIUM"),
        _d("Private Directory", "Private/restricted directory", "site:{target} inurl:private", DorkCategory.SENSITIVE_DIRECTORIES, "HIGH"),
    ],

    DorkCategory.FILE_UPLOAD: [
        _d("Upload Script", "File upload script", "site:{target} inurl:upload", DorkCategory.FILE_UPLOAD, "HIGH"),
        _d("Upload PHP", "PHP upload script", "site:{target} inurl:upload.php", DorkCategory.FILE_UPLOAD, "HIGH"),
        _d("File Upload Form", "Upload form page", "site:{target} intitle:upload filetype:php", DorkCategory.FILE_UPLOAD, "HIGH"),
    ],

    DorkCategory.EXPOSED_DOCUMENTS: [
        _d("PDF Documents", "Exposed PDF files", "site:{target} ext:pdf", DorkCategory.EXPOSED_DOCUMENTS, "LOW"),
        _d("Excel Spreadsheets", "Exposed XLS/XLSX files", "site:{target} ext:xls OR ext:xlsx", DorkCategory.EXPOSED_DOCUMENTS, "MEDIUM"),
        _d("Word Documents", "Exposed DOC/DOCX files", "site:{target} ext:doc OR ext:docx", DorkCategory.EXPOSED_DOCUMENTS, "MEDIUM"),
        _d("CSV Data", "Exposed CSV files", "site:{target} ext:csv", DorkCategory.EXPOSED_DOCUMENTS, "MEDIUM"),
        _d("TXT Documents", "Exposed text files", "site:{target} ext:txt", DorkCategory.EXPOSED_DOCUMENTS, "LOW"),
        _d("PPT Presentations", "Exposed slides", "site:{target} ext:ppt OR ext:pptx", DorkCategory.EXPOSED_DOCUMENTS, "MEDIUM"),
        _d("RTF Documents", "Rich text format documents", "site:{target} ext:rtf", DorkCategory.EXPOSED_DOCUMENTS, "MEDIUM"),
    ],

    DorkCategory.CAMERAS: [
        _d("WebcamXP", "WebcamXP streaming interface", "intitle:\"webcamXP\" inurl:8080", DorkCategory.CAMERAS, "LOW"),
        _d("Axis Cam", "Axis network camera", "intitle:\"Live View\" \"Axis\"", DorkCategory.CAMERAS, "LOW"),
        _d("IP Camera", "Generic IP camera viewer", "intitle:\"IP Camera\" intitle:\"viewer\"", DorkCategory.CAMERAS, "LOW"),
        _d("Webcam Viewer", "Generic webcam", "intitle:\"webcam\" \"viewer\"", DorkCategory.CAMERAS, "LOW"),
    ],

    DorkCategory.WEB_SERVERS: [
        _d("Apache Default", "Default Apache server page", 'intitle:"Apache2 Ubuntu Default Page"', DorkCategory.WEB_SERVERS, "LOW"),
        _d("Nginx Default", "Default Nginx server page", 'intitle:"Welcome to nginx"', DorkCategory.WEB_SERVERS, "LOW"),
        _d("IIS Default", "Default IIS server page", 'intitle:"IIS Windows" "Welcome"', DorkCategory.WEB_SERVERS, "LOW"),
        _d("Tomcat Default", "Default Tomcat server page", 'intitle:"Apache Tomcat" "Welcome"', DorkCategory.WEB_SERVERS, "LOW"),
    ],

    DorkCategory.ERROR_MESSAGES: [
        _d("PHP Error", "PHP error messages", "site:{target} \"PHP Fatal error\"", DorkCategory.ERROR_MESSAGES, "MEDIUM"),
        _d("MySQL Error", "MySQL error messages", "site:{target} \"MySQL\" \"Error\"", DorkCategory.ERROR_MESSAGES, "MEDIUM"),
        _d("Warning Messages", "PHP warning messages", "site:{target} \"PHP Warning\"", DorkCategory.ERROR_MESSAGES, "MEDIUM"),
        _d("Stack Trace", "Stack trace debugging info", "site:{target} \"Stack trace\"", DorkCategory.ERROR_MESSAGES, "MEDIUM"),
        _d("Debug Info", "Debug information display", "site:{target} \"Debug\" \"Line\" \"File\" ext:php", DorkCategory.ERROR_MESSAGES, "MEDIUM"),
    ],

    DorkCategory.SUBDOMAINS: [
        _d("Site Subdomain", "All indexed sub-pages", "site:*.{target}", DorkCategory.SUBDOMAINS, "LOW"),
        _d("Subdomain List", "Different subdomains", "site:*.{target} -www", DorkCategory.SUBDOMAINS, "LOW"),
        _d("CNAME Records", "CNAME references", "site:{target} intitle:CNAME", DorkCategory.SUBDOMAINS, "MEDIUM"),
    ],

    DorkCategory.EMAIL: [
        _d("Email List", "Email addresses on site", "site:{target} \"@\" \"email\"", DorkCategory.EMAIL, "MEDIUM"),
        _d("Mailto Links", "Mailto link emails", "site:{target} inurl:mailto:", DorkCategory.EMAIL, "MEDIUM"),
        _d("Contact Emails", "Contact page emails", "site:{target} intitle:contact email", DorkCategory.EMAIL, "MEDIUM"),
        _d("Email TXT", "Email list text file", "site:{target} ext:txt \"@\" inurl:email", DorkCategory.EMAIL, "HIGH"),
    ],

    DorkCategory.SOCIAL_MEDIA: [
        _d("LinkedIn Profiles", "LinkedIn company profiles", "site:linkedin.com inurl:{target}", DorkCategory.SOCIAL_MEDIA, "LOW"),
        _d("Twitter Mentions", "Twitter mentions of target", "site:twitter.com {target}", DorkCategory.SOCIAL_MEDIA, "LOW"),
        _d("Facebook Presence", "Facebook pages mentioning target", "site:facebook.com inurl:{target}", DorkCategory.SOCIAL_MEDIA, "LOW"),
        _d("Reddit Mentions", "Reddit mentions", "site:reddit.com {target}", DorkCategory.SOCIAL_MEDIA, "LOW"),
    ],

    DorkCategory.CLOUD_STORAGE: [
        _d("AWS S3 Bucket", "Amazon S3 bucket files", "site:s3.amazonaws.com {target}", DorkCategory.CLOUD_STORAGE, "HIGH"),
        _d("Google Cloud Storage", "GCP bucket files", "site:storage.googleapis.com {target}", DorkCategory.CLOUD_STORAGE, "HIGH"),
        _d("Azure Blob", "Azure blob storage", "site:blob.core.windows.net {target}", DorkCategory.CLOUD_STORAGE, "HIGH"),
        _d("Dropbox Share", "Dropbox shared links", "site:dropbox.com {target}", DorkCategory.CLOUD_STORAGE, "MEDIUM"),
        _d("S3 Bucket Listing", "AWS S3 bucket listing", "site:s3.amazonaws.com inurl:{target} intitle:index.of", DorkCategory.CLOUD_STORAGE, "HIGH"),
    ],

    DorkCategory.CODE_REPOS: [
        _d("GitHub Repos", "GitHub repositories", "site:github.com {target}", DorkCategory.CODE_REPOS, "MEDIUM"),
        _d("GitLab Repos", "GitLab repositories", "site:gitlab.com {target}", DorkCategory.CODE_REPOS, "MEDIUM"),
        _d("Bitbucket Repos", "Bitbucket repositories", "site:bitbucket.org {target}", DorkCategory.CODE_REPOS, "MEDIUM"),
        _d("Git Config", "Exposed git configuration", "site:{target} intitle:index.of .git", DorkCategory.CODE_REPOS, "CRITICAL"),
        _d("Gitignore", "Exposed gitignore files", "site:{target} ext:gitignore", DorkCategory.CODE_REPOS, "MEDIUM"),
    ],

    DorkCategory.PERSONAL_INFO: [
        _d("SSN Exposure", "Social security numbers", "site:{target} \"SSN\" \"###-##-####\" ext:txt OR ext:csv", DorkCategory.PERSONAL_INFO, "CRITICAL"),
        _d("DOB Exposure", "Dates of birth with names", "site:{target} \"date of birth\" \"name\"", DorkCategory.PERSONAL_INFO, "CRITICAL"),
        _d("Phone Numbers", "Phone number exposure", "site:{target} \"phone\" ext:csv OR ext:xls", DorkCategory.PERSONAL_INFO, "HIGH"),
        _d("Credit Card", "Credit card numbers (test)", "site:{target} intext:\"card number\" OR intext:\"cc number\"", DorkCategory.PERSONAL_INFO, "CRITICAL"),
    ],

    DorkCategory.SHODAN: [
        _d("Shodan IoT Search", "IoT devices via shodan.io", "site:shodan.io {target}", DorkCategory.SHODAN, "MEDIUM"),
        _d("Shodan Exposed", "Exposed services on shodan", 'site:shodan.io inurl:"host" {target}', DorkCategory.SHODAN, "HIGH"),
        _d("Shodan Reports", "Shodan reports and summaries", 'site:shodan.io inurl:"report" {target}', DorkCategory.SHODAN, "MEDIUM"),
    ],

    DorkCategory.NETWORK_DEVICES: [
        _d("Router Web", "Router web interface", "intitle:router configuration inurl:setup", DorkCategory.NETWORK_DEVICES, "MEDIUM"),
        _d("Switch Interface", "Network switch management", 'intitle:"switch" "management" inurl:admin', DorkCategory.NETWORK_DEVICES, "MEDIUM"),
        _d("Printer Web", "Network printer web interface", 'intitle:"printer" "status"', DorkCategory.NETWORK_DEVICES, "MEDIUM"),
        _d("Access Point", "Wireless access point", 'intitle:"access point" "status"', DorkCategory.NETWORK_DEVICES, "MEDIUM"),
    ],

    DorkCategory.IOT_DEVICES: [
        _d("Smart Home", "Smart home device interface", 'intitle:"smart home" "dashboard"', DorkCategory.IOT_DEVICES, "LOW"),
        _d("IP Webcam", "IP webcam stream", 'intitle:"IP Webcam" "live"', DorkCategory.IOT_DEVICES, "LOW"),
        _d("Router Interface", "Router configuration interface", 'intitle:"router" "configuration" inurl:setup', DorkCategory.IOT_DEVICES, "MEDIUM"),
        _d("Printer Interface", "Network printer web interface", 'intitle:"printer" "status" inurl:device', DorkCategory.IOT_DEVICES, "MEDIUM"),
        _d("NAS Interface", "NAS device management", 'intitle:"NAS" "management"', DorkCategory.IOT_DEVICES, "MEDIUM"),
    ],
}


# ─── Flat List ───────────────────────────────────────────────────────────────

def get_all_dorks() -> List[DorkRecord]:
    """Return all dorks as a flat list."""
    result = []
    for category_dorks in DORKS_BY_CATEGORY.values():
        result.extend(category_dorks)
    return result


def get_dorks_by_category(category: str) -> List[DorkRecord]:
    """Return all dorks in a specific category."""
    return DORKS_BY_CATEGORY.get(category, [])


def get_dorks_by_risk(risk_level: str) -> List[DorkRecord]:
    """Return all dorks matching a risk level (CRITICAL, HIGH, MEDIUM, LOW)."""
    risk_upper = risk_level.upper()
    return [d for d in get_all_dorks() if d["risk_level"] == risk_upper]


def resolve_dork_query(dork: DorkRecord, target: str) -> str:
    """Replace {target} placeholder in a dork query with the actual target."""
    return dork["query"].format(target=target)


def build_search_url(query: str) -> str:
    """Build a Google search URL for manual browsing (for reference)."""
    import urllib.parse
    return f"https://www.google.com/search?q={urllib.parse.quote(query)}"
