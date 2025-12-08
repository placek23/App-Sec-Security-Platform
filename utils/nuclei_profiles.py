"""
Intelligent Nuclei Template Selector
Comprehensive profiles for all target types
"""

# =============================================================================
# NUCLEI SCANNING PROFILES - COMPREHENSIVE COLLECTION
# =============================================================================

NUCLEI_TEMPLATE_PROFILES = {
    
    # =========================================================================
    # GENERAL PURPOSE PROFILES
    # =========================================================================
    
    "quick": {
        "description": "Fast scan for critical issues only",
        "severity": "high,critical",
        "tags": None,
        "exclude_tags": "dos,fuzz,intrusive",
        "rate_limit": 100,
        "estimated_time": "5-10 minutes",
        "template_count": "~500",
        "use_case": "Quick first look, time-limited assessments"
    },
    
    "bounty": {
        "description": "Standard bug bounty scan - balanced coverage",
        "severity": "medium,high,critical",
        "tags": "cve,sqli,xss,ssrf,rce,lfi,rfi,redirect,exposure,misconfig",
        "exclude_tags": "dos,fuzz,intrusive",
        "rate_limit": 50,
        "estimated_time": "15-30 minutes",
        "template_count": "~1500",
        "use_case": "Bug bounty programs, standard assessments"
    },
    
    "full": {
        "description": "Comprehensive scan - all templates",
        "severity": "info,low,medium,high,critical",
        "tags": None,
        "exclude_tags": "dos",
        "rate_limit": 30,
        "estimated_time": "1-2 hours",
        "template_count": "~4000",
        "use_case": "Full security assessment, pentest"
    },
    
    "stealth": {
        "description": "Minimal footprint, critical only",
        "severity": "critical",
        "tags": "cve,rce,sqli",
        "exclude_tags": "dos,fuzz,intrusive,brute",
        "rate_limit": 10,
        "estimated_time": "5-10 minutes",
        "template_count": "~200",
        "use_case": "Stealth testing, avoiding detection"
    },
    
    # =========================================================================
    # VULNERABILITY TYPE PROFILES
    # =========================================================================
    
    "cve": {
        "description": "Known CVE vulnerabilities only",
        "severity": "medium,high,critical",
        "tags": "cve",
        "exclude_tags": None,
        "rate_limit": 50,
        "estimated_time": "20-40 minutes",
        "template_count": "~2000",
        "use_case": "CVE-focused scanning, patch verification"
    },
    
    "owasp": {
        "description": "OWASP Top 10 vulnerability categories",
        "severity": "medium,high,critical",
        "tags": "owasp,sqli,xss,injection,auth,misconfig,exposure,xxe,ssrf",
        "exclude_tags": "dos,fuzz",
        "rate_limit": 50,
        "estimated_time": "15-25 minutes",
        "template_count": "~1000",
        "use_case": "Compliance scanning, OWASP assessment"
    },
    
    "injection": {
        "description": "All injection types (SQLi, XSS, SSTI, etc.)",
        "severity": "medium,high,critical",
        "tags": "sqli,xss,ssti,injection,rce,lfi,rfi,xxe",
        "exclude_tags": "dos,fuzz",
        "rate_limit": 30,
        "estimated_time": "15-25 minutes",
        "template_count": "~600",
        "use_case": "Injection-focused testing"
    },
    
    "takeover": {
        "description": "Subdomain takeover checks",
        "severity": "medium,high,critical",
        "tags": "takeover",
        "exclude_tags": None,
        "rate_limit": 100,
        "estimated_time": "2-5 minutes",
        "template_count": "~50",
        "use_case": "Subdomain takeover hunting"
    },
    
    "exposure": {
        "description": "Sensitive file and data exposure",
        "severity": "low,medium,high,critical",
        "tags": "exposure,config,backup,logs,debug,disclosure",
        "exclude_tags": None,
        "rate_limit": 50,
        "estimated_time": "10-15 minutes",
        "template_count": "~400",
        "use_case": "Finding exposed files, configs, backups"
    },
    
    "default-logins": {
        "description": "Default credential checks",
        "severity": "high,critical",
        "tags": "default-login",
        "exclude_tags": None,
        "rate_limit": 20,
        "estimated_time": "5-10 minutes",
        "template_count": "~100",
        "use_case": "Default credential testing"
    },
    
    "recon": {
        "description": "Technology detection and fingerprinting",
        "severity": "info",
        "tags": "tech,detection,fingerprint,waf-detect",
        "exclude_tags": None,
        "rate_limit": 100,
        "estimated_time": "2-5 minutes",
        "template_count": "~300",
        "use_case": "Technology stack identification"
    },
    
    # =========================================================================
    # CMS-SPECIFIC PROFILES
    # =========================================================================
    
    "wordpress": {
        "description": "WordPress CMS security testing",
        "severity": "low,medium,high,critical",
        "tags": "wordpress,wp-plugin,wp-theme,wpscan",
        "exclude_tags": "dos",
        "rate_limit": 30,
        "estimated_time": "15-30 minutes",
        "template_count": "~500",
        "use_case": "WordPress sites, WP plugin vulnerabilities"
    },
    
    "joomla": {
        "description": "Joomla CMS security testing",
        "severity": "low,medium,high,critical",
        "tags": "joomla",
        "exclude_tags": "dos",
        "rate_limit": 30,
        "estimated_time": "10-20 minutes",
        "template_count": "~150",
        "use_case": "Joomla sites"
    },
    
    "drupal": {
        "description": "Drupal CMS security testing",
        "severity": "low,medium,high,critical",
        "tags": "drupal",
        "exclude_tags": "dos",
        "rate_limit": 30,
        "estimated_time": "10-15 minutes",
        "template_count": "~100",
        "use_case": "Drupal sites"
    },
    
    "magento": {
        "description": "Magento eCommerce security testing",
        "severity": "low,medium,high,critical",
        "tags": "magento",
        "exclude_tags": "dos",
        "rate_limit": 30,
        "estimated_time": "10-15 minutes",
        "template_count": "~80",
        "use_case": "Magento eCommerce sites"
    },
    
    "sharepoint": {
        "description": "Microsoft SharePoint security testing",
        "severity": "low,medium,high,critical",
        "tags": "sharepoint",
        "exclude_tags": "dos",
        "rate_limit": 30,
        "estimated_time": "10-15 minutes",
        "template_count": "~50",
        "use_case": "SharePoint installations"
    },
    
    "confluence": {
        "description": "Atlassian Confluence security testing",
        "severity": "low,medium,high,critical",
        "tags": "confluence,atlassian",
        "exclude_tags": "dos",
        "rate_limit": 30,
        "estimated_time": "10-15 minutes",
        "template_count": "~60",
        "use_case": "Confluence wikis"
    },
    
    "jira": {
        "description": "Atlassian Jira security testing",
        "severity": "low,medium,high,critical",
        "tags": "jira,atlassian",
        "exclude_tags": "dos",
        "rate_limit": 30,
        "estimated_time": "10-15 minutes",
        "template_count": "~70",
        "use_case": "Jira installations"
    },
    
    # =========================================================================
    # TECHNOLOGY STACK PROFILES
    # =========================================================================
    
    "apache": {
        "description": "Apache HTTP Server vulnerabilities",
        "severity": "low,medium,high,critical",
        "tags": "apache",
        "exclude_tags": "dos",
        "rate_limit": 50,
        "estimated_time": "10-15 minutes",
        "template_count": "~150",
        "use_case": "Apache web servers"
    },
    
    "nginx": {
        "description": "Nginx web server vulnerabilities",
        "severity": "low,medium,high,critical",
        "tags": "nginx",
        "exclude_tags": "dos",
        "rate_limit": 50,
        "estimated_time": "5-10 minutes",
        "template_count": "~50",
        "use_case": "Nginx web servers"
    },
    
    "iis": {
        "description": "Microsoft IIS vulnerabilities",
        "severity": "low,medium,high,critical",
        "tags": "iis,microsoft",
        "exclude_tags": "dos",
        "rate_limit": 50,
        "estimated_time": "10-15 minutes",
        "template_count": "~80",
        "use_case": "IIS web servers"
    },
    
    "tomcat": {
        "description": "Apache Tomcat vulnerabilities",
        "severity": "low,medium,high,critical",
        "tags": "tomcat,apache",
        "exclude_tags": "dos",
        "rate_limit": 50,
        "estimated_time": "10-15 minutes",
        "template_count": "~100",
        "use_case": "Tomcat application servers"
    },
    
    "nodejs": {
        "description": "Node.js/Express vulnerabilities",
        "severity": "low,medium,high,critical",
        "tags": "nodejs,express,javascript",
        "exclude_tags": "dos",
        "rate_limit": 50,
        "estimated_time": "10-15 minutes",
        "template_count": "~80",
        "use_case": "Node.js applications"
    },
    
    "php": {
        "description": "PHP application vulnerabilities",
        "severity": "low,medium,high,critical",
        "tags": "php",
        "exclude_tags": "dos",
        "rate_limit": 50,
        "estimated_time": "15-20 minutes",
        "template_count": "~200",
        "use_case": "PHP applications"
    },
    
    "java": {
        "description": "Java/Spring application vulnerabilities",
        "severity": "low,medium,high,critical",
        "tags": "java,spring,struts",
        "exclude_tags": "dos",
        "rate_limit": 50,
        "estimated_time": "15-20 minutes",
        "template_count": "~200",
        "use_case": "Java applications, Spring Boot"
    },
    
    "dotnet": {
        "description": ".NET/ASP.NET vulnerabilities",
        "severity": "low,medium,high,critical",
        "tags": "aspnet,dotnet,microsoft",
        "exclude_tags": "dos",
        "rate_limit": 50,
        "estimated_time": "10-15 minutes",
        "template_count": "~100",
        "use_case": ".NET applications"
    },
    
    "python": {
        "description": "Python/Django/Flask vulnerabilities",
        "severity": "low,medium,high,critical",
        "tags": "python,django,flask",
        "exclude_tags": "dos",
        "rate_limit": 50,
        "estimated_time": "10-15 minutes",
        "template_count": "~80",
        "use_case": "Python web applications"
    },
    
    "ruby": {
        "description": "Ruby/Rails vulnerabilities",
        "severity": "low,medium,high,critical",
        "tags": "ruby,rails",
        "exclude_tags": "dos",
        "rate_limit": 50,
        "estimated_time": "10-15 minutes",
        "template_count": "~60",
        "use_case": "Ruby on Rails applications"
    },
    
    # =========================================================================
    # API PROFILES
    # =========================================================================
    
    "api": {
        "description": "API security testing (REST/SOAP)",
        "severity": "low,medium,high,critical",
        "tags": "api,rest,soap,json,swagger,openapi",
        "exclude_tags": "dos",
        "rate_limit": 30,
        "estimated_time": "10-20 minutes",
        "template_count": "~400",
        "use_case": "REST APIs, SOAP services"
    },
    
    "graphql": {
        "description": "GraphQL API security testing",
        "severity": "low,medium,high,critical",
        "tags": "graphql",
        "exclude_tags": "dos",
        "rate_limit": 30,
        "estimated_time": "5-10 minutes",
        "template_count": "~50",
        "use_case": "GraphQL endpoints"
    },
    
    # =========================================================================
    # CLOUD PROFILES
    # =========================================================================
    
    "cloud": {
        "description": "General cloud misconfigurations",
        "severity": "low,medium,high,critical",
        "tags": "aws,azure,gcp,cloud,s3,bucket",
        "exclude_tags": None,
        "rate_limit": 50,
        "estimated_time": "10-15 minutes",
        "template_count": "~300",
        "use_case": "Cloud infrastructure"
    },
    
    "aws": {
        "description": "Amazon Web Services security",
        "severity": "low,medium,high,critical",
        "tags": "aws,s3,ec2,lambda,cloudfront",
        "exclude_tags": None,
        "rate_limit": 50,
        "estimated_time": "10-15 minutes",
        "template_count": "~150",
        "use_case": "AWS infrastructure"
    },
    
    "azure": {
        "description": "Microsoft Azure security",
        "severity": "low,medium,high,critical",
        "tags": "azure,microsoft",
        "exclude_tags": None,
        "rate_limit": 50,
        "estimated_time": "10-15 minutes",
        "template_count": "~100",
        "use_case": "Azure infrastructure"
    },
    
    "gcp": {
        "description": "Google Cloud Platform security",
        "severity": "low,medium,high,critical",
        "tags": "gcp,google-cloud",
        "exclude_tags": None,
        "rate_limit": 50,
        "estimated_time": "10-15 minutes",
        "template_count": "~80",
        "use_case": "GCP infrastructure"
    },
    
    "kubernetes": {
        "description": "Kubernetes/Docker security",
        "severity": "low,medium,high,critical",
        "tags": "kubernetes,k8s,docker,container",
        "exclude_tags": None,
        "rate_limit": 50,
        "estimated_time": "10-15 minutes",
        "template_count": "~100",
        "use_case": "Container orchestration"
    },
    
    # =========================================================================
    # NETWORK/INFRASTRUCTURE PROFILES
    # =========================================================================
    
    "network": {
        "description": "Network services and protocols",
        "severity": "low,medium,high,critical",
        "tags": "network,tcp,udp,ftp,ssh,telnet,smtp",
        "exclude_tags": "dos",
        "rate_limit": 50,
        "estimated_time": "15-25 minutes",
        "template_count": "~200",
        "use_case": "Network infrastructure"
    },
    
    "ssl": {
        "description": "SSL/TLS configuration issues",
        "severity": "low,medium,high,critical",
        "tags": "ssl,tls,certificate",
        "exclude_tags": None,
        "rate_limit": 50,
        "estimated_time": "5-10 minutes",
        "template_count": "~50",
        "use_case": "SSL/TLS assessment"
    },
    
    "dns": {
        "description": "DNS security issues",
        "severity": "low,medium,high,critical",
        "tags": "dns",
        "exclude_tags": None,
        "rate_limit": 50,
        "estimated_time": "5-10 minutes",
        "template_count": "~30",
        "use_case": "DNS infrastructure"
    },
    
    # =========================================================================
    # DEVICE/IOT PROFILES
    # =========================================================================
    
    "iot": {
        "description": "IoT device vulnerabilities",
        "severity": "low,medium,high,critical",
        "tags": "iot,router,camera,printer",
        "exclude_tags": "dos",
        "rate_limit": 30,
        "estimated_time": "15-25 minutes",
        "template_count": "~300",
        "use_case": "IoT devices, embedded systems"
    },
    
    "router": {
        "description": "Router/firewall vulnerabilities",
        "severity": "low,medium,high,critical",
        "tags": "router,mikrotik,cisco,netgear,dlink",
        "exclude_tags": "dos",
        "rate_limit": 30,
        "estimated_time": "10-15 minutes",
        "template_count": "~150",
        "use_case": "Network routers and firewalls"
    },
    
    # =========================================================================
    # PANEL/ADMIN PROFILES
    # =========================================================================
    
    "panels": {
        "description": "Admin panels and dashboards",
        "severity": "low,medium,high,critical",
        "tags": "panel,admin,dashboard,cpanel,plesk,webmin",
        "exclude_tags": "dos",
        "rate_limit": 30,
        "estimated_time": "15-20 minutes",
        "template_count": "~200",
        "use_case": "Control panels, admin interfaces"
    },
    
    "login": {
        "description": "Login pages and authentication",
        "severity": "low,medium,high,critical",
        "tags": "login,auth,panel,default-login",
        "exclude_tags": "dos,brute",
        "rate_limit": 20,
        "estimated_time": "10-15 minutes",
        "template_count": "~150",
        "use_case": "Authentication testing"
    },
    
    # =========================================================================
    # CI/CD & DEVOPS PROFILES
    # =========================================================================
    
    "cicd": {
        "description": "CI/CD pipeline security",
        "severity": "low,medium,high,critical",
        "tags": "jenkins,gitlab,github,circleci,travis,bamboo",
        "exclude_tags": "dos",
        "rate_limit": 30,
        "estimated_time": "10-15 minutes",
        "template_count": "~100",
        "use_case": "CI/CD systems"
    },
    
    "git": {
        "description": "Git exposure and misconfigurations",
        "severity": "low,medium,high,critical",
        "tags": "git,gitlab,github,bitbucket,exposure",
        "exclude_tags": None,
        "rate_limit": 50,
        "estimated_time": "5-10 minutes",
        "template_count": "~50",
        "use_case": "Git repository exposure"
    },
}

# =============================================================================
# TAG DESCRIPTIONS
# =============================================================================

NUCLEI_TAGS = {
    # Vulnerability types
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "ssrf": "Server-Side Request Forgery",
    "rce": "Remote Code Execution",
    "lfi": "Local File Inclusion",
    "rfi": "Remote File Inclusion",
    "ssti": "Server-Side Template Injection",
    "xxe": "XML External Entity",
    "redirect": "Open Redirect",
    "csrf": "Cross-Site Request Forgery",
    "idor": "Insecure Direct Object Reference",
    
    # CVE/Known vulns
    "cve": "Known CVE vulnerabilities",
    "cve2024": "2024 CVEs",
    "cve2023": "2023 CVEs",
    "cve2022": "2022 CVEs",
    "cve2021": "2021 CVEs",
    
    # Categories
    "owasp": "OWASP Top 10 related",
    "takeover": "Subdomain takeover",
    "exposure": "Sensitive data exposure",
    "misconfig": "Misconfigurations",
    "default-login": "Default credentials",
    "auth": "Authentication issues",
    "disclosure": "Information disclosure",
    
    # CMS
    "wordpress": "WordPress",
    "wp-plugin": "WordPress plugins",
    "wp-theme": "WordPress themes",
    "joomla": "Joomla",
    "drupal": "Drupal",
    "magento": "Magento",
    
    # Technology
    "tech": "Technology detection",
    "apache": "Apache",
    "nginx": "Nginx",
    "iis": "Microsoft IIS",
    "tomcat": "Apache Tomcat",
    "php": "PHP",
    "java": "Java",
    "spring": "Spring Framework",
    "nodejs": "Node.js",
    "python": "Python",
    "django": "Django",
    "flask": "Flask",
    "ruby": "Ruby",
    "rails": "Ruby on Rails",
    
    # Cloud
    "aws": "Amazon Web Services",
    "azure": "Microsoft Azure",
    "gcp": "Google Cloud Platform",
    "cloud": "General cloud",
    "s3": "S3 bucket issues",
    "kubernetes": "Kubernetes",
    "docker": "Docker",
    
    # API
    "api": "API testing",
    "graphql": "GraphQL",
    "rest": "REST API",
    "swagger": "Swagger/OpenAPI",
    
    # Panels
    "panel": "Admin panels",
    "jenkins": "Jenkins CI",
    "gitlab": "GitLab",
    "jira": "Jira",
    "confluence": "Confluence",
    
    # Network
    "network": "Network services",
    "ssl": "SSL/TLS",
    "dns": "DNS",
    
    # Behavior modifiers (CAUTION)
    "dos": "Denial of Service (DANGEROUS)",
    "fuzz": "Fuzzing templates",
    "intrusive": "Intrusive tests",
    "brute": "Brute force"
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_profile(profile_name: str) -> dict:
    """Get a scanning profile by name"""
    return NUCLEI_TEMPLATE_PROFILES.get(profile_name, NUCLEI_TEMPLATE_PROFILES["bounty"])


def list_profiles(category: str = None):
    """List all available profiles, optionally filtered by category"""
    print("\n" + "=" * 80)
    print("NUCLEI SCANNING PROFILES")
    print("=" * 80)
    
    categories = {
        "general": ["quick", "bounty", "full", "stealth"],
        "vuln_type": ["cve", "owasp", "injection", "takeover", "exposure", "default-logins", "recon"],
        "cms": ["wordpress", "joomla", "drupal", "magento", "sharepoint", "confluence", "jira"],
        "tech_stack": ["apache", "nginx", "iis", "tomcat", "nodejs", "php", "java", "dotnet", "python", "ruby"],
        "api": ["api", "graphql"],
        "cloud": ["cloud", "aws", "azure", "gcp", "kubernetes"],
        "network": ["network", "ssl", "dns"],
        "device": ["iot", "router"],
        "admin": ["panels", "login"],
        "devops": ["cicd", "git"]
    }
    
    for cat_name, profile_names in categories.items():
        if category and cat_name != category:
            continue
            
        print(f"\n{'─' * 40}")
        print(f"  {cat_name.upper().replace('_', ' ')}")
        print(f"{'─' * 40}")
        
        for name in profile_names:
            if name in NUCLEI_TEMPLATE_PROFILES:
                profile = NUCLEI_TEMPLATE_PROFILES[name]
                print(f"\n  📋 {name}")
                print(f"     {profile['description']}")
                print(f"     Templates: {profile['template_count']} | Time: {profile['estimated_time']}")


def recommend_profile(target_info: dict) -> str:
    """
    Recommend a scanning profile based on target context.
    
    Args:
        target_info: Dict with target context:
            - type: "webapp", "api", "cloud", "cms", "network"
            - technology: detected tech stack
            - cms: "wordpress", "joomla", etc.
            - time_limit: minutes available
            - stealth: True/False
            - bug_bounty: True/False
    """
    target_type = target_info.get("type", "webapp")
    technology = target_info.get("technology", "").lower()
    cms = target_info.get("cms", "").lower()
    time_limit = target_info.get("time_limit", 30)
    stealth = target_info.get("stealth", False)
    bug_bounty = target_info.get("bug_bounty", True)
    
    # Stealth mode
    if stealth:
        return "stealth"
    
    # Very short time
    if time_limit < 10:
        return "quick"
    
    # CMS detection
    if cms or any(c in technology for c in ["wordpress", "wp-"]):
        return "wordpress"
    if "joomla" in technology or "joomla" in cms:
        return "joomla"
    if "drupal" in technology or "drupal" in cms:
        return "drupal"
    if "magento" in technology:
        return "magento"
    
    # API targets
    if target_type == "api" or "api" in technology:
        return "api"
    if "graphql" in technology:
        return "graphql"
    
    # Cloud targets
    if target_type == "cloud":
        return "cloud"
    if "aws" in technology or "amazon" in technology:
        return "aws"
    if "azure" in technology:
        return "azure"
    if "gcp" in technology or "google" in technology:
        return "gcp"
    
    # Tech stack detection
    if any(t in technology for t in ["jenkins", "gitlab", "github", "circleci"]):
        return "cicd"
    if "kubernetes" in technology or "k8s" in technology:
        return "kubernetes"
    if "java" in technology or "spring" in technology:
        return "java"
    if "php" in technology:
        return "php"
    if "node" in technology or "express" in technology:
        return "nodejs"
    if "python" in technology or "django" in technology or "flask" in technology:
        return "python"
    if "ruby" in technology or "rails" in technology:
        return "ruby"
    if "asp" in technology or ".net" in technology:
        return "dotnet"
    
    # Bug bounty defaults
    if bug_bounty:
        if time_limit < 20:
            return "quick"
        elif time_limit < 45:
            return "bounty"
        else:
            return "full"
    
    return "bounty"


def build_nuclei_args(profile_name: str) -> dict:
    """Build nuclei arguments from a profile"""
    profile = get_profile(profile_name)
    
    args = {
        "severity": profile["severity"],
        "rate_limit": profile["rate_limit"]
    }
    
    if profile["tags"]:
        args["tags"] = profile["tags"]
    
    if profile["exclude_tags"]:
        args["exclude_tags"] = profile["exclude_tags"]
    
    return args


def get_profile_summary(profile_name: str) -> str:
    """Get a human-readable summary of a profile"""
    profile = get_profile(profile_name)
    return f"""
Profile: {profile_name.upper()}
{profile['description']}

Templates: {profile['template_count']}
Estimated Time: {profile['estimated_time']}
Severity: {profile['severity']}
Tags: {profile['tags'] or 'All'}
Excluded: {profile['exclude_tags'] or 'None'}
Use Case: {profile['use_case']}
"""


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--list":
            list_profiles()
        elif sys.argv[1] == "--info":
            if len(sys.argv) > 2:
                print(get_profile_summary(sys.argv[2]))
            else:
                print("Usage: python nuclei_profiles.py --info <profile_name>")
        else:
            print(get_profile_summary(sys.argv[1]))
    else:
        list_profiles()
