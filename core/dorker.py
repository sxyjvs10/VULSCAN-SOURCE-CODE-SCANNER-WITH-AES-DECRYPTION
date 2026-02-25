import urllib.parse

class GoogleDorker:
    def __init__(self, domain):
        self.domain = domain
        self.dorks = {
            "Publicly Exposed Documents": f"site:{domain} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv",
            "Directory Listing Vulnerabilities": f"site:{domain} intitle:index.of",
            "Configuration Files": f"site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini",
            "Database Files": f"site:{domain} ext:sql | ext:dbf | ext:mdb",
            "Log Files": f"site:{domain} ext:log",
            "Backup and Old Files": f"site:{domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup",
            "Login Pages": f"site:{domain} inurl:login | inurl:signin | intitle:Login",
            "SQL Errors": f"site:{domain} intext:\"sql syntax near\" | intext:\"syntax error has occurred\" | intext:\"incorrect syntax near\" | intext:\"unexpected end of SQL command\" | intext:\"Warning: mysql_connect()\" | intext:\"Warning: mysql_query()\" | intext:\"truly a mysql result\"",
            "PHP Errors/Warnings": f"site:{domain} \"PHP Parse error\" | \"PHP Warning\" | \"PHP Error\"",
            "Wordpress": f"site:{domain} inurl:wp- | inurl:wp-content | inurl:plugins | inurl:uploads | inurl:themes | inurl:download",
            "Cloud Buckets": f"site:s3.amazonaws.com \"{domain}\"",
            "Subdomain Enumeration": f"site:*.{domain} | site:*.*.{domain} | site:dev.*.{domain} | site:staging.*.{domain} | site:uat.*.{domain} | site:test.*.{domain}",
            "Exposed Spreadsheets": f"site:{domain} ext:xls | ext:xlsx | ext:ods | ext:csv \"password\" | \"username\" | \"email\" | \"creds\"",
            "SSH Keys": f"site:{domain} intitle:\"index of\" id_rsa | id_dsa | authorized_keys | known_hosts | ext:pem | ext:ppk",
            "Project Management": f"site:{domain} inurl:jira | inurl:confluence | inurl:trello | inurl:slack | inurl:portal",
            "Git Folders": f"site:{domain} inurl:/.git | intitle:\"Index of /.git\"",
            "Open Redirects": f"site:{domain} inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http | inurl:link=",
            "Code Leaks": f"site:pastebin.com \"{domain}\" | site:jsfiddle.net \"{domain}\" | site:github.com \"{domain}\" | site:gist.github.com \"{domain}\"",
            "Sensitive Directories": f"site:{domain} inurl:/proc/self/cwd | intitle:\"index of\" \"parent directory\""
        }

    def generate_links(self):
        """
        Returns a list of tuples (Title, URL)
        """
        links = []
        for title, query in self.dorks.items():
            encoded_query = urllib.parse.quote(query)
            url = f"https://www.google.com/search?q={encoded_query}"
            links.append((title, url))
        return links

    def print_dorks(self):
        print(f"\n[*] Google Dorks for {self.domain}:")
        for title, link in self.generate_links():
            print(f"  [+] {title}:")
            print(f"      {link}")
