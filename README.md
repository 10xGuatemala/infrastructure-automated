# Infrastructure Automated Repo
Repository for scripts and tools aimed at automating and managing infrastructure in cloud and local environments. Streamlining deployment, maintenance, and scalability of technological solutions.

## WordPress Automated Script
Script: diezx-deb-lemp-wp.sh

### Description

This script automates the setup of a LEMP (Linux, Nginx, MySQL, PHP) server on Debian 10+. Its main function is to facilitate the installation and configuration of WordPress. Key features of this script include:

- **Installation** of core LEMP components.
- **Creation** of a limited sudo user.
- **Option** to restrict root access via SSH.
- **Setup** of an SSH key for secure access.
- **Configuration** of server's locale and timezone based on user preference.

### Security & Performance

To boost both the security and performance of WordPress, this script incorporates a tailored Nginx configuration that:

- **Optimizes** the loading of images and static files.
- **Sets** cache control headers.
- **Configures** prolonged expiration for static resources.
- **Disables** access to `xmlrpc.php` to avoid potential abuse.
- **Restricts** access to files like `readme.html` and `license.txt`.
- **Implements** various HTTP security headers to ward off web-based threats and ensure a correct content security policy.

### Resources

Before executing the script, users can check available locales and timezones with:

**Locales**:
- Command: `locale -a`
- [Supported Locales](https://www.gnu.org/software/gettext/manual/html_node/Locale-Names.html)

**Timezones**:
- Command: `timedatectl list-timezones`

### Usage
./diezx-deb-lemp-wp.sh \
     --domain="example.com" \
     --mysql_root_password="RootPass123" \
     --db_name="wp_database" \
     --db_user="wp_user" \
     --db_password="DbPass123" \
     --wp_admin="adminUser" \
     --wp_password="AdminPass123" \
     --wp_email="admin@example.com" \
     --wp_title="My WordPress Site" \
     --locale="en_US.UTF-8" \
     --timezone="US/Eastern" \
     --sudo_user="sudoUsername" \
     --sudo_password="SudoPass123" \
     --disable_root="yes" \
     --ssh_key="ssh-rsa AAAA...xyz user@host"

## Logs
To gain insights into the script's execution, you can review the log at: `/var/log/diezx-deb-lemp-wp.log`.

---

Happy deploying!
