#!/bin/bash

# Copyright 2023 - 10X de Guatemala, S.A.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Miguel E. Guerra Connor (miguelguerra@10x.gt)
# Creation Date: Oct 1, 2023
# Last Modification: Apr 13, 2024
# Version: 1.1.0
#
# Made in Guatemala ;)
#
# A script to automate the installation of WordPress on Debian systems with LEMP.
#
# Parameters:
#   --domain                 : The domain for the WordPress site, e.g., "my-site.com".
#   --mysql_root_password    : Password for the MySQL root user.
#   --db_name                : The name for the WordPress database.
#   --db_user                : Database username for WordPress.
#   --db_password            : Database user password for WordPress.
#   --wp_admin               : WordPress administrator username.
#   --wp_password            : WordPress administrator password.
#   --wp_email               : Email for the WordPress administrator.
#   --wp_title               : Title for the WordPress site.
#   --sudo_user              : Limited sudo user to be created for the Linode.
#   --sudo_password          : Password for the limited sudo user.
#   --disable_root           : Option to disable root access over SSH. Possible values: "yes", "no".
#   --ssh_key                : SSH public key.
#   --locale                 : Server locale setting, e.g., "en_US.UTF-8".
#   --timezone               : Server timezone, e.g., "US/Eastern".
#
# Example Usage:
# $sudo ./diezx-deb-lemp-wp.sh \
#     --domain="example.com" \
#     --mysql_root_password="RootPass123" \
#     --db_name="wp_database" \
#     --db_user="wp_user" \
#     --db_password="DbPass123" \
#     --wp_admin="adminUser" \
#     --wp_password="AdminPass123" \
#     --wp_email="admin@example.com" \
#     --wp_title="My WordPress Site" \
#     --locale="en_US.UTF-8" \
#     --timezone="US/Eastern" \
#     --sudo_user="sudoUsername" \
#     --sudo_password="SudoPass123" \
#     --disable_root="yes" \
#     --ssh_key="ssh-rsa AAAA...xyz user@host"

# Trap to capture and handle errors
trap 'echo "Error on line $LINENO"; exit 1' ERR

# Redirect output to a log file
exec > >(tee -i /var/log/diezx-deb-lemp-wp.log)
# Screen output for debub 
# exec 2>&1

# Ensure the script is executed with superuser permissions
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root or with sudo." 
   exit 1
fi

# Inform user about the script's execution time
echo "The script execution has started. This might take several minutes."

# Declare an associative array
declare -A parameters

# Define a list of valid parameter names
valid_params=(
  "domain" 
  "mysql_root_password" 
  "db_name" 
  "db_user" 
  "db_password" 
  "wp_admin" 
  "wp_password" 
  "wp_email" 
  "wp_title" 
  "locale" 
  "timezone" 
  "sudo_user" 
  "sudo_password" 
  "disable_root" 
  "ssh_key")

# Processing parameters
while [[ $# -gt 0 ]]; do
    key="${1%%=*}"   # Extract the key part (before the '=')
    value="${1#*=}"  # Extract the value part (after the '=')
    
    # Check if the key is in the list of valid parameters
    if [[ " ${valid_params[@]} " =~ " ${key#--} " ]]; then
        parameters[${key#--}]="$value"
    else
        echo "Unknown parameter: $1"
        exit 1
    fi
    shift
done

# Displaying parameters for debugging purposes
#for param in "${valid_params[@]}"; do
#    echo "$param: ${parameters[$param]}"
#done

# Verify that all mandatory arguments are defined
REQUIRED_ARGS=("domain"
  "mysql_root_password"
  "db_name"
  "db_user" 
  "db_password" 
  "wp_admin" 
  "wp_password" 
  "wp_email" 
  "wp_title" 
  "locale" 
  "timezone")
for arg in "${REQUIRED_ARGS[@]}"; do
    if [[ -z "${parameters[$arg]}" ]]; then
        echo "Error: Argument missing for $arg"
        exit 1
    fi
done

# Update the system
echo "Updating the system..."
sudo apt-get update -y && sudo apt-get upgrade -y

# Packages to install
packages=(
    nginx
    mariadb-server
    php
    php-fpm
    php-gd
    php-curl
    php-cli
    php-zip
    php-mysql
    php-xml
    certbot
    python3-certbot-nginx
)

echo "Installing necessary packages..."

# Instalar cada paquete si no está ya instalado
for pkg in "${packages[@]}"; do
    if ! dpkg -l | grep -qw "$pkg"; then
        echo "Installing $pkg..."
        sudo apt-get install -y "$pkg"
    else
        echo "$pkg is already installed."
    fi
done

echo "All necessary packages have been installed or were already present."

# Set the locale and timezone
echo "Setting locale to ${parameters[locale]} and timezone to ${parameters[timezone]}..."
# Ensure the locale is uncommented in /etc/locale.gen if it is commented
sudo sed -i "/^#.*${parameters[locale]}/s/^#//" /etc/locale.gen
# Set the locale and timezone
sudo locale-gen ${parameters[locale]}
sudo update-locale LANG=${parameters[locale]}
sudo timedatectl set-timezone ${parameters[timezone]}

# Create a limited sudo user
echo "Creating a limited sudo user..."
sudo adduser ${parameters[sudo_user]} --gecos "" --disabled-password
echo "${parameters[sudo_user]}:${parameters[sudo_password]}" | sudo chpasswd
sudo usermod -aG sudo ${parameters[sudo_user]}

# Disable root access over SSH if specified
if [[ ${parameters[disable_root]} == "yes" ]]; then
    echo "Disabling root access over SSH..."
    sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo systemctl reload sshd
fi

# Set up SSH key for the limited sudo user
if [[ ! -z "${parameters[ssh_key]}" ]]; then
    echo "Setting up SSH key..."
    sudo mkdir -p /home/${parameters[sudo_user]}/.ssh
    echo "${parameters[ssh_key]}" | sudo tee /home/${parameters[sudo_user]}/.ssh/authorized_keys
    sudo chown -R ${parameters[sudo_user]}:${parameters[sudo_user]} /home/${parameters[sudo_user]}/.ssh
    sudo chmod 700 /home/${parameters[sudo_user]}/.ssh
    sudo chmod 600 /home/${parameters[sudo_user]}/.ssh/authorized_keys
fi

# Start and enable services
echo "Starting and enabling services..."
sudo systemctl start nginx
sudo systemctl enable nginx
sudo systemctl start mariadb
sudo systemctl enable mariadb

# Configure nginx
echo "Configuring nginx..."
# Unlink the default site
sudo unlink /etc/nginx/sites-enabled/default || true  # Ignore error if the file doesn't exist

# Create the new site
sudo bash -c "cat > /etc/nginx/sites-available/${parameters[domain]} << 'EOL'
server {
  listen 80;
  server_name ${parameters[domain]} www.${parameters[domain]};

  root /var/www/html;
  index index.php index.html index.nginx-debian.html;
  access_log /var/log/nginx/${parameters[domain]}.log;
  error_log /var/log/nginx/${parameters[domain]}.log;

  # Headers for security
  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;
  add_header X-Frame-Options \"SAMEORIGIN\" always;
  add_header X-Content-Type-Options \"nosniff\" always;
  add_header Referrer-Policy \"no-referrer-when-downgrade\" always;
  add_header Content-Security-Policy \"frame-ancestors 'self'\";
  add_header Feature-Policy \"camera 'none'; microphone 'none'; geolocation 'none';\" always;

  location / {
    try_files \$uri \$uri/ /index.php\$is_args\$args;
  }

  location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
    expires 30d;
    add_header Cache-Control \"public, max-age=2592000\";
  }

  # Disable xmlrpc.php to ensure it doesn't receive remote API requests
  location = /xmlrpc.php {
    deny all;
    return 404;
  }

  # Restrict access to unnecessary files
  location ~* /(readme\.html|license\.txt)$ {
    deny all;
    return 404;
  }

  # Restrict the read access of user info of WordPress.
    location ~ ^/wp-json/wp/v2/users {
        deny all;
        return 403;
    }

  location ~ \.php$ {
    try_files \$uri =404;
    fastcgi_index index.php;
    include fastcgi_params;
    fastcgi_pass unix:/run/php/php-fpm.sock;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
  }
}
EOL"

# Enable the new site configuration
sudo ln -s /etc/nginx/sites-available/${parameters[domain]} /etc/nginx/sites-enabled/${parameters[domain]}

# Reload the nginx service
sudo systemctl reload nginx

# Secure the database
echo "Securing the database..."
sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${parameters[mysql_root_password]}';"
sudo mysql -uroot -p${parameters[mysql_root_password]} -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
sudo mysql -uroot -p${parameters[mysql_root_password]} -e "DELETE FROM mysql.user WHERE User='';"
sudo mysql -uroot -p${parameters[mysql_root_password]} -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
sudo mysql -uroot -p${parameters[mysql_root_password]} -e "FLUSH PRIVILEGES;"

# MySQL parameters and WP-CLI installation details from the parameters array
mysql_root_password=${parameters[mysql_root_password]}
db_name=${parameters[db_name]}
db_user=${parameters[db_user]}
db_password=${parameters[db_password]}
domain=${parameters[domain]}
wp_title=${parameters[wp_title]}
wp_admin=${parameters[wp_admin]}
wp_password=${parameters[wp_password]}
wp_email=${parameters[wp_email]}

# Create the database if it doesn't exist
echo "Checking and creating database if it doesn't exist..."
sudo mysql -uroot -p"$mysql_root_password" -e "CREATE DATABASE IF NOT EXISTS $db_name;"

# Create MySQL user if it doesn't exist
echo "Creating MySQL user if not exists..."
sudo mysql -uroot -p"$mysql_root_password" -e "CREATE USER IF NOT EXISTS '$db_user'@'localhost' IDENTIFIED BY '$db_password'; GRANT ALL PRIVILEGES ON $db_name.* TO '$db_user'@'localhost'; FLUSH PRIVILEGES;"

# Install WP-CLI if it is not already installed
echo "Installing WP-CLI if not already installed..."
if ! command -v wp > /dev/null; then
    curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x wp-cli.phar
    sudo mv wp-cli.phar /usr/local/bin/wp
else
    echo "WP-CLI is already installed."
fi

# Setting ownership to the www-data user
echo "Setting ownership to www-data user..."
sudo chown -R www-data:www-data /var/www

# Install WordPress if not already installed
echo "Installing WordPress if not already present..."
if ! sudo -u www-data -- wp core is-installed --path=/var/www/html; then
    sudo -u www-data -- wp core download --path=/var/www/html
    sudo -u www-data -- wp core config --debug --path=/var/www/html --dbname="$db_name" --dbuser="$db_user" --dbpass="$db_password" --dbhost=localhost
    sudo -u www-data -- wp core install --debug --path=/var/www/html --url="$domain" --title="$wp_title" --admin_user="$wp_admin" --admin_password="$wp_password" --admin_email="$wp_email"
    echo "WordPress installation completed successfully!"
else
    echo "WordPress is already installed."
fi


# Print installed software and versions
echo "Installation completed. Installed software and versions:"
nginx -v
wp --info
