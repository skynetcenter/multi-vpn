#!/bin/bash

# Color
N="\033[0m"
R="\033[0;31m"
G="\033[0;32m"
B="\033[0;34m"
Y="\033[0;33m"
C="\033[0;36m"
P="\033[0;35m"
LR="\033[1;31m"
LG="\033[1;32m"
LB="\033[1;34m"
LY="\033[1;33m"
LC="\033[1;36m"
LP="\033[1;35m"
RB="\033[41;37m"
GB="\033[42;37m"
BB="\033[44;37m"
BD="\033[1m"

# Notification
INFO="[ ${LC}INFO${N} ] ${LB}"
OK="[ ${LG}DONE${N} ] ${BD}"
ERROR="[ ${LR}ERROR${N} ] ${LR}"

# Check Services
check_install() {
	if [[ 0 -eq $? ]]; then
		echo -e "${OK}$1 is installed${N}"
		sleep 1
	else
		echo -e "${ERROR}$1 is not installed${N}\n"
		exit 1
	fi
}

check_status() {
	if [[ "$(systemctl is-active $1)" == "active" ]]; then
		echo -e "${OK}$1 is running${N}"
		sleep 1
	else
		echo -e "${ERROR}$1 is not running${N}\n"
		exit 1
	fi
}

check_screen() {
	if screen -ls | grep -qw $1; then
		echo -e "${OK}$1 is running${N}"
		sleep 1
	else
		echo -e "${ERROR}$1 is not running${N}\n"
		exit 1
	fi
}

clear

# Source
repo="https://raw.githubusercontent.com/skynetcenter/multi-vpn/main/"
network=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n 1)
random_num=$((RANDOM % 12 + 4))
ws_path="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"

# Check Requirements 
echo -e "${INFO}Checking system requirements ..${N}"
sleep 1
if [[ $EUID -ne 0 ]]; then
	echo -e "${ERROR}Autoscript must be run as root${N}\n"
	exit 1
fi
apt update > /dev/null 2>&1
apt install -y virt-what > /dev/null 2>&1
if ! [[ "$(virt-what)" == "kvm" || "$(virt-what)" == "hyperv" ]]; then
	echo -e "${ERROR}Autoscript only supported for KVM virtualization${N}\n"
	exit 1
fi
source '/etc/os-release'
if [[ "${ID}" != "ubuntu" && $(echo "${VERSION_ID}") != "20.04" ]]; then
	echo -e "${ERROR}Autoscript only supported for Ubuntu 20.04${N}\n"
	exit 1
fi

# Update Packages
clear
echo -e "${INFO}Updating current packages ..${N}"
sleep 1
apt update
apt upgrade -y
apt autoremove -y

# Install Dependencies
clear
echo -e "${INFO}Installing package dependencies ..${N}"
apt install -y systemd curl wget screen cmake zip unzip vnstat tar openssl git uuid-runtime socat
check_install systemd
check_install curl
check_install wget
check_install screen
check_install cmake
check_install unzip
check_install vnstat
check_install tar
check_install openssl
check_install git
check_install uuid-runtime
check_install socat

# Check Domain
clear
echo -e "${LB}Enter a domain name :${N}"
echo -e "\c"
read domain
domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
ip=$(wget -qO- ipv4.icanhazip.com)
echo -e "${INFO}Checking domain name ..${N}"
sleep 1
if [[ ${domain_ip} == "${ip}" ]]; then
	echo -e "${OK}Domain name matched with server IP${N}"
	sleep 1
elif grep -qw "$domain" /etc/hosts; then
	echo -e "${OK}Domain name matched with server hostname${N}"
else
	echo -e "${ERROR}Domain name does not match with server IP or hostname${N}\n"
	exit 1
fi

# Optimize Settings
clear
echo -e "${INFO}Optimizing current settings ..${N}"
sleep 1
sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
echo -e "* soft nofile 65536
* hard nofile 65536" >> /etc/security/limits.conf
locale-gen en_US

# Set Timezone
clear
echo -e "${INFO}Set timezone Asia/Kuala_Lumpur GMT +8 ..${N}"
sleep 1
ln -sf /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime
systemctl start systemd-timesyncd
timedatectl
date

# Disable IPv6
clear
echo -e "${INFO}Disabling IPv6 settings ..${N}"
sleep 1
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1
echo -e "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p

# Enable BBR+FQ
clear
echo -e "${INFO}Enabling BBR+FQ settings ..${N}"
sleep 1
sysctl -w net.core.default_qdisc=fq
sysctl -w net.ipv4.tcp_congestion_control=bbr
echo -e "net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
sysctl -p

# Reset Iptables
clear
echo -e "${INFO}Resetting Iptables settings ..${N}"
sleep 1
apt install -y iptables-persistent
check_install iptables-persistent
ufw disable
iptables-save | awk '/^[*]/ { print $1 } 
                     /^:[A-Z]+ [^-]/ { print $1 " ACCEPT" ; }
                     /COMMIT/ { print $0; }' | iptables-restore

# Configure Cron
clear
if [ $(dpkg-query -W -f='${Status}' cron 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
	echo -e "${INFO}Installing Cron ..${N}"
	sleep 1
	apt install -y cron
	check_install cron
fi
echo -e "${INFO}Configuring Cron ..${N}"
sleep 1
mkdir /multivpn
wget -O /multivpn/cron.daily "${repo}files/cron.daily"
chmod +x /multivpn/cron.daily
(crontab -l; echo "0 1 * * * /multivpn/cron.daily") | crontab -

# Configure SSH
clear
echo -e "${INFO}Configuring SSH ..${N}"
sleep 1
echo "Multi VPN Access Server" > /etc/issue.net
sed -i "s/#Banner none/Banner \/etc\/issue.net/g" /etc/ssh/sshd_config
mkdir /multivpn/ssh
touch /multivpn/ssh/ssh-clients.txt
systemctl restart ssh
check_status ssh

# Install Dropbear
clear
echo -e "${INFO}Installing Dropbear ..${N}"
sleep 1
apt install -y dropbear
check_install dropbear
echo -e "${INFO}Configuring Dropbear ..${N}"
sleep 1
sed -i "s/NO_START=1/NO_START=0/g" /etc/default/dropbear
sed -i "s/DROPBEAR_PORT=22/DROPBEAR_PORT=110/g" /etc/default/dropbear
echo -e "/bin/false" >> /etc/shells
wget -O /etc/dropbear_issue.net "${repo}files/dropbear_issue.net"
sed -i 's|DROPBEAR_BANNER=""|DROPBEAR_BANNER="/etc/dropbear_issue.net"|g' /etc/default/dropbear
systemctl restart dropbear
check_status dropbear

# Install Stunnel
clear
echo -e "${INFO}Installing Stunnel ..${N}"
sleep 1
apt install -y stunnel4
check_install stunnel4
echo -e "${INFO}Configuring Stunnel ..${N}"
sleep 1
sed -i "s/ENABLED=0/ENABLED=1/g" /etc/default/stunnel4
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -sha256 -subj "/CN=Multi VPN/emailAddress=admin@skynetcenter.me/O=UpCloud Ltd/OU=Multi VPN Server/C=MY" -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem
wget -O /etc/stunnel/stunnel.conf "${repo}files/stunnel.conf"
systemctl restart stunnel4
check_status stunnel4

# Install OpenVPN
clear
echo -e "${INFO}Installing OpenVPN ..${N}"
sleep 1
apt install -y openvpn
check_install openvpn
echo -e "${INFO}Configuring OpenVPN ..${N}"
sleep 1
wget "${repo}files/openvpn/EasyRSA-3.0.8.tgz"
tar xvf EasyRSA-3.0.8.tgz
mv EasyRSA-3.0.8 /etc/openvpn/easy-rsa
cp /etc/openvpn/easy-rsa/vars.example /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_COUNTRY\t"US"/set_var EASYRSA_REQ_COUNTRY\t"MY"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_PROVINCE\t"California"/set_var EASYRSA_REQ_PROVINCE\t"Wilayah Persekutuan"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_CITY\t"San Francisco"/set_var EASYRSA_REQ_CITY\t"Kuala Lumpur"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_ORG\t"Copyleft Certificate Co"/set_var EASYRSA_REQ_ORG\t\t"UpCloud Ltd"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_EMAIL\t"me@example.net"/set_var EASYRSA_REQ_EMAIL\t"admin@skynetcenter.me"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_OU\t\t"My Organizational Unit"/set_var EASYRSA_REQ_OU\t\t"Multi VPN Server"/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_CA_EXPIRE\t3650/set_var EASYRSA_CA_EXPIRE\t3650/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_CERT_EXPIRE\t825/set_var EASYRSA_CERT_EXPIRE\t3650/g' /etc/openvpn/easy-rsa/vars
sed -i 's/#set_var EASYRSA_REQ_CN\t\t"ChangeMe"/set_var EASYRSA_REQ_CN\t\t"Multi VPN"/g' /etc/openvpn/easy-rsa/vars
cd /etc/openvpn/easy-rsa
./easyrsa --batch init-pki
./easyrsa --batch build-ca nopass
./easyrsa gen-dh
./easyrsa build-server-full server nopass
cd
mkdir /etc/openvpn/key
cp /etc/openvpn/easy-rsa/pki/issued/server.crt /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/key/
cp /etc/openvpn/easy-rsa/pki/private/server.key /etc/openvpn/key/
wget -O /etc/openvpn/server-udp.conf "${repo}files/openvpn/server-udp.conf"
wget -O /etc/openvpn/server-tcp.conf "${repo}files/openvpn/server-tcp.conf"
sed -i "s/#AUTOSTART="all"/AUTOSTART="all"/g" /etc/default/openvpn
echo -e "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p
rm EasyRSA-3.0.8.tgz
iptables -t nat -I POSTROUTING -s 10.8.0.0/24 -o ${network} -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.9.0.0/24 -o ${network} -j MASQUERADE
systemctl start openvpn@server-udp
systemctl start openvpn@server-tcp
systemctl enable openvpn@server-udp
systemctl enable openvpn@server-tcp
check_status openvpn@server-udp
check_status openvpn@server-tcp
echo -e "${INFO}Configuring OpenVPN client ..${N}"
sleep 1
mkdir /multivpn/openvpn
wget -O /multivpn/openvpn/client-udp.ovpn "${repo}files/openvpn/client-udp.ovpn"
wget -O /multivpn/openvpn/client-tcp.ovpn "${repo}files/openvpn/client-tcp.ovpn"
echo -e "${LB}Enter a bug host :${N}"
echo -e "\c"
read bughost
sed -i "s/xx/$ip/g" /multivpn/openvpn/client-udp.ovpn
sed -i "s+remote xx 1194+remote $ip:1194@$bughost/+g" /multivpn/openvpn/client-tcp.ovpn
sed -i "s/xx/$ip/g" /multivpn/openvpn/client-tcp.ovpn
echo -e "\n<ca>" >> /multivpn/openvpn/client-tcp.ovpn
cat "/etc/openvpn/key/ca.crt" >> /multivpn/openvpn/client-tcp.ovpn
echo -e "</ca>" >> /multivpn/openvpn/client-tcp.ovpn
echo -e "\n<ca>" >> /multivpn/openvpn/client-udp.ovpn
cat "/etc/openvpn/key/ca.crt" >> /multivpn/openvpn/client-udp.ovpn
echo -e "</ca>" >> /multivpn/openvpn/client-udp.ovpn

# Install Squid
clear
echo -e "${INFO}Installing Squid ..${N}"
sleep 1
apt install -y squid
check_install squid
wget -O /etc/squid/squid.conf "${repo}files/squid.conf"
sed -i "s/xx/$domain/g" /etc/squid/squid.conf
sed -i "s/ip/$ip/g" /etc/squid/squid.conf
systemctl restart squid
check_status squid

# Install Open HTTP Puncher
clear
echo -e "${INFO}Installing OHP server ..${N}"
sleep 1
apt install -y python
check_install python
wget -O /usr/bin/ohpserver "${repo}files/ohpserver"
chmod +x /usr/bin/ohpserver
screen -AmdS ohp-dropbear ohpserver -port 3128 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:110
screen -AmdS ohp-openvpn ohpserver -port 8000 -proxy 127.0.0.1:8080 -tunnel 127.0.0.1:1194
check_screen ohp-dropbear
check_screen ohp-openvpn

# Install BadVPN UDPGW
clear
echo -e "${INFO}Installing BadVPN UDPGW ..${N}"
sleep 1
wget -O badvpn.zip "${repo}files/badvpn.zip"
unzip badvpn.zip
mkdir badvpn-master/build-badvpn
cd badvpn-master/build-badvpn
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
cd
rm -rf badvpn-master
rm -f badvpn.zip
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
check_screen badvpn

# Install Nginx
clear
echo -e "${INFO}Installing Nginx ..${N}"
sleep 1
rm -f /etc/apt/sources.list.d/nginx.list
apt install -y lsb-release gnupg2
check_install lsb-release
check_install gnupg2
echo "deb http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list
curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -
apt update
if ! command -v nginx > /dev/null 2>&1; then
	apt install -y nginx
fi
check_install nginx
echo -e "${INFO}Configuring Nginx ..${N}"
sleep 1
rm -rf /etc/nginx/conf.d
mkdir -p /etc/nginx/conf.d
wget -O /etc/nginx/conf.d/${domain}.conf "${repo}files/html/domain.conf"
sed -i "s/xx/${domain}/g" /etc/nginx/conf.d/${domain}.conf
nginxConfig=$(systemctl status nginx | grep loaded | awk '{print $3}' | tr -d "(;")
sed -i "/^ExecStart=.*/i ExecStartPost=/bin/sleep 0.1" $nginxConfig
systemctl daemon-reload
systemctl restart nginx
systemctl enable nginx
rm -rf /var/www/html
mkdir -p /var/www/html
wget -O /var/www/html/index.html "${repo}files/html/index.html"
wget -O /var/www/html/style.css "${repo}files/html/style.css"
nginxUser=$(ps -eo pid,comm,euser,supgrp | grep nginx | tail -n 1 | awk '{print $2}')
nginxGroup=$(ps -eo pid,comm,euser,supgrp | grep nginx | tail -n 1 | awk '{print $3}')
chown -R ${nginxUser}:${nginxGroup} /var/www/html
find /var/www/html/ -type d -exec chmod 750 {} \;
find /var/www/html/ -type f -exec chmod 640 {} \;

# Install Xray
clear
echo -e "${INFO}Installing Xray core ..${N}"
sleep 1
apt install -y lsof libpcre3 libpcre3-dev zlib1g-dev libssl-dev jq
check_install lsof
check_install libpcre3
check_install libpcre3-dev
check_install zlib1g-dev
check_install libssl-dev
check_install jq
mkdir -p /usr/local/bin
curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
check_install xray
echo $domain > /usr/local/etc/xray/domain
echo $ws_path > /usr/local/etc/xray/websocket
wget -O /usr/local/etc/xray/vless.json "${repo}files/xray/config.json"
#wget -O /usr/local/etc/xray/ws.json "${repo}files/xray/xray_ws.json" > /dev/null 2>&1
#sed -i "s/xx/${domain}/g" /usr/local/etc/xray/ws.json
sed -i "s+xx+${ws_path}+g" /usr/local/etc/xray/vless.json
echo -e "${INFO}Configuring Xray ..${N}"
sleep 1
signedcert=$(xray tls cert -domain="$domain" -name="Multi VPN" -org="UpCloud Ltd" -expire=87600h)
echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee /usr/local/etc/xray/self_signed_cert.pem
echo $signedcert | jq '.key[]' | sed 's/\"//g' > /usr/local/etc/xray/self_signed_key.pem
openssl x509 -in /usr/local/etc/xray/self_signed_cert.pem -noout
chown -R nobody.nogroup /usr/local/etc/xray/self_signed_cert.pem
chown -R nobody.nogroup /usr/local/etc/xray/self_signed_key.pem
mkdir /multivpn/xray
touch /multivpn/xray/xray-clients.txt
curl -sL https://get.acme.sh | bash
"$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt
systemctl restart nginx
if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --webroot "/var/www/html" -k ec-256 --force; then
	echo -e "${OK}SSL certificate generated${N}"
	sleep 1
	if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /multivpn/xray/xray.crt --keypath /multivpn/xray/xray.key --reloadcmd "systemctl restart xray@vless" --ecc --force; then
		echo -e "${OK}SSL certificate installed${N}"
		sleep 1
	fi
else
	echo -e "${ERROR}Invalid installing and configuring SSL certificate${N}\n"
	exit 1
fi
chown -R nobody.nogroup /multivpn/xray/xray.crt
chown -R nobody.nogroup /multivpn/xray/xray.key
systemctl daemon-reload
systemctl restart nginx
systemctl restart xray@vless
#systemctl restart xray@ws
systemctl enable xray@vless
#systemctl enable xray@ws
check_status nginx
check_status xray@vless
#check_status xray@ws
(crontab -l;echo "0 * * * * echo '# Xray-Vless access log (Script by Multi VPN)' > /var/log/xray/access-vless.log") | crontab -
#(crontab -l;echo "0 * * * * echo '# Xray-WS access log (Script by Void VPN)' > /var/log/xray/access-ws.log") | crontab -

# Install WireGuard
clear
echo -e "${INFO}Installing WireGuard ..${N}"
sleep 1
apt install -y wireguard resolvconf qrencode
check_install wireguard
check_install resolvconf
check_install qrencode
server_priv_key=$(wg genkey)
server_pub_key=$(echo "${server_priv_key}" | wg pubkey)
echo -e "ip=${ip}
server_priv_key=${server_priv_key}
server_pub_key=${server_pub_key}" > /etc/wireguard/params
source /etc/wireguard/params
echo -e "[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = ${server_priv_key}
PostUp = sleep 1; iptables -A FORWARD -i ${network} -o wg0 -j ACCEPT; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${network} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${network} -o wg0 -j ACCEPT; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${network} -j MASQUERADE" >> /etc/wireguard/wg0.conf
systemctl start wg-quick@wg0
systemctl enable wg-quick@wg0
mkdir /multivpn/wireguard
touch /multivpn/wireguard/wireguard-clients.txt
check_status wg-quick@wg0

# Install Speedtest CLI
clear
echo -e "${INFO}Installing Speedtest CLI ..${N}"
sleep 1
wget -O speedtest.tgz "https://install.speedtest.net/app/cli/ookla-speedtest-1.1.1-linux-$(uname -m).tgz"
tar xvf speedtest.tgz -C /usr/bin/ speedtest
check_install speedtest
rm -f speedtest.tgz

# Install Fail2Ban
clear
echo -e "${INFO}Installing Fail2Ban ..${N}"
sleep 1
apt install -y fail2ban
check_install fail2ban
systemctl restart fail2ban
check_status fail2ban

# Install DDOS Deflate
clear
echo -e "${INFO}Installing DDOS Deflate ..${N}"
sleep 1
apt install -y dnsutils tcpdump dsniff grepcidr net-tools
check_install dnsutils
check_install tcpdump
check_install dsniff
check_install grepcidr
check_install net-tools
wget -O ddos.zip "${repo}files/ddos-deflate.zip"
unzip ddos.zip
cd ddos-deflate
chmod +x install.sh
./install.sh
cd
rm -rf ddos.zip ddos-deflate
check_status ddos

# Configure rc.local
clear
echo -e "${INFO}Checking for rc.local service ..${N}"
sleep 1
systemctl status rc-local
if [[ 0 -ne $? ]]; then
	echo -e "${INFO}Installing rc.local ..${N}"
	sleep 1
	wget -O /etc/systemd/system/rc-local.service "${repo}files/rc-local.service"
	echo -e "${INFO}Configuring rc.local ..${N}"
	sleep 1
	wget -O /etc/rc.local "${repo}files/rc.local"
	chmod +x /etc/rc.local
	systemctl start rc-local
	systemctl enable rc-local
	check_status rc-local
else
	echo -e "${INFO}Configuring rc.local ..${N}"
	sleep 1
	wget -O /etc/rc.local "${repo}files/rc.local"
	systemctl start rc-local
	systemctl enable rc-local
	check_status rc-local
fi

# Save Iptables
clear
echo -e "${INFO}Saving Iptables settings ..${N}"
sleep 1
systemctl stop wg-quick@wg0
iptables-save > /multivpn/iptables.rules
systemctl start wg-quick@wg0

# Configure Menu
clear
echo -e "${INFO}Configuring VPN menu ..${N}"
sleep 1
wget -O /usr/bin/menu "${repo}files/menu/menu.sh"
wget -O /usr/bin/ssh-vpn-script "${repo}files/menu/ssh-vpn-script.sh"
wget -O /usr/bin/xray-script "${repo}files/menu/xray-script.sh"
wget -O /usr/bin/wireguard-script "${repo}files/menu/wireguard-script.sh"
wget -O /usr/bin/check-script "${repo}files/menu/check-script.sh"
wget -O /usr/bin/backup-script "${repo}files/menu/backup-script.sh"
chmod +x /usr/bin/{menu,ssh-vpn-script,xray-script,wireguard-script,check-script,backup-script}

# Reboot System
clear
rm -f /root/install.sh
cat /dev/null > ~/.bash_history
echo -e "clear
cat /dev/null > ~/.bash_history
history -c" >> ~/.bash_logout
echo -e "${OK}Autoscript installation completed${N}"
echo -e "${OK}Press any key to reboot system ..\c${N}"
read -n 1
clear && reboot