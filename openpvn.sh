#!/bin/bash
# shellcheck disable=SC1091,SC2164,SC2034,SC1072,SC1073,SC1009

# 
# OPENVPN + CCD + PORT-FORWARDING INSTALL/CONFIG SCRIPT
#
# Original script credit: github.com/angristan/openvpn-install
# Major modifications to:
#   - Prompt for local behind-the-client networks (CCD)
#   - Add or update CCD for existing user
#   - Provide port forwarding capabilities
#

function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ $ID == "debian" || $ID == "raspbian" ]]; then
			if [[ $VERSION_ID -lt 9 ]]; then
				echo "⚠️ Your version of Debian is not supported."
				echo ""
				echo "However, if you're using Debian >= 9 or unstable/testing then you can continue, at your own risk."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
				echo "⚠️ Your version of Ubuntu is not supported."
				echo ""
				echo "However, if you're using Ubuntu >= 16.04 or beta, then you can continue, at your own risk."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/system-release ]]; then
		source /etc/os-release
		if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "centos" ]]; then
			OS="centos"
			if [[ ! $VERSION_ID =~ (7|8) ]]; then
				echo "⚠️ Your version of CentOS is not supported."
				echo ""
				echo "The script only supports CentOS 7 and CentOS 8."
				echo ""
				exit 1
			fi
		fi
		if [[ $ID == "ol" ]]; then
			OS="oracle"
			if [[ ! $VERSION_ID =~ (8) ]]; then
				echo "Your version of Oracle Linux is not supported."
				echo ""
				echo "The script only supports Oracle Linux 8."
				exit 1
			fi
		fi
		if [[ $ID == "amzn" ]]; then
			OS="amzn"
			if [[ $VERSION_ID != "2" ]]; then
				echo "⚠️ Your version of Amazon Linux is not supported."
				echo ""
				echo "The script only supports Amazon Linux 2."
				echo ""
				exit 1
			fi
		fi
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "It seems you are not running this installer on a supported OS (Debian/Ubuntu/Fedora/CentOS/Arch/etc.)"
		exit 1
	fi
}

function initialCheck() {
	if ! isRoot; then
		echo "Sorry, you need to run this as root."
		exit 1
	fi
	if ! tunAvailable; then
		echo "TUN is not available."
		exit 1
	fi
	checkOS
}

function installUnbound() {
	if [[ ! -e /etc/unbound/unbound.conf ]]; then

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get install -y unbound
			echo 'interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes' >>/etc/unbound/unbound.conf

		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum install -y unbound
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "fedora" ]]; then
			dnf install -y unbound
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|# use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "arch" ]]; then
			pacman -Syu --noconfirm unbound
			curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache

			if [[ ! -f /etc/unbound/unbound.conf.old ]]; then
				mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old
			fi

			echo 'server:
	use-syslog: yes
	do-daemonize: no
	username: "unbound"
	directory: "/etc/unbound"
	trust-anchor-file: trusted-key.key
	root-hints: root.hints
	interface: 10.8.0.1
	access-control: 10.8.0.1/24 allow
	port: 53
	num-threads: 2
	use-caps-for-id: yes
	harden-glue: yes
	hide-identity: yes
	hide-version: yes
	qname-minimisation: yes
	prefetch: yes' >/etc/unbound/unbound.conf
		fi

		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/unbound.conf
		fi

		if [[ ! $OS =~ (fedora|centos|amzn|oracle) ]]; then
			echo "private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96" >>/etc/unbound/unbound.conf
		fi
	else
		echo 'include: /etc/unbound/openvpn.conf' >>/etc/unbound/unbound.conf
		echo 'server:
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96' >/etc/unbound/openvpn.conf

		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/openvpn.conf
		fi
	fi

	systemctl enable unbound
	systemctl restart unbound
}

function installQuestions() {
	echo "Welcome to the OpenVPN installer!"
	echo "The git repository is available at: https://github.com/angristan/openvpn-install"
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can leave the default options and just press enter if you are ok with them."
	echo ""
	echo "I need to know the IPv4 address of the interface you want OpenVPN listening on."
	echo "Unless your server is behind NAT, it should be the public IPv4 address."

	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	if [[ -z $IP ]]; then
		IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi

	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		read -rp "IP address: " -e -i "$IP" IP
	fi

	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo ""
		echo "It seems this server is behind NAT. What is its public IPv4 address or hostname?"
		echo "We need it for the clients to connect to the server."
		PUBLICIP=$(curl -s https://api.ipify.org)
		until [[ $ENDPOINT != "" ]]; do
			read -rp "Public IPv4 address or hostname: " -e -i "$PUBLICIP" ENDPOINT
		done
	fi

	echo ""
	echo "Checking for IPv6 connectivity..."
	echo ""
	if type ping6 >/dev/null 2>&1; then
		PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
	fi
	if eval "$PING6"; then
		echo "Your host appears to have IPv6 connectivity."
		SUGGESTION="y"
	else
		echo "Your host does not appear to have IPv6 connectivity."
		SUGGESTION="n"
	fi
	echo ""
	until [[ $IPV6_SUPPORT =~ (y|n) ]]; do
		read -rp "Do you want to enable IPv6 support (NAT)? [y/n]: " -e -i $SUGGESTION IPV6_SUPPORT
	done
	echo ""
	echo "What port do you want OpenVPN to listen on?"
	echo "   1) Default: 1194"
	echo "   2) Custom"
	echo "   3) Random [49152-65535]"
	until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "Port choice [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
	1)
		PORT="1194"
		;;
	2)
		until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
			read -rp "Custom port [1-65535]: " -e -i 1194 PORT
		done
		;;
	3)
		PORT=$(shuf -i49152-65535 -n1)
		echo "Random Port: $PORT"
		;;
	esac
	echo ""
	echo "What protocol do you want OpenVPN to use?"
	echo "UDP is faster. Unless it is not available, you shouldn't use TCP."
	echo "   1) UDP"
	echo "   2) TCP"
	until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "Protocol [1-2]: " -e -i 1 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
	1)
		PROTOCOL="udp"
		;;
	2)
		PROTOCOL="tcp"
		;;
	esac
	echo ""
	echo "What DNS resolvers do you want to use with the VPN?"
	echo "   1) Current system resolvers (from /etc/resolv.conf)"
	echo "   2) Self-hosted DNS Resolver (Unbound)"
	echo "   3) Cloudflare"
	echo "   4) Quad9"
	echo "   5) Quad9 uncensored"
	echo "   6) FDN (France)"
	echo "   7) DNS.WATCH (Germany)"
	echo "   8) OpenDNS"
	echo "   9) Google"
	echo "   10) Yandex Basic"
	echo "   11) AdGuard DNS"
	echo "   12) NextDNS"
	echo "   13) Custom"
	until [[ $DNS =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ] && [ "$DNS" -le 13 ]; do
		read -rp "DNS [1-13]: " -e -i 9 DNS
		if [[ $DNS == 2 ]] && [[ -e /etc/unbound/unbound.conf ]]; then
			echo ""
			echo "Unbound is already installed."
			echo "We can configure it to use from your OpenVPN clients. No changes to existing config."
			echo ""
			until [[ $CONTINUE =~ (y|n) ]]; do
				read -rp "Apply config changes to Unbound? [y/n]: " -e CONTINUE
			done
			if [[ $CONTINUE == "n" ]]; then
				unset DNS
				unset CONTINUE
			fi
		elif [[ $DNS == "13" ]]; then
			until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "Primary DNS: " -e DNS1
			done
			until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "Secondary DNS (optional): " -e DNS2
				if [[ $DNS2 == "" ]]; then
					break
				fi
			done
		fi
	done
	echo ""
	echo "Do you want to use compression? (Not recommended due to VORACLE attack)."
	until [[ $COMPRESSION_ENABLED =~ (y|n) ]]; do
		read -rp "Enable compression? [y/n]: " -e -i n COMPRESSION_ENABLED
	done
	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "Choose which compression algorithm: (ordered by efficiency)"
		echo "   1) LZ4-v2"
		echo "   2) LZ4"
		echo "   3) LZO"
		until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "Compression algorithm [1-3]: " -e -i 1 COMPRESSION_CHOICE
		done
		case $COMPRESSION_CHOICE in
		1)
			COMPRESSION_ALG="lz4-v2"
			;;
		2)
			COMPRESSION_ALG="lz4"
			;;
		3)
			COMPRESSION_ALG="lzo"
			;;
		esac
	fi
	echo ""
	echo "Do you want to customize encryption settings? (Otherwise uses defaults: AES-128-GCM etc.)"
	until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
		read -rp "Customize encryption settings? [y/n]: " -e -i n CUSTOMIZE_ENC
	done
	if [[ $CUSTOMIZE_ENC == "n" ]]; then
		CIPHER="AES-128-GCM"
		CERT_TYPE="1" # ECDSA
		CERT_CURVE="prime256v1"
		CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		DH_TYPE="1" # ECDH
		DH_CURVE="prime256v1"
		HMAC_ALG="SHA256"
		TLS_SIG="1" # tls-crypt
	else
		echo ""
		echo "Data channel cipher:"
		echo "   1) AES-128-GCM (recommended)"
		echo "   2) AES-192-GCM"
		echo "   3) AES-256-GCM"
		echo "   4) AES-128-CBC"
		echo "   5) AES-192-CBC"
		echo "   6) AES-256-CBC"
		until [[ $CIPHER_CHOICE =~ ^[1-6]$ ]]; do
			read -rp "Cipher [1-6]: " -e -i 1 CIPHER_CHOICE
		done
		case $CIPHER_CHOICE in
		1)
			CIPHER="AES-128-GCM"
			;;
		2)
			CIPHER="AES-192-GCM"
			;;
		3)
			CIPHER="AES-256-GCM"
			;;
		4)
			CIPHER="AES-128-CBC"
			;;
		5)
			CIPHER="AES-192-CBC"
			;;
		6)
			CIPHER="AES-256-CBC"
			;;
		esac
		echo ""
		echo "Certificate key type:"
		echo "   1) ECDSA (recommended)"
		echo "   2) RSA"
		until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
			read -rp "Certificate key type [1-2]: " -e -i 1 CERT_TYPE
		done
		case $CERT_TYPE in
		1)
			echo ""
			echo "ECDSA curve choice:"
			echo "   1) prime256v1 (recommended)"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "Curve [1-3]: " -e -i 1 CERT_CURVE_CHOICE
			done
			case $CERT_CURVE_CHOICE in
			1)
				CERT_CURVE="prime256v1"
				;;
			2)
				CERT_CURVE="secp384r1"
				;;
			3)
				CERT_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "RSA key size:"
			echo "   1) 2048 bits (recommended)"
			echo "   2) 3072 bits"
			echo "   3) 4096 bits"
			until [[ $RSA_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "RSA key size [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
			done
			case $RSA_KEY_SIZE_CHOICE in
			1)
				RSA_KEY_SIZE="2048"
				;;
			2)
				RSA_KEY_SIZE="3072"
				;;
			3)
				RSA_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		echo "Control channel cipher:"
		if [[ $CERT_TYPE == "1" ]]; then
			echo "   1) TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256 (recommended)"
			echo "   2) TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp "Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
		else
			echo "   1) TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256 (recommended)"
			echo "   2) TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp "Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
		fi
		echo ""
		echo "Diffie-Hellman key type:"
		echo "   1) ECDH (recommended)"
		echo "   2) DH"
		until [[ $DH_TYPE =~ ^[1-2]$ ]]; do
			read -rp "DH key type [1-2]: " -e -i 1 DH_TYPE
		done
		case $DH_TYPE in
		1)
			echo ""
			echo "ECDH curve:"
			echo "   1) prime256v1 (recommended)"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			until [[ $DH_CURVE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "Curve [1-3]: " -e -i 1 DH_CURVE_CHOICE
			done
			case $DH_CURVE_CHOICE in
			1)
				DH_CURVE="prime256v1"
				;;
			2)
				DH_CURVE="secp384r1"
				;;
			3)
				DH_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "DH key size:"
			echo "   1) 2048 bits (recommended)"
			echo "   2) 3072 bits"
			echo "   3) 4096 bits"
			until [[ $DH_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "DH key size [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
			done
			case $DH_KEY_SIZE_CHOICE in
			1)
				DH_KEY_SIZE="2048"
				;;
			2)
				DH_KEY_SIZE="3072"
				;;
			3)
				DH_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		echo "HMAC (digest) algorithm for control channel packets:"
		echo "   1) SHA-256 (recommended)"
		echo "   2) SHA-384"
		echo "   3) SHA-512"
		until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "Digest algorithm [1-3]: " -e -i 1 HMAC_ALG_CHOICE
		done
		case $HMAC_ALG_CHOICE in
		1)
			HMAC_ALG="SHA256"
			;;
		2)
			HMAC_ALG="SHA384"
			;;
		3)
			HMAC_ALG="SHA512"
			;;
		esac
		echo ""
		echo "Additional security: tls-auth or tls-crypt"
		echo "   1) tls-crypt (recommended)"
		echo "   2) tls-auth"
		until [[ $TLS_SIG =~ ^[1-2]$ ]]; do
			read -rp "Control channel security [1-2]: " -e -i 1 TLS_SIG
		done
	fi
	echo ""
	echo "All set. Ready to install OpenVPN with these options."
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "Press any key to continue..."
	fi
}

function installOpenVPN() {
	if [[ $AUTO_INSTALL == "y" ]]; then
		APPROVE_INSTALL=${APPROVE_INSTALL:-y}
		APPROVE_IP=${APPROVE_IP:-y}
		IPV6_SUPPORT=${IPV6_SUPPORT:-n}
		PORT_CHOICE=${PORT_CHOICE:-1}
		PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
		DNS=${DNS:-1}
		COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
		CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
		CLIENT=${CLIENT:-client}
		PASS=${PASS:-1}
		CONTINUE=${CONTINUE:-y}
		if [[ $IPV6_SUPPORT == "y" ]]; then
			PUBLIC_IP=$(curl https://ifconfig.co)
		else
			PUBLIC_IP=$(curl -4 https://ifconfig.co)
		fi
		ENDPOINT=${ENDPOINT:-$PUBLIC_IP}
	fi

	installQuestions

	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	if [[ -z $NIC ]] && [[ $IPV6_SUPPORT == 'y' ]]; then
		NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
	fi

	if [[ -z $NIC ]]; then
		echo
		echo "Cannot detect public interface (for MASQUERADE)."
		until [[ $CONTINUE =~ (y|n) ]]; do
			read -rp "Continue? [y/n]: " -e CONTINUE
		done
		if [[ $CONTINUE == "n" ]]; then
			exit 1
		fi
	fi

	if [[ ! -e /etc/openvpn/server.conf ]]; then
		# Install openvpn if needed
		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get update
			apt-get -y install ca-certificates gnupg
			if [[ $VERSION_ID == "16.04" ]]; then
				echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" >/etc/apt/sources.list.d/openvpn.list
				wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
				apt-get update
			fi
			apt-get install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'centos' ]]; then
			yum install -y epel-release
			yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'
		elif [[ $OS == 'oracle' ]]; then
			yum install -y 'oracle-epel-release-*'
			yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'
		elif [[ $OS == 'amzn' ]]; then
			amazon-linux-extras install -y epel
			yum install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'fedora' ]]; then
			dnf install -y openvpn iptables openssl wget ca-certificates curl policycoreutils-python-utils
		elif [[ $OS == 'arch' ]]; then
			pacman --needed --noconfirm -Syu openvpn iptables openssl wget ca-certificates curl
		fi

		if [[ -d /etc/openvpn/easy-rsa/ ]]; then
			rm -rf /etc/openvpn/easy-rsa/
		fi
	fi

	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi

	if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
		local version="3.0.7"
		wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
		mkdir -p /etc/openvpn/easy-rsa
		tar xzf ~/easy-rsa.tgz --strip-components=1 --directory /etc/openvpn/easy-rsa
		rm -f ~/easy-rsa.tgz

		cd /etc/openvpn/easy-rsa/ || return
		case $CERT_TYPE in
		1)
			echo "set_var EASYRSA_ALGO ec" >vars
			echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
			;;
		2)
			echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
			;;
		esac

		SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_CN" >SERVER_CN_GENERATED
		SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_NAME" >SERVER_NAME_GENERATED

		echo "set_var EASYRSA_REQ_CN $SERVER_CN" >>vars
		./easyrsa init-pki
		./easyrsa --batch build-ca nopass

		if [[ $DH_TYPE == "2" ]]; then
			openssl dhparam -out dh.pem $DH_KEY_SIZE
		fi

		./easyrsa build-server-full "$SERVER_NAME" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

		case $TLS_SIG in
		1)
			openvpn --genkey --secret /etc/openvpn/tls-crypt.key
			;;
		2)
			openvpn --genkey --secret /etc/openvpn/tls-auth.key
			;;
		esac
	else
		cd /etc/openvpn/easy-rsa/ || return
		SERVER_NAME=$(cat SERVER_NAME_GENERATED)
	fi

	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	if [[ $DH_TYPE == "2" ]]; then
		cp dh.pem /etc/openvpn
	fi
	chmod 644 /etc/openvpn/crl.pem

	echo "port $PORT" >/etc/openvpn/server.conf
	if [[ $IPV6_SUPPORT == 'n' ]]; then
		echo "proto $PROTOCOL" >>/etc/openvpn/server.conf
	else
		echo "proto ${PROTOCOL}6" >>/etc/openvpn/server.conf
	fi

	echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3" >>/etc/openvpn/server.conf

	# DNS
	case $DNS in
	1)
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
			if [[ $line =~ ^[0-9.]*$ ]] || [[ $IPV6_SUPPORT == 'y' ]]; then
				echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
			fi
		done
		;;
	2)
		echo 'push "dhcp-option DNS 10.8.0.1"' >>/etc/openvpn/server.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'push "dhcp-option DNS fd42:42:42:42::1"' >>/etc/openvpn/server.conf
		fi
		;;
	3)
		echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server.conf
		;;
	4)
		echo 'push "dhcp-option DNS 9.9.9.9"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.112"' >>/etc/openvpn/server.conf
		;;
	5)
		echo 'push "dhcp-option DNS 9.9.9.10"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.10"' >>/etc/openvpn/server.conf
		;;
	6)
		echo 'push "dhcp-option DNS 80.67.169.40"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 80.67.169.12"' >>/etc/openvpn/server.conf
		;;
	7)
		echo 'push "dhcp-option DNS 84.200.69.80"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 84.200.70.40"' >>/etc/openvpn/server.conf
		;;
	8)
		echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server.conf
		;;
	9)
		echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server.conf
		;;
	10)
		echo 'push "dhcp-option DNS 77.88.8.8"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 77.88.8.1"' >>/etc/openvpn/server.conf
		;;
	11)
		echo 'push "dhcp-option DNS 94.140.14.14"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 94.140.15.15"' >>/etc/openvpn/server.conf
		;;
	12)
		echo 'push "dhcp-option DNS 45.90.28.167"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 45.90.30.167"' >>/etc/openvpn/server.conf
		;;
	13)
		echo "push \"dhcp-option DNS $DNS1\"" >>/etc/openvpn/server.conf
		if [[ $DNS2 != "" ]]; then
			echo "push \"dhcp-option DNS $DNS2\"" >>/etc/openvpn/server.conf
		fi
		;;
	esac

	echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf

	# IPv6
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6
push "route-ipv6 2000::/3"
push "redirect-gateway ipv6"' >>/etc/openvpn/server.conf
	fi

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/server.conf
	fi

	if [[ $DH_TYPE == "1" ]]; then
		echo "dh none" >>/etc/openvpn/server.conf
		echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf
	else
		echo "dh dh.pem" >>/etc/openvpn/server.conf
	fi

	case $TLS_SIG in
	1)
		echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server.conf
		;;
	2)
		echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server.conf
		;;
	esac

	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
client-to-client
# See CCD for behind-client subnets
" >>/etc/openvpn/server.conf

	echo "net.ipv4.ip_forward=1" >/etc/sysctl.d/99-openvpn.conf
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "net.ipv6.conf.all.forwarding=1" >>/etc/sysctl.d/99-openvpn.conf
	fi
	sysctl --system

	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ $PORT != '1194' ]]; then
				semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
			fi
		fi
	fi

	if [[ $OS == 'arch' || $OS == 'fedora' || $OS == 'centos' || $OS == 'oracle' ]]; then
		cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn-server@.service
		if [[ $OS == "fedora" ]]; then
			sed -i 's|--cipher AES-256-GCM.*||' /etc/systemd/system/openvpn-server@.service
		fi
		systemctl daemon-reload
		systemctl enable openvpn-server@server
		systemctl restart openvpn-server@server
	elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
		systemctl enable openvpn
		systemctl start openvpn
	else
		cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service
		systemctl daemon-reload
		systemctl enable openvpn@server
		systemctl restart openvpn@server
	fi

	if [[ $DNS == 2 ]]; then
		installUnbound
	fi

	mkdir -p /etc/iptables
	cat <<EOF >/etc/iptables/add-openvpn-rules.sh
#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT
EOF

	if [[ $IPV6_SUPPORT == 'y' ]]; then
		cat <<EOF >>/etc/iptables/add-openvpn-rules.sh
ip6tables -t nat -I POSTROUTING 1 -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -I INPUT 1 -i tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT
EOF
	fi

	cat <<EOF >/etc/iptables/rm-openvpn-rules.sh
#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT
EOF

	if [[ $IPV6_SUPPORT == 'y' ]]; then
		cat <<EOF >>/etc/iptables/rm-openvpn-rules.sh
ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT
ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT
EOF
	fi

	chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh

	cat <<EOF >/etc/systemd/system/iptables-openvpn.service
[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn

	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi

	echo "client" >/etc/openvpn/client-template.txt
	if [[ $PROTOCOL == 'udp' ]]; then
		echo "proto udp" >>/etc/openvpn/client-template.txt
		echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt
	else
		echo "proto tcp-client" >>/etc/openvpn/client-template.txt
	fi

	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns
verb 3" >>/etc/openvpn/client-template.txt

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/client-template.txt
	fi

	newClient
	echo "If you want to add more clients, simply run this script again!"
}

#
# Ask user if they want a behind-the-client network (CCD)
# If yes, create or update /etc/openvpn/ccd/<clientName> with 'iroute ...',
# and also add 'route ...' lines to server.conf
#
function askAndCreateCCD() {
	local userName="$1"
	echo ""
	echo "Would you like to define a behind-the-client local network for $userName? [y/n]"
	read -rp "e.g. 192.168.10.0/255.255.255.0 for site-to-site or LAN sharing: " -e ccdChoice
	if [[ "$ccdChoice" != "y" ]]; then
		return 0
	fi

	echo ""
	echo "Enter the local network and mask you want to route (e.g. 192.168.10.0 255.255.255.0)."
	read -rp "Local network IP (e.g. 192.168.10.0): " localNetIp
	read -rp "Local network mask (e.g. 255.255.255.0): " localNetMask

	mkdir -p /etc/openvpn/ccd
	local ccdFile="/etc/openvpn/ccd/$userName"
	if [[ -f "$ccdFile" ]]; then
		echo "Updating existing CCD file: $ccdFile"
	else
		echo "Creating new CCD file: $ccdFile"
	fi

	sed -i '/^iroute /d' "$ccdFile" 2>/dev/null
	echo "iroute $localNetIp $localNetMask" >>"$ccdFile"

	# Add route to server.conf if not present
	if ! grep -q "route $localNetIp $localNetMask" /etc/openvpn/server.conf 2>/dev/null; then
		echo "route $localNetIp $localNetMask" >>/etc/openvpn/server.conf
	fi

	echo ""
	echo "Do you want to push this route to all other VPN clients? [y/n]"
	read -rp "Push route for other clients? " -e pushRouteChoice
	if [[ "$pushRouteChoice" == "y" ]]; then
		local pushLine="push \"route $localNetIp $localNetMask\""
		if ! grep -q "$pushLine" /etc/openvpn/server.conf 2>/dev/null; then
			echo "$pushLine" >>/etc/openvpn/server.conf
		fi
	fi

	echo ""
	echo "Restarting OpenVPN to apply route changes..."
	if [[ -f /etc/systemd/system/openvpn-server@.service ]]; then
		systemctl restart openvpn-server@server
	else
		systemctl restart openvpn@server
	fi

	echo "CCD for '$userName' updated. The local subnet behind $userName is accessible."
}

function newClient() {
	echo ""
	echo "Enter a name for the client (alphanumeric, underscore, or dash)."
	until [[ $CLIENT =~ ^[a-zA-Z0-9_-]+$ ]]; do
		read -rp "Client name: " -e CLIENT
	done

	echo ""
	echo "Do you want to protect the .ovpn with a password? (Encrypt the private key)"
	echo "   1) Passwordless"
	echo "   2) Password-protected"
	until [[ $PASS =~ ^[1-2]$ ]]; do
		read -rp "Choose [1-2]: " -e -i 1 PASS
	done

	local CLIENTEXISTS
	CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=$CLIENT\$")
	if [[ $CLIENTEXISTS == '1' ]]; then
		echo ""
		echo "Client '$CLIENT' already exists in the PKI. Choose another name or revoke it first."
		exit
	else
		cd /etc/openvpn/easy-rsa/ || return
		case $PASS in
		1)
			./easyrsa build-client-full "$CLIENT" nopass
			;;
		2)
			echo "⚠️ You will be asked for the client password below."
			./easyrsa build-client-full "$CLIENT"
			;;
		esac
		echo "Client $CLIENT added."
	fi

	# If user wants behind-the-client network
	askAndCreateCCD "$CLIENT"

	# Determine home directory for the .ovpn
	local homeDir
	if [ -e "/home/${CLIENT}" ]; then
		homeDir="/home/${CLIENT}"
	elif [ "${SUDO_USER}" ]; then
		if [ "${SUDO_USER}" == "root" ]; then
			homeDir="/root"
		else
			homeDir="/home/${SUDO_USER}"
		fi
	else
		homeDir="/root"
	fi

	# Check if we use tls-crypt or tls-auth
	if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
		TLS_SIG="1"
	elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
		TLS_SIG="2"
	fi

	cp /etc/openvpn/client-template.txt "$homeDir/$CLIENT.ovpn"
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
		echo "</key>"

		if [[ $TLS_SIG == "1" ]]; then
			echo "<tls-crypt>"
			cat /etc/openvpn/tls-crypt.key
			echo "</tls-crypt>"
		else
			echo "key-direction 1"
			echo "<tls-auth>"
			cat /etc/openvpn/tls-auth.key
			echo "</tls-auth>"
		fi
	} >>"$homeDir/$CLIENT.ovpn"

	echo ""
	echo "Configuration file: $homeDir/$CLIENT.ovpn"
	echo "Please download it and import into your OpenVPN client."
	exit 0
}

function revokeClient() {
	local NUMBEROFCLIENTS
	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ $NUMBEROFCLIENTS == '0' ]]; then
		echo ""
		echo "No existing clients found!"
		exit 1
	fi

	echo ""
	echo "Select the client certificate to revoke:"
	tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
	local CLIENTNUMBER
	until [[ $CLIENTNUMBER -ge 1 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
		read -rp "Client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
	done
	local CLIENT
	CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)

	cd /etc/openvpn/easy-rsa/ || return
	./easyrsa --batch revoke "$CLIENT"
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	rm -f /etc/openvpn/crl.pem
	cp pki/crl.pem /etc/openvpn/crl.pem
	chmod 644 /etc/openvpn/crl.pem
	find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
	rm -f "/root/$CLIENT.ovpn"
	sed -i "/^$CLIENT,.*/d" /etc/openvpn/ipp.txt

	echo ""
	echo "Certificate for client '$CLIENT' revoked."
}

function removeUnbound() {
	sed -i '/include: \/etc\/unbound\/openvpn.conf/d' /etc/unbound/unbound.conf
	rm -f /etc/unbound/openvpn.conf

	until [[ $REMOVE_UNBOUND =~ (y|n) ]]; do
		echo ""
		echo "If you were already using Unbound, we only removed the OpenVPN part."
		read -rp "Completely remove Unbound? [y/n]: " -e REMOVE_UNBOUND
	done

	if [[ $REMOVE_UNBOUND == 'y' ]]; then
		systemctl stop unbound
		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get remove --purge -y unbound
		elif [[ $OS == 'arch' ]]; then
			pacman --noconfirm -R unbound
		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum remove -y unbound
		elif [[ $OS == 'fedora' ]]; then
			dnf remove -y unbound
		fi
		rm -rf /etc/unbound/
		echo ""
		echo "Unbound removed!"
	else
		systemctl restart unbound
		echo ""
		echo "Unbound left intact."
	fi
}

function removeOpenVPN() {
	echo ""
	read -rp "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
	if [[ $REMOVE == 'y' ]]; then
		local PORT
		PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
		local PROTOCOL
		PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)

		if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
			systemctl disable openvpn-server@server
			systemctl stop openvpn-server@server
			rm -f /etc/systemd/system/openvpn-server@.service
		elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
			systemctl disable openvpn
			systemctl stop openvpn
		else
			systemctl disable openvpn@server
			systemctl stop openvpn@server
			rm -f /etc/systemd/system/openvpn\@.service
		fi

		systemctl stop iptables-openvpn
		systemctl disable iptables-openvpn
		rm -f /etc/systemd/system/iptables-openvpn.service
		systemctl daemon-reload
		rm -f /etc/iptables/add-openvpn-rules.sh
		rm -f /etc/iptables/rm-openvpn-rules.sh

		if hash sestatus 2>/dev/null; then
			if sestatus | grep "Current mode" | grep -qs "enforcing"; then
				if [[ $PORT != '1194' ]]; then
					semanage port -d -t openvpn_port_t -p "$PROTOCOL" "$PORT"
				fi
			fi
		fi

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get remove --purge -y openvpn
			if [[ -e /etc/apt/sources.list.d/openvpn.list ]]; then
				rm -f /etc/apt/sources.list.d/openvpn.list
				apt-get update
			fi
		elif [[ $OS == 'arch' ]]; then
			pacman --noconfirm -R openvpn
		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum remove -y openvpn
		elif [[ $OS == 'fedora' ]]; then
			dnf remove -y openvpn
		fi

		find /home/ -maxdepth 2 -name "*.ovpn" -delete
		find /root/ -maxdepth 1 -name "*.ovpn" -delete
		rm -rf /etc/openvpn
		rm -rf /usr/share/doc/openvpn*
		rm -f /etc/sysctl.d/99-openvpn.conf
		rm -rf /var/log/openvpn

		if [[ -e /etc/unbound/openvpn.conf ]]; then
			removeUnbound
		fi
		echo ""
		echo "OpenVPN removed!"
	else
		echo ""
		echo "Removal aborted!"
	fi
}

#
# Add/Update CCD for an existing user
#
function addCcdToExistingClient() {
	local NUMBEROFCLIENTS
	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ $NUMBEROFCLIENTS == '0' ]]; then
		echo ""
		echo "No existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client to add/update a behind-client network (CCD):"
	tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
	local CLIENTNUMBER
	until [[ $CLIENTNUMBER -ge 1 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
		read -rp "Client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
	done
	local clientName
	clientName=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
	echo "You chose: $clientName"

	askAndCreateCCD "$clientName"
}

### PORT FORWARDING START
# Helper to parse /etc/openvpn/ipp.txt to find a client's IP
function getClientIPByName() {
	local name="$1"
	local ipFile="/etc/openvpn/ipp.txt"
	if [[ ! -f "$ipFile" ]]; then
		echo ""
		return
	fi
	local line
	line=$(grep "^${name}," "$ipFile" 2>/dev/null)
	if [[ -z "$line" ]]; then
		echo ""
	else
		echo "$line" | cut -d',' -f2
	fi
}

# List forwarded ports by scanning add-openvpn-rules.sh for lines with DNAT
function listForwardedPorts() {
	echo ""
	echo "Currently forwarded ports (from add-openvpn-rules.sh):"
	if ! grep -q "DNAT --to" /etc/iptables/add-openvpn-rules.sh 2>/dev/null; then
		echo "  None."
		return
	fi
	grep "DNAT --to" /etc/iptables/add-openvpn-rules.sh | while read -r line; do
		local proto port dest
		proto=$(echo "$line" | grep -oP "(?<=-p )\S+")
		port=$(echo "$line" | grep -oP "(?<=--dport )\d+")
		dest=$(echo "$line" | grep -oP "(?<=--to )\S+")
		echo "  Forwarding port $port/$proto -> $dest"
	done
}

# Add a new TCP port-forward rule
function addForwardedPort() {
	echo ""
	echo "Enter the existing client name (CN) to forward a port to:"
	read -rp "Client name: " clientName

	local clientIp
	clientIp=$(getClientIPByName "$clientName")
	if [[ -z "$clientIp" ]]; then
		echo "No static IP found in /etc/openvpn/ipp.txt for $clientName."
		echo "Enter the client VPN IP manually (e.g. 10.8.0.10):"
		read -rp "Client IP: " clientIp
	fi

	echo "Which TCP port on the server do you want to forward?"
	read -rp "Port number (1-65535): " forwardPort

	# Check if already in use
	if grep -qE "dport $forwardPort " /etc/iptables/add-openvpn-rules.sh; then
		echo "Port $forwardPort is already forwarded. Aborting."
		return
	fi

	# Add to add-openvpn-rules.sh
	echo "iptables -t nat -A PREROUTING -p tcp --dport $forwardPort -j DNAT --to $clientIp" \
		>> /etc/iptables/add-openvpn-rules.sh

	# Add to rm-openvpn-rules.sh
	echo "iptables -t nat -D PREROUTING -p tcp --dport $forwardPort -j DNAT --to $clientIp" \
		>> /etc/iptables/rm-openvpn-rules.sh

	# Apply now
	iptables -t nat -A PREROUTING -p tcp --dport "$forwardPort" -j DNAT --to "$clientIp"

	echo "Port $forwardPort (TCP) forwarded to $clientIp."
}

# Remove a TCP port-forward rule
function removeForwardedPort() {
	echo ""
	echo "Enter the TCP port you wish to un-forward:"
	read -rp "Port number: " forwardPort

	# Find line
	local lineInAdd
	lineInAdd=$(grep "dport $forwardPort " /etc/iptables/add-openvpn-rules.sh 2>/dev/null)
	if [[ -z "$lineInAdd" ]]; then
		echo "No rule found for port $forwardPort."
		return
	fi

	local clientIp
	clientIp=$(echo "$lineInAdd" | grep -oP "(?<=--to )\S+")

	# Remove from add-openvpn-rules.sh
	sed -i "/dport $forwardPort .*--to $clientIp/d" /etc/iptables/add-openvpn-rules.sh
	# Remove from rm-openvpn-rules.sh
	sed -i "/dport $forwardPort .*--to $clientIp/d" /etc/iptables/rm-openvpn-rules.sh

	# Remove from current iptables
	iptables -t nat -D PREROUTING -p tcp --dport "$forwardPort" -j DNAT --to "$clientIp" 2>/dev/null

	echo "Port $forwardPort forwarding to $clientIp removed."
}

function managePortForwarding() {
	while true; do
		echo ""
		echo "Port Forwarding Menu"
		echo "   1) List existing forwarded ports"
		echo "   2) Add a new forwarded port"
		echo "   3) Remove a forwarded port"
		echo "   4) Return to main menu"

		read -rp "Option [1-4]: " PF_OPTION
		case $PF_OPTION in
			1)
				listForwardedPorts
				;;
			2)
				addForwardedPort
				;;
			3)
				removeForwardedPort
				;;
			4)
				break
				;;
			*)
				echo "Invalid option."
				;;
		esac
	done
}
### PORT FORWARDING END

function manageMenu() {
	echo "Welcome to OpenVPN-install!"
	echo "The git repository is: https://github.com/angristan/openvpn-install"
	echo ""
	echo "It looks like OpenVPN is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) Revoke an existing user"
	echo "   3) Add/Update CCD for an existing user (behind-client network)"
	echo "   4) Remove OpenVPN"
	echo "   5) Exit"
	### PORT FORWARDING
	echo "   6) Manage port forwarding"

	local MENU_OPTION
	until [[ $MENU_OPTION =~ ^[1-6]$ ]]; do
		read -rp "Select an option [1-6]: " MENU_OPTION
	done

	case $MENU_OPTION in
	1)
		newClient
		;;
	2)
		revokeClient
		;;
	3)
		addCcdToExistingClient
		;;
	4)
		removeOpenVPN
		;;
	5)
		exit 0
		;;
	6)
		managePortForwarding
		;;
	esac
}

#
# MAIN
#
initialCheck

# If server.conf exists, presumably OpenVPN is installed:
if [[ -e /etc/openvpn/server.conf && $AUTO_INSTALL != "y" ]]; then
	manageMenu
else
	installOpenVPN
fi
