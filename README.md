OpenVPN Installer & Manager Script

This repository provides a single script—openvp.sh—to install and manage an OpenVPN server with features including:

    Automatic installation of OpenVPN on supported Linux distributions
    Client creation (with or without a password)
    CCD (Client Config Directory) support: easily configure subnets behind each VPN client
    Port forwarding: forward TCP ports from the server’s public IP to a client’s VPN IP
    Menu-based management for adding/revoking users, port forwarding, and more

Features

    Automated OpenVPN Installation
    Installs OpenVPN along with necessary dependencies, configures firewall rules, and sets up a secure VPN server.

    Add or Revoke VPN Clients
    Create new clients interactively (with or without password-protected keys) and revoke existing users at any time.

    CCD for Site-to-Site
    Quickly configure subnets behind individual clients (site-to-site setups). The script updates server.conf, creates a CCD file, and pushes routes if desired.

    Port Forwarding
    Forward TCP ports on the server to a specific client’s VPN IP—ideal for hosting services behind a VPN client.

    Menu-Driven
    After the first install, simply re-run the script to bring up a management menu that makes tasks quick and simple.

Supported Operating Systems

openvp.sh supports the following operating systems:

    Debian (9+)
    Ubuntu (16.04+)
    Fedora
    CentOS (7 or 8)
    Oracle Linux (8)
    Amazon Linux 2
    Arch Linux

Other derivatives (e.g., Raspbian) may also work, but have not been tested extensively.
Quick Start

    Download the script:

wget https://raw.githubusercontent.com/sameerlike141/openpvn-sameer/main/openvp.sh -O openvp.sh

Make it executable (optional step if you prefer):

chmod +x openvp.sh

Run the script as root (or with sudo):

sudo bash openvp.sh

Follow the prompts
The script will ask for network settings, DNS preferences, port number, etc., then install and configure OpenVPN automatically.

Menu usage
After the initial installation, re-run the script (sudo bash openvp.sh) to see the management menu:

    1) Add a new user
    2) Revoke existing user
    3) Add/Update CCD (behind-client network) for an existing user
    4) Remove OpenVPN
    5) Exit
    6) Manage port forwarding

How to Use the Script (Detailed)
Installation Phase

    Root / sudo is required.
    The script asks for:
        Server IP or public hostname
        Port and protocol (TCP or UDP)
        DNS choice (system resolvers, external services, or self-hosted)
        Encryption preferences (optional advanced customization)
        Compression (not recommended, but available)

It then installs all necessary packages, configures networking (including iptables rules), and generates certificates using EasyRSA.
Post-Install Management

Re-run the script:

    (1) Add a new user
    Create a client certificate/key; optionally define a local subnet behind that client (CCD).
    (2) Revoke existing user
    Revoke a certificate and remove it from the server.
    (3) Add/Update CCD
    Attach or modify a behind-the-client subnet for a user who already exists.
    (4) Remove OpenVPN
    Uninstall OpenVPN entirely and remove firewall rules.
    (5) Exit
    Close the script without making changes.
    (6) Manage port forwarding
        List existing port-forward rules
        Add a new rule (TCP port on the server → a client’s VPN IP)
        Remove an existing rule

Contributing

If you encounter issues or want to improve the script:

    Open an issue in this repository.
    Submit a pull request with proposed enhancements.

Disclaimer

    This script attempts to provide a secure default configuration, but no script can guarantee perfect security.
    Always follow best practices in server administration.
    Regularly update your OS and OpenVPN to ensure the latest patches are applied.
