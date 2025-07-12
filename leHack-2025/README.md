
# "Phishing detection and investigation with OSINT feeds and free softwares" - LeHack 2025

Event URL: https://lehack.org/2025/tracks/workshops/#using-osint-to-detect-and-track-phishing-campaigns
Short workshop presentation: https://github.com/StalkPhish/workshops/blob/main/leHack-2025/Stalkphish-LeHack-WorkShop-2025.pdf


### Get tools

> The commands shown are based on a Linux Debian/Ubuntu installation, to be adapted according to the system used

    /opt$ git clone https://github.com/t4d/StalkPhish-OSS
    /opt$ git clone https://github.com/t4d/PhishingKit-Yara-Rules
    /opt$ git clone https://github.com/t4d/PhishingKit-Yara-Search
    /opt$ sudo apt install clamav

# Install and activate Python3 Virtual Environment

    /opt$ sudo apt install python3-virtualenv git python3-pip
    /opt$ . /opt/venv/bin/activate

-> install pip packages of each tool (as: pip install -r requirements.txt)

# Install Tor

> For a minimum of anonymity, I advise you not to connect directly to phishing sites.

    /opt$ sudo apt install tor

-> or use your own anonymizaton/private network (to configure in StalkPhish-OSS config file)

# Check StalkPhish-OSS configuration
Default (example.conf) used:

 - adapt your search keywords
 - "/opt/StalkPhish/..." as default paths
 - Tor by default, as "socks5://127.0.0.1:9050)"
 - all "free" feeds are activated

-> create/use your own API keys for your tests 



# Cheat sheet

## StalkPhish-OSS 
### launch with specific configuration file

    python3 StalkPhish.py -c conf/example.conf

### try to download phishing kits (-G), don't search on OSINT feeds (-N)

    python3 StalkPhish.py -c conf/example.conf -G -N

### specific keyword search (-s):

    StalkPhish.py -c conf/example.conf -s office365

### add a URL in database (-u)

    StalkPhish.py -c conf/example.conf -u https://bmh.lzi.mybluehost.me/CA/


## PhishingKit-Yara-Search
### one rule on one file

    python3 PhishingKit-Yara-Search.py -r /opt/PhishingKit-Yara-Rules/PK_PayPal_H3ATSTR0K3.yar -f /opt/StalkPhish-OSS/stalkphish/dl/{ZIP_FILE}

### one rule on a directory containing several zip files

    python3 PhishingKit-Yara-Search.py -r /opt/PhishingKit-Yara-Rules/PK_PayPal_H3ATSTR0K3.yar -D /opt/StalkPhish-OSS/stalkphish/dl/

### all rules on a directory containing several zip files

    python3 PhishingKit-Yara-Search.py -r /opt/PhishingKit-Yara-Rules/ -D /opt/StalkPhish-OSS/stalkphish/dl/

## ClamAV

    clamscan -d /opt/PhishingKit-Yara-Rules/ /opt/StalkPhish-OSS/stalkphish/dl/

