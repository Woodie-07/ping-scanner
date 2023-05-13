# pingscanner

A quick website I threw together in a couple hours. Scans a subnet for hosts that respond to ICMP pings and plots them on a Hilbert curve.
I'm aware that the code isn't great, but it works.

## Warning!
Scanning the internet, even just with ICMP pings, can result in abuse reports. Use at your own risk. I recommend [pfcloud.io](https://pfcloud.io) for scanning the internet, they won't give you any hassle about abuse reports. I use pfcloud for hosting my own scanner.

## Usage
1. Clone the repo
2. Install requirements with `pip install -r requirements.txt`
3. Clone [ipv4-heatmap](https://github.com/measurement-factory/ipv4-heatmap) into ipv4-heatmap/ with `git clone https://github.com/measurement-factory/ipv4-heatmap.git`
4. Install masscan and dependencies for ipv4-heatmap with `apt install build-essential libgd-dev masscan libpcap0.8`
5. Compile ipv4-heatmap with `make` in the ipv4-heatmap/ directory
6. Copy config.py.example to config.py
7. Edit `config.py` to your liking. Include your own SQL database credentials and optionally tweak the scanning rate calculation function and/or enter your own listen host/port.
8. Run `python3 main.py` to start the webserver
