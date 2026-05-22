![Wifi Weevil](src/wifi-weevil-header.png)

# Wifi-Weevil

Capture a WPA2 WiFi handshake by sending a deauthentication attack to a selected access point. The WPA2 handshake can then be cracked using hashcat or a similar tool to determine the WiFi password.

## 🌐 Installation

To install WiFi Weevil, run the following. `init.sh` will install any other needed dependencies.

```bash
git clone https://github.com/antiweevil/wifi-weevil.git
cd wifi-weevil
bash init.sh
```

## 🪡 Usage

To use the program, first insert a WiFi adapter, specifically one that has packet injection capabilities. If you'd like more information about these WiFi adapters, read more at morrownr's guide [here](https://github.com/morrownr/USB-WiFi/blob/main/home/USB_WiFi_Adapters_that_are_supported_with_Linux_in-kernel_drivers.md).

Then, you may run the program with the following.
```bash
python3 weevil.py
```

Keep in mind that you may temporarily lose access to WiFi while the program is running, as your adapter is set to monitor mode to capture handshakes.

You can also run the program with arguments. The following is a description of each argument and its function.

+ `-s`, `--start`
    + Start the WiFi Weevil program. This functions the same as running the program with no arguments.
+ `-r`, `--reconnect`
    + If you lose WiFi, and the program is no longer running, this command will restart your wireless connection and stop monitoring mode on your WiFi adapter.
+ `-t`, `--time`
    + Manually override the amount of time reserved for access point scanning. If increased from the default of 8 seconds, the program will spend more time searching for APs before timing out or retrying.
+ `-h`, `--help`
    + Print a help menu of every WiFi Weevil command/argument.

## 👋 Credits

+ **Freepik**: Beetle icon in the header
    + Available at [flaticon.com](https://www.flaticon.com/free-icon/beetle_1853888).

## ‼️ Disclaimer

Never use this program or any of its components on machines or networks you do not own or have explicit permission to use. I am not responsible for any damages.