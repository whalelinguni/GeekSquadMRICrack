import os
import shutil
import winreg
import psutil
import ctypes
import sys
import time
import win32security
import ntsecuritycon as con
from colorama import init, Fore, Style

"""
Script to clean up Geek Squad related files and registry entries.

Features:
- Terminates specific processes related to Geek Squad tools.
- Deletes the Geek Squad directory if it exists.
- Removes Geek Squad related registry keys and subkeys.

Dependencies:
- psutil: Used for process termination.
- pywin32: Required for adjusting registry permissions and taking ownership.
- colorama: Adds color to the terminal output for better readability.

Usage:
- Run the script with elevated privileges (Administrator) to ensure proper permission handling.
- Example: python cleanupGS.py
"""

init(autoreset=True)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if sys.version_info[0] == 3 and sys.version_info[1] >= 5:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
    else:
        raise RuntimeError("Cannot elevate to admin privileges.")

def clear_console():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def print_header(message):
    print("\n" + Fore.CYAN + Style.BRIGHT + "#" * 50)
    print(Fore.CYAN + Style.BRIGHT + f"# {message}")
    print(Fore.CYAN + Style.BRIGHT + "#" * 50 + "\n")

def terminate_processes():
    processes_to_terminate = [
        "FACE.exe",
        "FMOD.exe",
        "ProcessAnalyzer.exe",
        "StartupManager.exe",
        "SystemUpdater.exe",
        "HUD.dll"
    ]

    print_header("Terminating Processes")
    for process_name in processes_to_terminate:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == process_name:
                try:
                    proc.kill()
                    print(f"{Fore.GREEN}[SUCCESS] Process '{process_name}' (PID: {proc.info['pid']}) has been terminated.")
                except Exception as e:
                    print(f"{Fore.RED}[ERROR] Failed to terminate process '{process_name}': {e}")
                break
        else:
            print(f"{Fore.YELLOW}[SKIP] Process '{process_name}' is not running.")

def delete_geek_squad_directory():
    directory = r'C:\ProgramData\Geek Squad'
    print_header("Checking for Geek Squad Directory")

    if os.path.exists(directory):
        print(f"{Fore.CYAN}[INFO] Directory found: {directory}")
        try:
            print(f"{Fore.CYAN}[INFO] Deleting the directory and its contents...")
            shutil.rmtree(directory)
            print(f"{Fore.GREEN}[SUCCESS] Successfully deleted the directory: {directory}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to delete the directory: {directory}\n[ERROR] Reason: {e}")
    else:
        print(f"{Fore.YELLOW}[SKIP] Directory does not exist: {directory}")

def take_ownership_and_adjust_permissions(key, subkey_path):
    try:
        admin_sid = win32security.LookupAccountName("", "Administrators")[0]

        win32security.SetNamedSecurityInfo(
            subkey_path, win32security.SE_REGISTRY_KEY,
            win32security.OWNER_SECURITY_INFORMATION, admin_sid, None, None, None
        )
        print(f"{Fore.CYAN}[INFO] Ownership of '{subkey_path}' transferred to Administrators.")

        security_descriptor = win32security.GetNamedSecurityInfo(
            subkey_path, win32security.SE_REGISTRY_KEY, win32security.DACL_SECURITY_INFORMATION
        )
        dacl = security_descriptor.GetSecurityDescriptorDacl()

        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.KEY_ALL_ACCESS, admin_sid)
        win32security.SetNamedSecurityInfo(
            subkey_path, win32security.SE_REGISTRY_KEY,
            win32security.DACL_SECURITY_INFORMATION, None, None, dacl, None
        )
        print(f"{Fore.CYAN}[INFO] Successfully adjusted permissions for '{subkey_path}'.")

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to adjust permissions or take ownership for '{subkey_path}': {e}")

def delete_subkeys_and_values(key, subkey_path):
    try:
        open_subkey = winreg.OpenKey(key, subkey_path, 0, winreg.KEY_ALL_ACCESS)
        num_subkeys, num_values, _ = winreg.QueryInfoKey(open_subkey)

        for i in range(num_values):
            value_name = winreg.EnumValue(open_subkey, 0)[0]
            print(f"{Fore.CYAN}[INFO] Deleting value: {value_name}")
            winreg.DeleteValue(open_subkey, value_name)

        for i in range(num_subkeys):
            subkey_name = winreg.EnumKey(open_subkey, 0)
            print(f"{Fore.CYAN}[INFO] Deleting subkey: {subkey_name}")
            delete_subkeys_and_values(open_subkey, subkey_name)

        winreg.DeleteKey(key, subkey_path)
        print(f"{Fore.GREEN}[SUCCESS] Deleted subkey: {subkey_path}")

    except FileNotFoundError:
        print(f"{Fore.YELLOW}[SKIP] Subkey or value does not exist: {subkey_path}")
    except OSError as e:
        print(f"{Fore.RED}[ERROR] Failed to delete registry subkey {subkey_path}: {e}")

def delete_registry_key():
    key_path = r"SOFTWARE\Geek Squad"
    print_header("Checking for Geek Squad Registry Key")

    try:
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS)
        print(f"{Fore.CYAN}[INFO] Registry key found: HKEY_LOCAL_MACHINE\\{key_path}")

        take_ownership_and_adjust_permissions(winreg.HKEY_LOCAL_MACHINE, key_path)
        delete_subkeys_and_values(winreg.HKEY_LOCAL_MACHINE, key_path)

    except FileNotFoundError:
        print(f"{Fore.YELLOW}[SKIP] Registry key does not exist: HKEY_LOCAL_MACHINE\\{key_path}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Error deleting registry key HKEY_LOCAL_MACHINE\\{key_path}: {e}")

def prompt_user_to_continue():
    while True:
        user_input = input(f"{Fore.CYAN}Do you want clean? (Y/N): ").strip().lower()
        if user_input == 'y':
            print(f"{Fore.GREEN}Starting Cleanup!...\n")
            break
        elif user_input == 'n':
            print(f"{Fore.RED}Kthxbye. Exiting...\n")
            sys.exit(0)
        else:
            print(f"{Fore.YELLOW}Invalid input. Please enter 'Y' for yes or 'N' for no.\n")
            print("You punish for dumb. Wait 30 seconds.")
            time.sleep(42)

if __name__ == "__main__":
    if not is_admin():
        print(f"{Fore.RED}[ERROR] This script must be run with elevated (administrator) privileges.")
        print(f"{Fore.CYAN}[INFO] Attempting to relaunch the script as admin...")
        run_as_admin()
        sys.exit(0)
    clear_console()
    print(r" _____         _      _____               _    _____ _                     ")
    print(r"|   __|___ ___| |_   |   __|___ _ _  __ _| |  |     | |___  __ ___ ___ ___ ")
    print(r"|  |  | -_| -_| '_|  |__   | . | | ||. | . |  |   --| | -_||. |   | -_|  _|")
    print(r"|_____|___|___|_|_|  |_____|_  |___|___|___|  |_____|_|___|___|_|_|___|_|  ")
    print(r"                             |_|                                           ")
    print("------------------------------------------------------------------------------")
    prompt_user_to_continue()
    time.sleep(2)
    terminate_processes()
    delete_geek_squad_directory()
    delete_registry_key()
    print("------------------------------------------------------------------------------")
    print("")
    print(f"{Fore.GREEN}Cleanup Complete!!\n")
    print(r"8===D   8==D    8=====D 8==D   8=====D  8=D")
    print("rocket ship! rocket chsip! chsutp! rocketship!\n")
