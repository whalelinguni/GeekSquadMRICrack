import os
import hashlib
import time
from colorama import init, Fore

"""
Patcher Script for MRI Tools
- Removes Expiration check
- Disables 'call home' ping 

Usage:
1. Copy this script to the MRI directory where the 'GSCommon.dll' and 'desktop_information.dll' files are located.
2. Run the script:

   python MRI-Patch-Tool_WL_v4.20.py

The script will automatically patch the necessary files and notify you of the patch status.

--Whale Linguini
"""

init(autoreset=True)
GSCommon_path = 'GSCommon.dll'
Desktop_info_path = 'desktop_information.dll'
EXPECTED_HASHES_BEFORE = {
    GSCommon_path: "74B30100B40D7F0F7B5545AE8DF6583E33D49DA41E68BD8104C8C173E5B350FB",
    Desktop_info_path: "A96B783FA1EAF1A76A82D55FD67A2FE1BFA2E418C354F1C8FBEADA69CD579949"
}

EXPECTED_HASHES_AFTER = {
    GSCommon_path: "AD8B0E095DD7A488A7CA9A212A655E86BE216D01F3B5299AB33E249FB6EE3C39",
    Desktop_info_path: "43563B5A482D6545A67D92356C109C2D8F797A11944E67BA30A297CB58D03DF0"
}
REPLACEMENTS_DESKTOP_INFO = {
    'geeksquadcentral.com': 'localhost',
    'geeksquadlabs.com': 'localhost'
}
REPLACEMENTS_GSCOMMON = {
    'geeksquadcentral.com': 'localhost'
}

def clear_console():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest().upper()
def check_files_exist():
    missing_files = []
    if not os.path.isfile(GSCommon_path):
        missing_files.append(GSCommon_path)
    if not os.path.isfile(Desktop_info_path):
        missing_files.append(Desktop_info_path)

    if missing_files:
        print(f"{Fore.RED}[ERROR] Missing files: {', '.join(missing_files)}")
        print(f"{Fore.YELLOW}[INFO] Please place this script in the same directory as 'GSCommon.dll' and 'desktop_information.dll', then run it again.")
        pause_exit()
        return False
    return True
def pause_exit():
    input(f"\n{Fore.CYAN}Press any key to exit...")
def check_initial_hashes():
    files_already_patched = True
    for file_path, expected_before_hash in EXPECTED_HASHES_BEFORE.items():
        current_hash = calculate_file_hash(file_path)
        expected_after_hash = EXPECTED_HASHES_AFTER[file_path]

        print(f"\n### Checking initial hash for {file_path} ###")
        print(f"\tExpected 'Before' Hash: {expected_before_hash}")
        print(f"\tExpected 'After' Hash:  {expected_after_hash}")
        print(f"\tCalculated Hash:         {current_hash}")

        if current_hash == expected_before_hash:
            print(f"\t{Fore.GREEN}[INFO] The file '{file_path}' matches the 'before patch' hash.")
            files_already_patched = False  # File is not yet patched, so continue patching.
        elif current_hash == expected_after_hash:
            print(f"\t{Fore.YELLOW}[INFO] The file '{file_path}' matches the 'after patch' hash. It may already be patched.")
        else:
            print(f"\t{Fore.RED}[WARNING] The file '{file_path}' hash does not match either the 'before' or 'after' expected hash.")

    if files_already_patched:
        while True:
            user_input = input(f"{Fore.CYAN}Files appear to be already patched. Do you want to force patch them again? (Y/N): ").strip().lower()
            if user_input == 'y':
                print(f"{Fore.GREEN}Forcing patch...\n")
                break
            elif user_input == 'n':
                print(f"{Fore.RED}Exiting...\n")
                pause_exit()
                sys.exit(0)
            else:
                print(f"{Fore.YELLOW}Invalid input. Please enter 'Y' for yes or 'N' for no.")
def validate_post_patch_hashes():
    for file_path, expected_after_hash in EXPECTED_HASHES_AFTER.items():
        post_patch_hash = calculate_file_hash(file_path)
        print(f"\n### Checking post-patch hash for {file_path} ###")
        print(f"\tExpected 'After' Hash: {expected_after_hash}")
        print(f"\tCalculated Hash:       {post_patch_hash}")

        if post_patch_hash == expected_after_hash:
            print(f"\t{Fore.GREEN}[INFO] File '{file_path}' hash matches the expected 'after patch' hash.\n")
        else:
            print(f"\t{Fore.RED}[WARNING] Post-patch hash for '{file_path}' does not match the expected 'after patch' hash!\n")
def patch_dll(dll_path, old_byte, new_byte, offset):
    old_byte = bytes([old_byte])
    new_byte = bytes([new_byte])

    print(f"### Patching Byte Data {dll_path} ###")
    print(f"--- Disable Expiration ---")
    time.sleep(0.6)
    print(f"\tTarget DLL: {dll_path}")
    print(f"\tExpected Byte: 0x{old_byte.hex().upper()}")
    print(f"\tNew Byte:      0x{new_byte.hex().upper()}")
    print(f"\tOffset:        0x{offset:X}\n")

    if not os.path.isfile(dll_path):
        print(f"{Fore.RED}[ERROR] File '{dll_path}' does not exist.")
        pause_exit()
        return

    file_size = os.path.getsize(dll_path)
    print(f"\t{Fore.CYAN}[INFO] File Size: {file_size} bytes")

    if offset >= file_size:
        print(f"\t{Fore.RED}[ERROR] Offset 0x{offset:X} is out of the file's range.")
        pause_exit()
        return

    with open(dll_path, "r+b") as f:
        f.seek(offset)
        current_byte = f.read(1)
        print(f"\t{Fore.CYAN}[INFO] Current Byte at 0x{offset:X}: 0x{current_byte.hex().upper()}")

        if current_byte == old_byte:
            f.seek(offset)
            f.write(new_byte)
            print(f"\t{Fore.GREEN}[SUCCESS] Byte at offset 0x{offset:X} patched from 0x{old_byte.hex().upper()} to 0x{new_byte.hex().upper()}.\n")
        elif current_byte == new_byte:
            print(f"\t{Fore.YELLOW}[INFO] The file is already patched. Byte at offset 0x{offset:X} is already 0x{new_byte.hex().upper()}.\n")
        else:
            print(f"\t{Fore.YELLOW}[WARNING] Byte at offset 0x{offset:X} does not match the expected value 0x{old_byte.hex().upper()}.")
            print(f"\t\tCurrent value is 0x{current_byte.hex().upper()}.\n")
def replace_in_binary(file_path, keyword, replace_word):
    keyword_bytes = keyword.encode('utf-16le')
    replace_bytes = replace_word.encode('utf-16le')

    with open(file_path, 'rb') as f:
        binary_data = f.read()

    occurrences = binary_data.count(keyword_bytes)
    if occurrences == 0:
        print(f"\t{Fore.YELLOW}[WARNING] No occurrences of '{keyword}' (UTF-16) found in the binary. The file might already be patched or incorrect.")
        return False

    print(f"\t{Fore.GREEN}[INFO] Found {occurrences} occurrences of '{keyword}' (UTF-16).")

    modified_binary_data = binary_data.replace(keyword_bytes, replace_bytes + b'\x00' * (len(keyword_bytes) - len(replace_bytes)))

    with open(file_path, 'wb') as f:
        f.write(modified_binary_data)

    print(f"\t{Fore.GREEN}[SUCCESS] Replaced occurrences of '{keyword}' with '{replace_word}' in the binary.")
    return True
def replace_strings_in_dlls():
    for dll in [GSCommon_path, Desktop_info_path]:
        print(f"\n### Patching String Data {dll} ###")
        print(f"--- Disable Callhome Ping ---")
        time.sleep(0.6)
        replacements = REPLACEMENTS_GSCOMMON if dll == GSCommon_path else REPLACEMENTS_DESKTOP_INFO

        for keyword, replace_word in replacements.items():
            replace_in_binary(dll, keyword, replace_word)

def prompt_user_to_continue():
    while True:
        user_input = input(f"{Fore.CYAN}Do patch? (Y/N): ").strip().lower()
        if user_input == 'y':
            print(f"{Fore.GREEN}Starting Patch!...\n")
            break
        elif user_input == 'n':
            print(f"{Fore.RED}Kthxbye. Exiting...\n")
            pause_exit()
            sys.exit(0)
        else:
            print(f"{Fore.YELLOW}Invalid input. Please enter 'Y' for yes or 'N' for no.\n")
            print("You punish for dumb. Wait 30 seconds.")
            time.sleep(42)

if __name__ == "__main__":
    if not check_files_exist():
        sys.exit(1)
    print("Checking files...")
    print("-------------------------------------------")
    check_initial_hashes()
    time.sleep(2)
    clear_console()
    
    print(r"   _______  _______  _______  ___   _    _______  _______  __   __  _______  ______  ")
    print(r"  |       ||       ||       ||   | | |  |       ||       ||  | |  ||   _   ||      | ")
    print(r"  |    ___||    ___||    ___||   |_| |  |  _____||   _   ||  | |  ||  |_|  ||  _    |")
    print(r"  |   | __ |   |___ |   |___ |      _|  | |_____ |  | |  ||  |_|  ||       || | |   |")
    print(r"  |   ||  ||    ___||    ___||     |_   |_____  ||  |_|  ||       ||       || |_|   |")
    print(r"  |   |_| ||   |___ |   |___ |    _  |   _____| ||      | |       ||   _   ||       |")
    print(r"  |_______||_______||_______||___| |_|  |_______||____||_||_______||__| |__||______| ")
    print(r"")
    print(r" __   __  ______    ___     _______  _______  _______  _______  __   __  _______  ______   ")
    print(r"|  |_|  ||    _ |  |   |   |       ||   _   ||       ||       ||  | |  ||       ||    _ |  ")
    print(r"|       ||   | ||  |   |   |    _  ||  |_|  ||_     _||       ||  |_|  ||    ___||   | ||  ")
    print(r"|       ||   |_||_ |   |   |   |_| ||       |  |   |  |       ||       ||   |___ |   |_||_ ")
    print(r"|       ||    __  ||   |   |    ___||       |  |   |  |      _||       ||    ___||    __  |")
    print(r"| ||_|| ||   |  | ||   |   |   |    |   _   |  |   |  |     |_ |   _   ||   |___ |   |  | |")
    print(r"|_|   |_||___|  |_||___|   |___|    |__| |__|  |___|  |_______||__| |__||_______||___|  |_|")
    print(r"                                                                        --Whale Linguini")
    print("--------------------------------------------------------------------------------------------\n")
    prompt_user_to_continue()
    time.sleep(1.8)
    patch_dll(GSCommon_path, old_byte=0x74, new_byte=0x75, offset=0x2DA11)
    replace_strings_in_dlls()
    validate_post_patch_hashes()

    print(f"\n{Fore.GREEN}### All operations completed successfully! ###")
    pause_exit()
