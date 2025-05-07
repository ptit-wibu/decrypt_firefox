#!/usr/bin/env python3
import ctypes as ct
import json
import os
import sys
from base64 import b64decode
from getpass import getpass
import logging
import platform
import configparser

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)

DEFAULT_ENCODING = "utf-8"

class NSSProxy:
    class SECItem(ct.Structure):
        _fields_ = [
            ("type", ct.c_uint),
            ("data", ct.c_char_p),
            ("len", ct.c_uint),
        ]

        def decode_data(self):
            return ct.string_at(self.data, self.len).decode(DEFAULT_ENCODING)

    class PK11SlotInfo(ct.Structure):
        pass

    def __init__(self):
        self.libnss = self.load_nss()
        SlotInfoPtr = ct.POINTER(self.PK11SlotInfo)
        SECItemPtr = ct.POINTER(self.SECItem)

        self._set_ctypes(ct.c_int, "NSS_Init", ct.c_char_p)
        self._set_ctypes(ct.c_int, "NSS_Shutdown")
        self._set_ctypes(SlotInfoPtr, "PK11_GetInternalKeySlot")
        self._set_ctypes(None, "PK11_FreeSlot", SlotInfoPtr)
        self._set_ctypes(ct.c_int, "PK11_NeedLogin", SlotInfoPtr)
        self._set_ctypes(ct.c_int, "PK11_CheckUserPassword", SlotInfoPtr, ct.c_char_p)
        self._set_ctypes(ct.c_int, "PK11SDR_Decrypt", SECItemPtr, SECItemPtr, ct.c_void_p)
        self._set_ctypes(None, "SECITEM_ZfreeItem", SECItemPtr, ct.c_int)

    def _set_ctypes(self, restype, name, *argtypes):
        res = getattr(self.libnss, name)
        res.argtypes = argtypes
        res.restype = restype
        setattr(self, "_" + name, res)

    def load_nss(self):
        if platform.system() == "Windows":
            possible_paths = [
                r"C:\Program Files\Mozilla Firefox\nss3.dll",
                r"C:\Program Files (x86)\Mozilla Firefox\nss3.dll"
            ]
            firefox_paths = [
                r"C:\Program Files\Mozilla Firefox",
                r"C:\Program Files (x86)\Mozilla Firefox"
            ]

            for nss_path, firefox_path in zip(possible_paths, firefox_paths):
                if os.path.exists(nss_path):
                    try:
                        os.add_dll_directory(firefox_path)
                        return ct.CDLL(nss_path)
                    except OSError:
                        LOG.error("Failed to load NSS library from %s", nss_path)
                        continue
            LOG.error("Could not find or load NSS library in any known paths")
            sys.exit(1)
        else:
            nss_path = "/usr/lib/x86_64-linux-gnu/libnss3.so"
            try:
                return ct.CDLL(nss_path)
            except OSError:
                LOG.error("Failed to load NSS library from %s", nss_path)
                sys.exit(1)

    def initialize(self, profile):
        profile_path = "sql:" + profile
        err_status = self._NSS_Init(profile_path.encode(DEFAULT_ENCODING))
        if err_status:
            LOG.error("Failed to initialize NSS with profile %s", profile)
            sys.exit(1)

    def authenticate(self, profile):
        keyslot = self._PK11_GetInternalKeySlot()
        if not keyslot:
            LOG.error("Failed to retrieve internal KeySlot")
            sys.exit(1)
        try:
            if self._PK11_NeedLogin(keyslot):
                password = getpass(f"Enter password for profile (hint: try 'labpass'): ")
                err_status = self._PK11_CheckUserPassword(keyslot, password.encode(DEFAULT_ENCODING))
                if err_status:
                    LOG.error("Incorrect password")
                    sys.exit(1)
            else:
                LOG.info("No password required")
        finally:
            self._PK11_FreeSlot(keyslot)

    def decrypt(self, data64):
        data = b64decode(data64)
        inp = self.SECItem(0, data, len(data))
        out = self.SECItem(0, None, 0)
        err_status = self._PK11SDR_Decrypt(inp, out, None)
        if err_status:
            LOG.error("Decryption failed")
            sys.exit(1)
        try:
            return out.decode_data()
        finally:
            self._SECITEM_ZfreeItem(out, 0)

    def shutdown(self):
        self._NSS_Shutdown()

def get_default_firefox_profile_path():
    if platform.system() == "Windows":
        user_profile = os.environ["USERPROFILE"]
        profiles_ini_path = os.path.join(user_profile, "AppData", "Roaming", "Mozilla", "Firefox", "profiles.ini")
    else:
        user_profile = os.environ["HOME"]
        profiles_ini_path = os.path.join(user_profile, ".mozilla", "firefox", "profiles.ini")

    config = configparser.ConfigParser()
    config.read(profiles_ini_path)

    # Ưu tiên chọn profile có hậu tố .default-release
    for section in config.sections():
        if config.has_option(section, "Path"):
            path = config.get(section, "Path")
            if ".default-release" in path:
                is_relative = config.getboolean(section, "IsRelative", fallback=True)
                if is_relative:
                    if platform.system() == "Windows":
                        return os.path.join(user_profile, "AppData", "Roaming", "Mozilla", "Firefox", path)
                    else:
                        return os.path.join(user_profile, ".mozilla", "firefox", path)
                else:
                    return path

    # Nếu không tìm thấy, dùng profile được đánh dấu Default=1
    for section in config.sections():
        if config.has_option(section, "Default") and config.get(section, "Default") == "1":
            relative_path = config.get(section, "Path")
            is_relative = config.getboolean(section, "IsRelative", fallback=True)
            if is_relative:
                if platform.system() == "Windows":
                    return os.path.join(user_profile, "AppData", "Roaming", "Mozilla", "Firefox", relative_path)
                else:
                    return os.path.join(user_profile, ".mozilla", "firefox", relative_path)
            else:
                return relative_path

    raise FileNotFoundError("Không tìm thấy profile Firefox phù hợp.")

def main():
    profile_path = get_default_firefox_profile_path()
    logins_file = os.path.join(profile_path, "logins.json")

    if not os.path.isfile(logins_file):
        LOG.error("logins.json not found in %s", profile_path)
        sys.exit(1)

    nss = NSSProxy()
    nss.initialize(profile_path)
    nss.authenticate(profile_path)

    with open(logins_file, "r") as f:
        data = json.load(f)
        logins = data.get("logins", [])

    outputs = []
    for login in logins:
        url = login["hostname"]
        try:
            username = nss.decrypt(login["encryptedUsername"])
            password = nss.decrypt(login["encryptedPassword"])
            outputs.append({"url": url, "username": username, "password": password})
        except KeyError:
            LOG.warning("Skipping invalid login entry")

    nss.shutdown()

    with open("results.txt", "w", encoding=DEFAULT_ENCODING) as f:
        for output in outputs:
            result = (
                f"URL: {output['url']}\n"
                f"Username: {output['username']}\n"
                f"Password: {output['password']}\n\n"
            )
            f.write(result)
            print(result)

    LOG.info("Results saved to results.txt")

if __name__ == "__main__":
    main()
