import os
import sys
import ctypes
import hashlib
import pathlib

def GetNoMercyPath():
    def IsSysWow64():
        if sys.maxsize > 2**32:
            return False
        else:
            return bool(ctypes.windll.kernel32.GetModuleHandleW("ntdll.dll"))

    buffer = ctypes.create_unicode_buffer(256)
    if not ctypes.windll.kernel32.ExpandEnvironmentStringsW("%ProgramW6432%" if IsSysWow64() else "%ProgramFiles%", buffer, len(buffer)):
        print(f"ExpandEnvironmentStringsW(wow64: {int(IsSysWow64())}) failed with error: {ctypes.windll.kernel32.GetLastError()}")
        return ""

    path = buffer.value
    if not path or not pathlib.Path(path).exists():
        print(f"Program files: {path} path is not correct!")
        return ""

    return os.path.join(path, "NoMercy")

def GetMd5(filename):
    try:
        with open(filename, "rb") as file:
            md5_hash = hashlib.md5()
            for chunk in iter(lambda: file.read(4096), b""):
                md5_hash.update(chunk)
            return md5_hash.hexdigest()
    except Exception as e:
        print(f"Exception occurred: {e}")
    return ""

def GetSHA1(filename):
    try:
        with open(filename, "rb") as file:
            sha1_hash = hashlib.sha1()
            for chunk in iter(lambda: file.read(4096), b""):
                sha1_hash.update(chunk)
            return sha1_hash.hexdigest()
    except Exception as e:
        print(f"Exception occurred: {e}")
    return ""

def GetSHA256(filename):
    try:
        with open(filename, "rb") as file:
            sha256_hash = hashlib.sha256()
            for chunk in iter(lambda: file.read(4096), b""):
                sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Exception occurred: {e}")
    return ""

def WildcardMatch(string, match):
    p_match = 0
    p_string = 0
    
    while p_match < len(match):
        if match[p_match] == '?':
            if p_string >= len(string):
                return False
            p_string += 1
            p_match += 1
        elif match[p_match] == '*':
            if WildcardMatch(string[p_string:], match[p_match + 1:]) or (p_string < len(string) and WildcardMatch(string[p_string + 1:], match[p_match])):
                return True
            return False
        else:
            if p_string >= len(string) or string[p_string] != match[p_match]:
                return False
            p_string += 1
            p_match += 1
    
    return p_string == len(string) and p_match == len(match)

def ReadFileContent(filename):
    try:
        with open(filename, "rb") as file:
            return file.read().decode("utf-8")
    except Exception as e:
        print(f"Exception occurred: {e}")
    return ""