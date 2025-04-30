import re

def extract_strings_py(path, min_len=4):
    with open(path, 'rb') as f:
        data = f.read()
    pattern = rb'[\x20-\x7E]{%d,}' % min_len
    raw = re.findall(pattern, data)
    return [s.decode('ascii', errors='ignore') for s in raw]

def is_malicious_by_strings(path, threshold=3, min_len=4):
    strs = extract_strings_py(path, min_len)
    flags =  [
    'cmd.exe','powershell','CreateRemoteThread','WinExec',
    'http://','https://','URLDownloadToFile','WScript.Shell',
    'RegOpenKeyEx','LoadLibrary','GetProcAddress',
    '.exe','.dll','.scr','MZ','PE','base64_decode',
    'eval(','system(','exec(','socket(','connect(',
    'HKEY_LOCAL_MACHINE','C:\\Windows','/tmp/',
    'reverse shell','chmod 777','wget ','curl ',
]
    matches = [s for s in strs if any(i in s for i in flags)]
    return len(matches), strs, len(matches) >= threshold

path = input('Enter file path: ')
match_count, all_strings, verdict = is_malicious_by_strings(path, threshold=2, min_len=4)
print(f'Extracted {len(all_strings)} strings: ')
for s in all_strings:
    print(' ', s)
print(f'\nFlags matches: {match_count}')
print('Malicious' if verdict else 'Clean')