#!/usr/bin/env python3

import ctags, re, json, sys, simplejson
from ctags import CTags, TagEntry

tags = CTags('./tags')
entry = TagEntry()

sct_file = open('./syscall.tbl', 'r')

sys_calls = []
i = 0

# FIXME: better JSON output

for line in sct_file:
    parts = line.split()
    if(len(parts) > 3 and parts[0] >= '0'):
        name = parts[3]
        if tags.find(entry, name.encode('utf-8'), ctags.TAG_FULLMATCH | ctags.TAG_OBSERVECASE):
            found_sym = False
            while(not found_sym):
                if(entry['kind'] == b'prototype'):
                    found_sym = True
                    details = [i, name, entry[b'signature']]
                    if(entry[b'signature'] != "(void)"):
                        sig = entry[b'signature'].decode('utf-8').strip('()').split(',')
                    else:
                        sig = [];
                    regs = {};
                    details.append("%0#4x"%(i));
                    if(len(sig) < 6):
                        for param in sig:
                            par = param.strip()
                            par_def = None

                            if(param.find("struct") != -1):
                                type_match = re.search("struct (\w+)", param)
                                if(type_match):
                                    par_entry = TagEntry()
                                    if(tags.find(par_entry, type_match.group(1).encode('utf-8'), ctags.TAG_FULLMATCH|ctags.TAG_OBSERVECASE)):
                                        if(par_entry['kind'] == 'struct'):
                                            par_def = {'file': par_entry['file'], 'line': int(par_entry['lineNumber'])}
                            details.append({'type': par, 'def': par_def})
                    else:
                        details.append("param addr*")
                    remaining = 9 - len(details)
                    for x in range(0, remaining):
                        details.append("")

                    pattern = "SYSCALL_DEFINE%d(%s".format(len(sig), name.replace("sys_", "")).encode('utf-8')
                    search = b"SYSCALL_DEFINE%d"%(len(sig))
                    if tags.find(entry, search, ctags.TAG_FULLMATCH | ctags.TAG_OBSERVECASE):
                        found = False
                        while(found == False):
                            if(entry['pattern'].find(pattern) == 2):
                                details.append(entry['file'])
                                details.append(int(entry['lineNumber']))
                                found = True
                                break
                            if(not tags.findNext(entry)):
                                details.append("not found")
                                details.append("")
                                break
                    else:
                        details.append("not found")
                        details.append("")
                    sys_calls.append(details)
                else:
                    if(not tags.findNext(entry)):
                        sys_calls.append([i, "", "", "", "", "", "", "", "", "", ""])
                        break
    else:
        sys_calls.append([i, "not implemented", "", "%0#4x"%(i), "", "", "", "", "", "", ""])

    i += 1

print(simplejson.dumps(sys_calls, indent="  "))
