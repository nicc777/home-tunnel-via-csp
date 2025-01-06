"""
    Copyright (c) 2025. All rights reserved. NS Coetzee <nicc777@gmail.com>

    This file is licensed under GPLv3 and a copy of the license should be included in the project (look for the file 
    called LICENSE), or alternatively view the license text at 
    https://raw.githubusercontent.com/nicc777/home-tunnel-via-csp/refs/heads/main/LICENSE or 
    https://www.gnu.org/licenses/gpl-3.0.txt
"""

import os
from datetime import datetime
import traceback
import random
from git import cmd as git_cmd


def get_utc_timestamp(with_decimal: bool=False): 
    epoch = datetime(1970,1,1,0,0,0)
    now = datetime.utcnow()
    timestamp = (now - epoch).total_seconds()
    if with_decimal:
        return timestamp
    return int(timestamp)


def is_debug_set_in_environment()->bool:    # pragma: no cover
    try:
        env_debug = os.getenv('DEBUG', '0').lower()
        if env_debug in ('1','true','t','enabled', 'e'):
            return True
    except:
        pass
    return False


def is_url_a_git_repo(url: str)->bool:
    try:
        if '%00' in url:
            url = url[0:url.find('%00')]
        remote_refs = {}
        g = git_cmd.Git()
        for ref in g.ls_remote(url).split('\n'):
            hash_ref_list = ref.split('\t')
            remote_refs[hash_ref_list[1]] = hash_ref_list[0]
        if len(remote_refs) > 0:
            return True
    except:
        traceback.print_exc()
    return False


def merge_dicts(A: dict, B: dict)->dict:
    # FROM https://stackoverflow.com/questions/29241228/how-can-i-merge-two-nested-dictionaries-together (Vivek Sable)
    for i, j in B.items(): 
        if i in A:
            A[i].update(j)
        else:
            A[i] = j
    return A


def generate_random_string(
    length: int=16,
    chars: str='abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ'
)->str:
    if chars is None:
        raise Exception('chars parameter cannot be None')
    if isinstance(chars, str) is False:
        raise Exception('chars must be a string object')
    if len(chars) == 0:
        raise Exception('chars parameter must contain at least some characters')
    result = ''
    chars_list = list(chars)
    random.shuffle(chars_list)
    while len(result) < length:
        result = '{}{}'.format(
            result,
            random.choice(chars_list)
        )
    return result

