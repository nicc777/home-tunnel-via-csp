"""
    Copyright (c) 2025. All rights reserved. NS Coetzee <nicc777@gmail.com>

    This file is licensed under GPLv3 and a copy of the license should be included in the project (look for the file 
    called LICENSE), or alternatively view the license text at 
    https://raw.githubusercontent.com/nicc777/home-tunnel-via-csp/refs/heads/main/LICENSE or 
    https://www.gnu.org/licenses/gpl-3.0.txt
"""


import yaml
import traceback
import copy
import re


def split_yaml_file_sections(yaml_file_path: str)->tuple:
    yaml_sections = list()
    section_text = ''
    with open(yaml_file_path, 'r') as f:
        for line in f:
            if line.startswith('---'):  # YAML Section start
                yaml_sections.append(section_text)
                section_text = ''
            else:
                line = line.replace('\n', '')
                line = line.replace('\r', '')
                if len(section_text) > 0:    
                    section_text = '{}\n{}'.format(section_text, line)
                else:
                    section_text = '{}'.format(line)
    if len(section_text) > 0:
        yaml_sections.append(section_text)
    return tuple(yaml_sections)


