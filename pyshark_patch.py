#!/usr/bin/env python3

import site
from pathlib import Path
import os

# print(site.getsitepackages())

# sp = site.getsitepackages()
patch_target_relative_suffix = "pyshark/tshark/tshark_xml.py"

# pyshark/tshark/tshark_xml.py

for site in site.getsitepackages():
    site_path = Path(site)
    patch_target = site_path.joinpath(patch_target_relative_suffix)
    if patch_target.exists() and patch_target.is_file():
        os.system("patch -i pyshark_tshark_lxml.patch {}".format(str(patch_target.absolute())))



# ['/usr/local/lib/python3.9/dist-packages', '/usr/lib/python3/dist-packages', '/usr/lib/python3.9/dist-packages']