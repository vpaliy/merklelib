import sys

_ver = sys.version_info

is_py2 = (_ver[0] == 2)
is_py3 = (_ver[0] == 3)

if is_py2:
  bytes = str
  str = unicode
  basestring = basestring
  bytes_types = (bytes, bytearray)
elif is_py3:
  builtin_str = str
  str = str
  bytes = bytes
  bytes_types = (bytes, bytearray)
