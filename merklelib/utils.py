
def is_string(value):
  return isinstance(value, bytes)


def to_string(value):
  if isinstance(value, (bytes, bytearray)):
    return value
  elif isinstance(value, str):
    return value.encode()
  elif isinstance(value, int):
    return bytes(str(value).encode())

def to_hex(value):
  return to_string(value).hex()


def from_hex(value):
  try:
    return bytes.fromhex(value)
  except:
    return value
