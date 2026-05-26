import hashlib
import base64

# Verhoeff Tables
VERHOEFF_D = (
  (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
  , (1, 2, 3, 4, 0, 6, 7, 8, 9, 5)
  , (2, 3, 4, 0, 1, 7, 8, 9, 5, 6)
  , (3, 4, 0, 1, 2, 8, 9, 5, 6, 7)
  , (4, 0, 1, 2, 3, 9, 5, 6, 7, 8)
  , (5, 9, 8, 7, 6, 0, 4, 3, 2, 1)
  , (6, 5, 9, 8, 7, 1, 0, 4, 3, 2)
  , (7, 6, 5, 9, 8, 2, 1, 0, 4, 3)
  , (8, 7, 6, 5, 9, 3, 2, 1, 0, 4)
  , (9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
)

VERHOEFF_P = (
  (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
  , (1, 5, 7, 6, 2, 8, 3, 0, 9, 4)
  , (5, 8, 0, 3, 7, 9, 6, 1, 4, 2)
  , (8, 9, 1, 6, 0, 4, 3, 5, 2, 7)
  , (9, 4, 5, 3, 1, 2, 6, 8, 7, 0)
  , (4, 2, 8, 6, 5, 7, 3, 9, 0, 1)
  , (2, 7, 9, 3, 8, 0, 6, 4, 1, 5)
  , (7, 0, 4, 6, 9, 1, 3, 2, 5, 8)
)

VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)

def validate_verhoeff(number: str) -> bool:
  """Validates a 25-digit UID using the Verhoeff checksum."""
  if not number.isdigit() or len(number) != 25:
    return False
  if number[0] in ('0', '1'):
    return False
  
  c = 0
  for i, digit in enumerate(reversed(number)):
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(digit)]]
  return c == 0

def generate_verhoeff_check_digit(number: str) -> int:
  """Generates the check digit for a 24-digit string."""
  c = 0
  for i, digit in enumerate(reversed(number)):
    # Start from index 1 because the check digit will be at index 0 in the reversed number
    c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][int(digit)]]
  return VERHOEFF_INV[c]

def calculate_tsrct_sha256(body_b64: str) -> str:
  """
  Calculates SHA-256 of the UTF8-Bytes of the Base64String representation of the body.
  sha = SHA-256(UTF8-Bytes(Base64String(bodyBytes)))
  """
  # body_b64 is already the Base64 string.
  # Ensure it is the URL-safe, non-padded version if needed, but the spec says hash the string.
  hasher = hashlib.sha256()
  hasher.update(body_b64.encode('utf-8'))
  return base64.urlsafe_b64encode(hasher.digest()).decode('utf-8').rstrip('=')

def b64url_encode(data: bytes) -> str:
  """URL-safe, non-padded Base64 encoding."""
  return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
