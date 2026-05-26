import json
from typing import Optional
from pydantic import BaseModel, Field
from utils import b64url_encode, calculate_tsrct_sha256

class TDocHeader(BaseModel):
  alg: str = "RS256"
  cls: str
  typ: str
  its: int # Issued timestamp
  length: int = Field(alias="len") # Body length
  uid: str # Unique Doc ID
  src: str # Source/Issuer UID
  sig: Optional[str] = None # Signature (often omitted in header as it's the 3rd part)
  sha: str # SHA-256 quirk hash
  cty: str = "text/plain" # Content type
  acl: str = "acl_pri" # Access control
  key: Optional[str] = None # Key UID used for signing
  nce: Optional[str] = None # Nonce
  dsc: Optional[str] = None # Description
  exp: Optional[int] = None # Expiry timestamp

  class Config:
    populate_by_name = True

class TDoc(BaseModel):
  header: TDocHeader
  body_b64: str
  signature_b64: Optional[str] = None

  def encode(self) -> str:
    """Returns the formatted T-Doc: header.body.signature"""
    header_json = self.header.model_dump_json(by_alias=True, exclude_none=True)
    header_b64 = b64url_encode(header_json.encode('utf-8'))
    
    # Body is already b64 encoded
    sig = self.signature_b64 if self.signature_b64 else ""
    
    return f"{header_b64}.{self.body_b64}.{sig}"

  @classmethod
  def build(
    cls
    , header_data: dict
    , body_bytes: bytes
  ) -> "TDoc":
    """Helper to build a TDoc from raw bytes."""
    body_b64 = b64url_encode(body_bytes)
    header_data["len"] = len(body_bytes)
    header_data["sha"] = calculate_tsrct_sha256(body_b64)
    
    header = TDocHeader(**header_data)
    return cls(header=header, body_b64=body_b64)
