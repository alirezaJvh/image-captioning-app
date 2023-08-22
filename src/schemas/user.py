import email
from os import access
from pydantic import BaseModel

class User(BaseModel):
    id: int
    email: str
    
    
    class Config:
        from_attributes = True


class Token(BaseModel):
    token: str
    email: str

class TokenData(BaseModel):
    email: str or None = None