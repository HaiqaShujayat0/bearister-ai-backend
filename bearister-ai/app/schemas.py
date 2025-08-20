from pydantic import BaseModel, EmailStr
from typing import Optional
class UserCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    agree_terms: bool
    is_verified: Optional[bool] = False



class UserLogin(BaseModel):
    email: EmailStr
    password: str
    
class UserResponse(BaseModel):
    id: int
    full_name: str
    email: str
    agree_terms: bool
    is_superadmin: bool
    is_verified: bool

    class Config:
        orm_mode = True
# class adminUserResponse(BaseModel):
#     id: int
#     full_name: str
#     email: str


#     class Config:
#         orm_mode = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    user: UserResponse 


class TokenWithUser(Token):
    role: str
    user: UserResponse
    
    
class MessageResponse(BaseModel):
    message: str
        
class UserProfile(BaseModel):
    id: int
    full_name: str
    email: str
    phone: Optional[str] = None

    class Config:
        orm_mode = True 


class UserProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    email: EmailStr
    phone: Optional[str] = None

class UpdatePasswordRequest(BaseModel):
    old_password: str
    new_password: str    