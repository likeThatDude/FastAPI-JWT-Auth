from pydantic import BaseModel


class BaseUserSchema(BaseModel):
    username: str
    email: str


class UserCreateSchema(BaseUserSchema):
    password: str


class UserSchema(BaseUserSchema):

    id: int

    class Config:
        from_attributes = True


class TokenSchema(BaseModel):
    access_token: str
    token_type: str = 'bearer'
