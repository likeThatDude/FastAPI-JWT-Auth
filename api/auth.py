from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm
from models.auth_schema import UserCreateSchema, TokenSchema, UserSchema
from services.auth_service import AuthService, get_current_user

auth_router = APIRouter(prefix='/auth', tags=['Authentication'])


@auth_router.post('/registration', response_model=TokenSchema)
def sign_up(user_data: UserCreateSchema, service: AuthService = Depends()):
    return service.registration_new_user(user_data)


@auth_router.post('/login', response_model=TokenSchema)
def sign_in(form_data: OAuth2PasswordRequestForm = Depends(), service: AuthService = Depends()):
    return service.authenticate_user(form_data.username, form_data.password)


@auth_router.get('/user', response_model=UserSchema)
def get_user(user: UserSchema = Depends(get_current_user)):
    return user
