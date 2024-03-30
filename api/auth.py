from fastapi import APIRouter, Depends
from starlette.responses import JSONResponse
from models.auth_schema import UserCreateSchema, TokenSchema, UserSchema, CookieResponse, UserLoginSchema
from services.auth_service import AuthService, get_current_user, logout_user

auth_router = APIRouter(prefix='/auth', tags=['Authentication'])


@auth_router.post('/registration', response_model=TokenSchema)
def sign_up(user_data: UserCreateSchema, service: AuthService = Depends()):
    return service.registration_new_user(user_data)


@auth_router.post('/login', response_model=CookieResponse)
def sign_in(form_data: UserLoginSchema, service: AuthService = Depends()):
    return service.authenticate_user(form_data.username, form_data.password)


@auth_router.get('/user', response_model=UserSchema)
def get_user(user: UserSchema = Depends(get_current_user)):
    return user


@auth_router.post("/logout")
def logout():
    return logout_user()
