import datetime
import jwt
from jwt import PyJWTError
import bcrypt
from pydantic import ValidationError

from models.auth_schema import UserSchema, TokenSchema, UserCreateSchema
from fastapi.exceptions import HTTPException
from fastapi import status, Depends
from fastapi.security import OAuth2PasswordBearer
from database import User, get_session
from sqlalchemy.orm import Session

jwt_secret: str = 'cs7tk4hawIC6frkDa9a80DV_-lIYqK_K4RlDXPaGT2w'
jwt_algorithm: str = 'HS256'
jwt_expiration: int = 3600

oauth2_schema = OAuth2PasswordBearer(tokenUrl='/auth/login')


def get_current_user(token: str = Depends(oauth2_schema)) -> UserSchema:
    return AuthService.validate_token(token)


class AuthService:

    # Проверяем пароль, передаём пароль который получили при входе и пароль из базы данных
    # Затем при помощи bcrypt.verify сравниваем и возвращаем True или False
    @classmethod
    def verify_password(cls, form_password: str, db_hashed_password: str) -> bool:
        return bcrypt.checkpw(form_password.encode('utf-8'), db_hashed_password.encode('utf-8'))

    # Хэшируем пароль
    @classmethod
    def hashed_password(cls, password) -> str:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Проверка присланного нам в запросе токена.
    @classmethod
    def validate_token(cls, token: str) -> UserSchema:
        # Ошибка которую мы будем выбрасывать если не
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Sorry yours token not valid :(',
            headers={
                'WWW-Authenticate': 'Bearer'
            }
        )
        try:
            # Достаём из токена информацию в поле payload в которой можем положить id password
            # или любую инфу о пользователе
            payload = jwt.decode(token, jwt_secret, algorithms=jwt_algorithm)
        except PyJWTError:
            raise exception from None

        # Получаем значение ключа user или что нам нужно
        # Пример того что в токене
        # {
        #     "sub": "1234567890",
        #     "iat": 1516239022,
        #     "user": {
        #         "id": 1,
        #         "username": "Anton",
        #         "password": "qwerty"
        #     }
        # }

        user_data = payload.get('user')

        # Валидируем данные при помощи pydentic схемы (Делаем из словаря схему)
        try:
            user = UserSchema.parse_obj(user_data)
        except ValidationError:
            raise exception from None

        return user

    @classmethod
    def create_token(cls, user: User) -> TokenSchema:
        user_data = UserSchema.from_orm(user)

        time_now = datetime.datetime.utcnow()
        payload = {
            'iat': time_now,
            'nbf': time_now,
            'exp': time_now + datetime.timedelta(seconds=jwt_expiration),
            'sub': str(user_data.id),
            'user': user_data.dict()
        }
        token = jwt.encode(payload, jwt_secret, algorithm=jwt_algorithm)
        return TokenSchema(access_token=token)

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def registration_new_user(self, user_data: UserCreateSchema) -> TokenSchema:
        user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=self.hashed_password(user_data.password)
        )
        self.session.add(user)
        self.session.commit()

        return self.create_token(user)

    def authenticate_user(self, username: str, password: str) -> TokenSchema:
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={
                'WWW-Authenticate': 'Bearer'
            }
        )
        user = self.session.query(User).filter(User.username == username).first()

        if not user:
            raise exception

        if not self.verify_password(password, user.hashed_password):
            raise exception

        return self.create_token(user)
