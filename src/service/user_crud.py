from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from ..schemas.user import TokenData, Token
from ..models.user import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oath_2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SECRET_KEY = '333287e25342d6db8d150d10e4178474b65addbcbe97f8a3ebe2cd414b63e8fe'
ALGORITHM = 'HS256'


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

async def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

async def authenticate_user(db: Session, email: str, password: str):
    user = await get_user_by_email(db, email)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    token = create_access_token(user)
    return token

def create_access_token(user: User):
    user_dict = {"user": user.email}
    encoded_jwt = jwt.encode(user_dict, SECRET_KEY, algorithm=ALGORITHM)
    return {"token": encoded_jwt, "email": user.email}

async def get_current_user(token: str = Depends(oath_2_scheme)):
    credential_exception = HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail='could not validate credential.')
    try:
        payload = jwt.decode(token, SECRET_KEY)
        email = payload.get('user')
        if email is None:
            raise credential_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credential_exception

    # TODO: validate
    # user = await get_user_by_email(db, token_data.email)
    # if user is None: 
    #     credential_exception
    return token_data

async def create_user(db: Session, email: str, password: str):
    user = await get_user_by_email(db, email)
    if user:
        raise HTTPException(status_code=409)
    hash_password = get_password_hash(password)
    db_user = User(email=email, password=hash_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


