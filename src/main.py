import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status
from .database import SessionLocal, engine
from .service import user_crud
from sqlalchemy.orm import Session
from .schemas.user import Token, User, TokenData
from .models.user import Base

Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post('/user/login', response_model=Token)
async def login_for_access_token(email: str, password: str, db: Session=Depends(get_db)):
    user_token = await user_crud.authenticate_user(db, email, password)
    if not user_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return user_token


@app.post('/user', response_model=User)
async def register_user(email: str, password: str, db: Session=Depends(get_db)):
    user = await user_crud.create_user(db, email, password)
    return user

@app.get('/user')
async def get_user(token_date: TokenData = Depends(user_crud.get_current_user)):
    return token_date
