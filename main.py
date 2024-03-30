from fastapi import FastAPI
from api.auth import auth_router

app = FastAPI()
app.include_router(auth_router)

import uvicorn

if __name__ == '__main__':
    uvicorn.run(app)
