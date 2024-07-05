from datetime import datetime, time, timedelta
from enum import Enum
from typing import Union, Literal
from uuid import UUID
from fastapi import FastAPI, Body, Cookie, Header, Form, File, UploadFile, HTTPException, status, Request, Depends, \
    BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, HttpUrl, EmailStr
from starlette.middleware.base import BaseHTTPMiddleware
from jose import jwt, JWTError
from passlib.context import CryptContext

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}


# class Item(BaseModel):
#     name: str
#     description: str = Field(None, title="description", max_length=300)
#     price: float = Field(..., gt=0, description="Price")
#     tax: float | None = None


# @app.put("/items/{i_id}")
# async def update_item(i_id: int, item: Item = Body(..., embed=True)):
#     results = {"item_id": i_id, "item": item}
#     return results

"""
Body Nested Models
"""

# class Image(BaseModel):
#     url: HttpUrl
#     name: str
#

# class Item(BaseModel):
#     name: str
#     description: str = Field(None, title="description", max_length=300)
#     price: float = Field(..., gt=0, description="Price")
#     tax: float | None = None
#     tags: set[str] = set()
#     image: list[Image] | None = None
#     # image: Image | None = None

#
# class Offer(BaseModel):
#     name: str
#     description: str | None = None
#     price: float
#     items: list[Item]
#
#
# @app.put("/items/{item_id}")
# async def item_update(item_id: int, item: Item):
#     results = {"item_id": item_id, "item": item}
#     return results
#
#
# @app.post("/offers")
# async def create_offer(offer: Offer = Body(..., embed=True)):
#     return offer
#
#
# @app.post("/images/multiple")
# async def create_image(images: Image):
#     return images

"""
Part 10: Declare Request Example Data
"""

# class Item(BaseModel):
#     name: str = Field(..., example="Foo")
#     description: str | None = Field(None, example="A very nice Item")
#     price: float = Field(..., example=16.5)
#     tax: float | None = Field(None, example=1.7)
#
#     # class Config:
#     #     schema_extra = {
#     #         "example": {
#     #             "name": "Foo",
#     #             "description": "A vary nice Item",
#     #             "price": 16.25,
#     #             "tax": 1.67
#     #         }
#     #     }
#
#
# @app.put("/i/{id}")
# async def update_i(item_id: int, item: Item):
#     results = {"item_id": item_id, "item": item}
#     return results

# class Item(BaseModel):
#     name: str
#     description: str | None = None
#     price: float
#     tax: float | None = None

# class Config:
#     schema_extra = {
#         "example": {
#             "name": "Foo",
#             "description": "A vary nice Item",
#             "price": 16.25,
#             "tax": 1.67
#         }
#     }


# @app.put("/i/{id}")
# async def update_i(item_id: int, item: Item = Body(..., example={
#     "name": "Foo",
#     "description": "A vary nice Item",
#     "price": 15.25,
#     "tax": 1.7
# })):
#     results = {"item_id": item_id, "item": item}
#     return results

"""
Part 11: Extra Data Types
"""

# @app.put("/item/{item_id}/")
# async def read_item(item_id: UUID, start_date: datetime | None = Body(None), end_date: datetime | None = Body(None),
#                     repeat_at: time | None = Body(None), process_after: timedelta | None = Body(None)):
#     start_process = start_date + process_after
#     duration = end_date - start_process
#     return {
#         "item_id": item_id,
#         "start_date": start_date,
#         "end_date": end_date,
#         "repeat_at": repeat_at,
#         "process_after": process_after,
#         "start_process": start_process,
#         "duration": duration
#     }


"""
Part 12: Cookie and Header Parameters
"""

# @app.get("/items")
# async def read_items(cookie_id: str | None = Cookie(None), accept_encoding: str | None = Header(None),
#                      sec_ch_ua: str | None = Header(None), user_agent: str | None = Header(None),
#                      x_token: list[str] | None = Header(None)):
#     return {"cookie_id": cookie_id, "Accept-Encoding": accept_encoding, "sec_ch_ua": sec_ch_ua,
#             "User-Agent": user_agent, "X-Token values": x_token}


"""
Part 13: Response Model
"""

# from typing import Literal
#
#
# class Item(BaseModel):
#     name: str
#     description: str | None = None
#     price: float
#     tax: float | None = None
#     tags: list[str] = []
#
#
# items = {
#     "foo": {"name": "Foo", "price": 50.2},
#     "bar": {"name": "Bar", "price": 62, "description": "good", "tax": 20.2},
#     "baz": {"name": "Baz", "price": 50.2, "description": None, "tax": 10.58, "tags": []},
# }
#
#
# @app.get("/item/{id}", response_model=Item, response_model_exclude_unset=True)
# async def get_item(id: Literal["foo", 'bar', 'baz']):
#     return items[id]
#
#
# @app.get("/item/{id}/name", response_model=Item, response_model_include={"name", "description"})
# async def read_item_name(id: Literal["foo", 'bar', 'baz']):
#     return items[id]
#
#
# @app.get("/item/{id}/public", response_model=Item, response_model_exclude={"tax"})
# async def read_item_public(id: Literal["foo", 'bar', 'baz']):
#     return items[id]
#
#
# @app.post("/item/", response_model=Item)
# async def create_items(item: Item):
#     return item
#
#
# class UserBase(BaseModel):
#     username: str
#     email: EmailStr
#     full_name: str | None = None
#
#
# class UserIn(UserBase):
#     password: str
#
#
# class UserOut(UserBase):
#     pass
#
#
# @app.post("/user/", response_model=UserOut)
# async def create_user(user: UserIn):
#     return user


"""
Part 14: Extra Models
"""

# class UserBase(BaseModel):
#     username: str
#     email: EmailStr
#     full_name: str | None = None
#
#
# class UserIn(UserBase):
#     password: str
#
#
# class UserOut(UserBase):
#     pass
#
#
# class UserInDB(UserBase):
#     hashed_password: str
#
#
# def fake_password_hasher(raw_password: str):
#     return f"supersecret{raw_password}"
#
#
# def fake_save_user(user_in: UserIn):
#     hashed_password = fake_password_hasher(user_in.password)
#     user_in_db = UserInDB(**user_in.dict(), hashed_password=hashed_password)
#     print("User 'saved'.")
#     return user_in_db
#
#
# @app.post("/user/", response_model=UserOut)
# async def create_user(user_in: UserIn):
#     user_saved = fake_save_user(user_in)
#     return user_saved
#
#
# class BaseItem(BaseModel):
#     description: str
#     type: str
#
#
# class CarItem(BaseItem):
#     type: str = "car"
#
#
# class PlaneItem(BaseItem):
#     type: str = "plane"
#     size: int
#
#
# items = {
#     "item1": {"description": "All my friends drive a low rider", "type": "car"},
#     "item2": {
#         "description": "Music is my aeroplane, it's my aeroplane",
#         "type": "plane",
#         "size": 5,
#     },
# }
#
#
# @app.get("/items/{item_id}", response_model=Union[PlaneItem, CarItem])
# async def read_item(item_id: Literal["item1", "item2"]):
#     return items[item_id]
#
#
# class ListItem(BaseModel):
#     name: str
#     description: str
#
#
# list_items = [
#     {"name": "Foo", "description": "There comes my hero"},
#     {"name": "Red", "description": "It's my aeroplane"},
# ]
#
#
# @app.get("/list_items/", response_model=list[ListItem])
# async def read_items():
#     return items
#
#
# @app.get("/arbitrary", response_model=dict[str, float])
# async def get_arbitrary():
#     return {"foo": 1, "bar": "2"}


"""
    Form Field
"""

# class User(BaseModel):
#     username: str
#     password: str


# @app.post("/login/")
# async def login(user: User):
#     return user

# @app.post("/login/")
# async def login(username: str = Form(...), password: str = Form(...)):
#     print("password", password)
#     return {"username": username}
#
#
# @app.post("/login/body/")
# async def login_body(username: str = Body(...), password: str = Body(...)):
#     print("password", password)
#     return {"username": username}


"""
Request File
"""

#
# @app.post("/files")
# async def create_file(file: bytes = File(...)):
#     return {"file": len(file)}
#
#
# @app.post("/upload")
# async def upload_file(file: UploadFile):
#     return {"file": file.filename}


# @app.post("/files")
# async def create_file(file: bytes | None = File(None)):
#     if not file:
#         return {"message": "No file sent"}
#     return {"file": len(file)}
#
#
# @app.post("/upload")
# async def upload_file(file: UploadFile | None = None):
#     if not file:
#         return {"message": "No upload file sent"}
#     return {"file": file.filename}

# @app.post("/files")
# async def create_file(files: list[bytes] = File(..., description="Sent file")):
#     return {"file": [len(file) for file in files]}
#
#
# @app.post("/upload")
# async def upload_file(files: list[UploadFile] = File(..., description="A file upload")):
#     return {"file": [file.filename for file in files]}


# @app.post("/file")
# async def create_file(file: bytes = File(...), fileb: UploadFile = File(...), token: str =File(...)):
#     return {
#         "file_size": len(file),
#         "token": token,
#         "file_content_type": fileb.content_type
#     }

"""
Part 19: Handling Errors
"""

# items = {"foo": "The Foo Wrestlers"}
#
#
# @app.get("/items/{item_id}")
# async def read_item(item_id: str):
#     if item_id not in items:
#         raise HTTPException(
#             status_code=404,
#             detail="Item not found",
#             headers={"X-Error": "There goes my error"},
#         )
#     return {"item": items[item_id]}
#
#
# class UnicornException(Exception):
#     def __init__(self, name: str):
#         self.name = name
#
#
# @app.exception_handler(UnicornException)
# async def unicorn_exception_handler(request: Request, exc: UnicornException):
#     return JSONResponse(
#         status_code=418,
#         content={"message": f"Oops! {exc.name} did something. There goes a rainbow..."},
#     )
#
#
# @app.get("/unicorns/{name}")
# async def read_unicorns(name: str):
#     if name == "yolo":
#         raise UnicornException(name=name)
#     return {"unicorn_name": name}
#
#
# # @app.exception_handler(RequestValidationError)
# # async def validation_exception_handler(request, exc):
# #     return PlainTextResponse(str(exc), status_code=400)
# #
# #
# # @app.exception_handler(StarletteHTTPException)
# # async def http_exception_handler(request, exc):
# #     return PlainTextResponse(str(exc.detail), status_code=exc.status_code)
# #
# #
# # @app.get("/validation_items/{item_id}")
# # async def read_validation_items(item_id: int):
# #     if item_id == 3:
# #         raise HTTPException(status_code=418, detail="Nope! I don't like 3.")
# #     return {"item_id": item_id}
#
#
# # @app.exception_handler(RequestValidationError)
# # async def validation_exception_handler(request: Request, exc: RequestValidationError):
# #     return JSONResponse(
# #         status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
# #         content=jsonable_encoder({"detail": exc.errors(), "blahblah": exc.body}),
# #     )
# #
# #
# # class Item(BaseModel):
# #     title: str
# #     size: int
# #
# #
# # @app.post("/items/")
# # async def create_item(item: Item):
# #     return item
#
#
# @app.exception_handler(StarletteHTTPException)
# async def custom_http_exception_handler(request, exc):
#     print(f"OMG! An HTTP error!: {repr(exc)}")
#     return await http_exception_handler(request, exc)
#
#
# @app.exception_handler(RequestValidationError)
# async def validation_exception_handler(request, exc):
#     print(f"OMG! The client sent invalid data!: {exc}")
#     return await request_validation_exception_handler(request, exc)
#
#
# @app.get("/blah_items/{item_id}")
# async def read_items(item_id: int):
#     if item_id == 3:
#         raise HTTPException(status_code=418, detail="Nope! I don't like 3.")
#     return {"item_id": item_id}

## Part 20 - Path Operation Configuration
# class Item(BaseModel):
#     name: str
#     description: str | None = None
#     price: float
#     tax: float | None = None
#     tags: set[str] = set()
#
#
# class Tags(Enum):
#     items = "items"
#     users = "users"
#
#
# @app.post(
#     "/items/",
#     response_model=Item,
#     status_code=status.HTTP_201_CREATED,
#     tags=[Tags.items],
#     summary="Create an Item-type item",
#     # description="Create an item with all the information: "
#     # "name; description; price; tax; and a set of "
#     # "unique tags",
#     response_description="The created item",
# )
# async def create_item(item: Item):
#     """
#     Create an item with all the information:
#
#     - **name**: each item must have a name
#     - **description**: a long description
#     - **price**: required
#     - **tax**: if the item doesn't have tax, you can omit this
#     - **tags**: a set of unique tag strings for this item
#     """
#     return item
#
#
# @app.get("/items/", tags=[Tags.items])
# async def read_items():
#     return [{"name": "Foo", "price": 42}]
#
#
# @app.get("/users/", tags=[Tags.users])
# async def read_users():
#     return [{"username": "PhoebeBuffay"}]
#
#
# @app.get("/elements/", tags=[Tags.items], deprecated=True)
# async def read_elements():
#     return [{"item_id": "Foo"}]


"""
Part 21: JSON Compatible Encoder and Body Updates
"""

# fake_db = {}
#
# class Item(BaseModel):
#     name: str
#     timestamp: datetime
#     description: str | None = None

# @app.put("/item/{id}")
# async def update_item(id: str, item: Item):
#     json_data = jsonable_encoder(item)
#     fake_db[id] = json_data
#     print(fake_db)
#     return "Success"

#
# class Item(BaseModel):
#     name: str | None = None
#     description: str | None = None
#     price: float | None = None
#     tax: float = 10.5
#     tags: list[str] = []
#
#
# items = {
#     "foo": {"name": "Foo", "price": 50.2},
#     "bar": {"name": "Bar", "price": 50.2, "description": "The Bar", "tax": 20.5},
#     "baz": {"name": "Baz", "price": 50.2, "description": None, "tax": 10.5, "tags": []},
# }
#
#
# @app.get("/items/{item_id}/", response_model=Item)
# async def read_item(item_id: str):
#     return items.get(item_id)
#
#
# @app.put("/item/{item_id}", response_model=Item)
# async def update_item(item_id: str, item: Item):
#     update_item_encoder = jsonable_encoder(item)
#     items[item_id] = update_item_encoder
#     return update_item_encoder
#
#
# @app.patch("/item/{item_id}", response_model=Item)
# async def patch_item(item_id: str, item: Item):
#     stored_item_data = items.get(item_id)
#     if stored_item_data is not None:
#         stored_item_model = Item(**stored_item_data)
#     else:
#         stored_item_model = Item()
#     update_data = item.dict(exclude_unset=True)
#     updated_item = stored_item_model.copy(update=update_data)
#     items[item_id] = jsonable_encoder(updated_item)
#     print(items[item_id])
#     return updated_item

"""
Part 22: Dependencies
"""
#
#
# async def hello():
#     return "world"
#
#
# async def common_parameters(q: str | None = None, skip: int = 0, limit: int = 100, blah: str = Depends(hello)):
#     return {"q": q, "skip": skip, "limit": limit, "hello": blah}
#
#
# @app.get("/items/")
# async def read_items(commons: dict = Depends(common_parameters)):
#     return commons
#
#
# @app.get("/users/")
# async def read_users(commons: dict = Depends(common_parameters)):
#     return commons


"""
 Part 23: Classes as Dependencies
"""
# fake_items_db = [{"item_name": "Foo"}, {"item_name": "Bar"}, {"item_name": "Baz"}]
#
#
# class CommonQueryParams:
#     def __init__(self, q: str | None = None, skip: int = 0, limit: int = 100):
#         self.q = q
#         self.skip = skip
#         self.limit = limit
#
#
# @app.get("/items/")
# async def read_items(commons: CommonQueryParams = Depends(CommonQueryParams)):
#     response = {}
#     if commons.q:
#         response.update({"q": commons.q})
#     items = fake_items_db[commons.skip: commons.skip + commons.limit]
#     response.update({"items": items})
#     return response


"""
Part 25: Dependencies in path operation decorators, global dependencies
"""
#
# async def verify_token(x_token: str = Header(...)):
#     if x_token != "fake-super-secret-token":
#         raise HTTPException(status_code=400, detail="X-Token header invalid")
#
#
# async def verify_key(x_key: str = Header(...)):
#     if x_key != "fake-super-secret-key":
#         raise HTTPException(status_code=400, detail="X-Key header invalid")
#     return x_key
#
# @app.get("/items/", dependencies=[Depends(verify_token), Depends(verify_key)])
# async def read_items():
#     return [{"item": "Foo"}, {"item": "Bar"}]
#
#
# @app.get("/users/", dependencies=[Depends(verify_token), Depends(verify_key)])
# async def read_users():
#     return [{"username": "Rick"}, {"username": "Morty"}]


# app = FastAPI(dependencies=[Depends(verify_token), Depends(verify_key)])
#
#
# @app.get("/items/")
# async def read_items():
#     return [{"item": "Foo"}, {"item": "Bar"}]
#
#
# @app.get("/users/")
# async def read_users():
#     return [{"username": "Rick"}, {"username": "Morty"}]

"""
Part 26: Security
"""
# oauth2_schema = OAuth2PasswordBearer(tokenUrl='token')
#
# fake_users_db = {
#     "johndoe": dict(
#         username="johndoe",
#         full_name="John Doe",
#         emai="johndoe@gmail.com",
#         hashed_password="fakehashedsecret",
#         disabled=False
#     ),
#     "alice": dict(
#         username="alice",
#         full_name="Alice",
#         emai="alice@gmail.com",
#         hashed_password="fakehashedsecret2",
#         disabled=True
#     ),
# }
#
#
# def hash_fake_password(password: str):
#     return f"fakehashed{password}"
#
#
# @app.get("/items/")
# async def items_read(token: str = Depends(oauth2_schema)):
#     return {"token": token}
#
#
# class User(BaseModel):
#     username: str
#     email: str | None = None
#     full_name: str | None = None
#     disabled: bool | None = None
#
#
# class UserInDB(User):
#     hashed_password: str
#
#
# def get_user(db, username: str):
#     if username in db:
#         user_dict = db[username]
#         return UserInDB(**user_dict)
#
#
# async def fake_encode_token(token):
#     return get_user(fake_users_db, token)
#
#
# async def get_current_user(token: str = Depends(oauth2_schema)):
#     user = fake_encode_token(token)
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid authentication credentials",
#             headers={"WWW-Authenticate": "Bearer"}
#         )
#     return user
#
#
# async def get_current_active_user(current_user: User = Depends(get_current_user)):
#     if current_user.disabled:
#         raise HTTPException(status_code=400, detail="Inactivate user")
#     return current_user
#
#
# @app.post("/token")
# async def login(form_data: OAuth2PasswordRequestForm = Depends()):
#     user_dict = fake_users_db.get(form_data.username)
#     if not user_dict:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")
#     user = UserInDB(**user_dict)
#     hashed_password = hash_fake_password(form_data.password)
#     if not hashed_password == user.hashed_password:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")
#
#     return {"access_token": user.username, "token_type": "bearer"}
#
#
# @app.get("/user/me")
# async def get_me(current_user: User = Depends(get_current_active_user)):
#     return current_user


"""
Part 27: Security with JWT
"""
#
# SECRET_KEY = "thequickbrownfoxjumpedoverthelazydog"
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30
#
# fake_users_db = {
#     "johndoe": {
#         "username": "johndoe",
#         "full_name": "John Doe",
#         "email": "johndoe@example.com",
#         "hashed_password": "$2b$12$hVuMMQhLQevWLqEoADrAlep2mzC4hPDwN.tBEhfeNDTIbfk/5Go.O",
#         "disabled": False,
#     }
# }
#
#
# class Token(BaseModel):
#     access_token: str
#     token_type: str
#
#
# class TokenData(BaseModel):
#     username: str | None = None
#
#
# class User(BaseModel):
#     username: str
#     email: str | None = None
#     full_name: str | None = None
#     disabled: bool | None = None
#
#
# class UserInDB(User):
#     hashed_password: str
#
#
# pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
#
#
# def verify_password(plain_password, hashed_password):
#     return pwd_context.verify(plain_password, hashed_password)
#
#
# def get_password_hash(password):
#     return pwd_context.hash(password)
#
#
# def get_user(db, username: str):
#     if username in db:
#         user_dict = db[username]
#         return UserInDB(**user_dict)
#
#
# def authenticate_user(fake_db, username: str, password: str):
#     user = get_user(fake_db, username)
#     if not user:
#         return False
#     if not verify_password(password, user.hashed_password):
#         return False
#     return user
#
#
# def create_access_token(data: dict, expires_delta: timedelta | None = None):
#     to_encode = data.copy()
#     if expires_delta:
#         expire = datetime.utcnow() + expires_delta
#     else:
#         expire = datetime.utcnow() + timedelta(minutes=15)
#
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt
#
#
# @app.post("/token")
# async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
#     user = authenticate_user(fake_users_db, form_data.username, form_data.password)
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"}
#         )
#
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(
#         data={"sub": user.username}, expires_delta=access_token_expires
#     )
#     return {"access_token": access_token, "token_type": "bearer"}
#
#
# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"}
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#         token_data = TokenData(username=username)
#     except JWTError:
#         raise credentials_exception
#
#     user = get_user(fake_users_db, username=token_data.username)
#
#     if user is None:
#         raise credentials_exception
#     return user
#
#
# async def get_current_active_user(current_user: User = Depends(get_current_user)):
#     if current_user.disabled:
#         raise HTTPException(status_code=400, detail="Inactive user")
#
#     return current_user
#
#
# @app.get("/users/me", response_model=User)
# async def get_users(current_user: User = Depends(get_current_active_user)):
#     return current_user
#
#
# @app.get("/users/me/items")
# async def read_own_items(current_user: User = Depends(get_current_active_user)):
#     return [{"item_id": "foo", "owner": current_user.username}]


"""
Part 28: Middleware and CORS
"""
#
# import time
#
#
# class MyMiddleware(BaseHTTPMiddleware):
#     async def dispatch(self, request: Request, call_next):
#         start_time = time.time()
#         response = await call_next(request)
#         process_time = time.time() - start_time
#         response.headers["X-Process-Time"] = str(process_time)
#         return response
#
# origins = ["http://localhost:8000", "http://localhost:3000", "*"]
#
# app.add_middleware(MyMiddleware)
# app.add_middleware(CORSMiddleware, allow_origins=origins)
#
#
# @app.get("/b")
# async def b():
#     return {"hello":"salom"}

"""
Part 31: Background Tasks
"""

# import time
#
#
# def write_notification(email: str, message=""):
#     with open("log.txt", mode="w") as email_file:
#         content = f"notification for {email}: {message}"
#         time.sleep(5)
#         email_file.write(content)
#
#
# @app.post("/send-notification/{email}", status_code=202)
# async def send_notification(email: str, background_tasks: BackgroundTasks):
#     background_tasks.add_task(write_notification, email, message="some notification")
#     return {"message": " notification sent in the background"}


# def write_log(message: str):
#     with open("log.txt", mode="a") as log:
#         log.write(message)
#
#
# def get_query(background_tasks: BackgroundTasks, q: str | None = None):
#     if q:
#         message = f"found query: {q}\n"
#         background_tasks.add_task(write_log, message)
#     return q
#
#
# @app.post("/send-notification/{email}")
# async def send_notification(
#         email: str, background_tasks: BackgroundTasks, q: str = Depends(get_query)
# ):
#     message = f"message to {email}\n"
#     background_tasks.add_task(write_log, message)
#     return {"message": "Message sent", "query": q}
#


"""
Part 32: Metadata and Docs URLs
"""
#
# description = """
# ChimichangApp API helps you do awesome stuff. 🚀
#
# ## Items
#
# You can **read items**.
#
# ## Users
#
# You will be able to:
#
# * **Create users** (_not implemented_).
# * **Read users** (_not implemented_).
# """
#
# tags_metadata = [
#     dict(
#         name="users",
#         description="Operations with users. The **login** logic is also here.",
#     ),
#     dict(
#         name="items",
#         description="Manage items. So _fancy_ they have their own docs.",
#         externalDocs=dict(
#             description="Items external docs", url="https://www.google.com"
#         ),
#     ),
# ]
#
#
# app = FastAPI(
#     title="ChimichangApp",
#     description=description,
#     version="0.0.1",
#     terms_of_service="http://example.com/terms/",
#     contact=dict(
#         name="Deadpoolio the Amazing",
#         url="http://x-force.example.com/contact",
#         email="dp@x-force.example.com",
#     ),
#     license_info=dict(
#         name="Apache 2.0", url="https://www.apache.org/licenses/LICENSE-2.0.html"
#     ),
#     openapi_tags=tags_metadata,
#     openapi_url="/api/v1/openapi.json",
#     docs_url="/hello-world",
#     redoc_url=None,
# )
#
#
# @app.get("/users", tags=["users"])
# async def get_users():
#     return [dict(name="Harry"), dict(name="Ron")]
#
#
# @app.get("/items/", tags=["items"])
# async def read_items():
#     return [dict(name="wand"), dict(name="flying broom")]


"""
Part 33: Static Files, Testing, and Debugging
"""
# app.mount("/static", StaticFiles(directory="static"), name="static")

fake_secret_token = "coneofsilence"
fake_db = dict(
    foo=dict(
        id="foo", title="Foo", description="There goes my hero",

    ),
    bar=dict(
        id="bar", title="Bar", description="There bartenders",

    )
)


class Item(BaseModel):
    id: str
    title: str
    description: str | None = None


@app.get("/item/{item_id}")
async def read_main(item_id: str, x_token: str = Header()):
    if x_token != fake_secret_token:
        raise HTTPException(status_code=400, detail="Invalid X-Token header")
    if item_id not in fake_db:
        raise HTTPException(status_code=404, detail="Item not found")

    return fake_db[item_id]


@app.post("/item/", response_model=Item)
async def create_item(item: Item, x_token: str = Header()):
    if x_token != fake_secret_token:
        raise HTTPException(status_code=400, detail="Invalid X-Token header")
    if item.id in fake_db:
        raise HTTPException(status_code=400, detail="Item already exists")

    fake_db[item.id] = item
    return item
