# coding=utf-8
import logging
import os
import secrets
from typing import Optional

import fastapi
import slowapi.errors
import slowapi.middleware
import slowapi.util
from dotenv import load_dotenv
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from pydantic import BaseModel, Field

import bsrv.logic as lg
from bsrv.dbm import UserAlreadyExists, UserDoesntExist, ProjectDoesntExist

load_dotenv()

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("api.log",
                                            encoding="utf-8"),
                        logging.StreamHandler()
                        ])
logger = logging.getLogger(__name__)

JWT_SECRET = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES"))

app = fastapi.FastAPI(title="BlockServices",
                      description="BlockServices API and alternative "
                                  "Scratch API for Dashblocks",
                      version="0.4.0",
                      redoc_url="/redocs",
                      license_info={"name": "GPL-3.0"},
                      copyright_holder="BlockMaster777")

limiter = slowapi.Limiter(key_func=slowapi.util.get_remote_address,
                          default_limits=["10/minute"],
                          storage_uri="memory://")

app.state.limiter = limiter
app.add_middleware(slowapi.middleware.SlowAPIMiddleware)
app.add_exception_handler(slowapi.errors.RateLimitExceeded,
                          slowapi._rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type", "Authorization"]
)

security = HTTPBearer(auto_error=False)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=20,
                          pattern="^[a-zA-Z0-9_]+$",
                          description="Unique username",
                          examples=["user123", "MarkusPerson", "DBDev"])
    name: str = Field(min_length=1, max_length=50, pattern="^[a-zA-Z0-9_ ]+$",
                      description="Display name",
                      examples=["User 123", "Markus Person",
                                "DBDev - best user ever"])
    email: str = Field(pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\."
                               r"[a-zA-Z0-9-.]+$",
                       examples=["dbdev@gmail.com", "vasa.belkin@yandex.ru"])
    password: str = Field(min_length=8, max_length=100)


class UserLogin(BaseModel):
    username: str = Field(description="Unique username",
                          examples=["user123", "MarkusPerson", "DBDev"])
    password: str


class UIDResponse(BaseModel):
    uid: int = Field(description="Unique user id", examples=[1, 2, 3])


class JWTResponse(BaseModel):
    access_token: str = Field(description="JWT token")
    token_type: str = Field(description="Token type", examples=["Bearer"])


class PublicUserData(BaseModel):
    id: int = Field(description="Unique user id", examples=[1, 2, 3])
    username: str = Field(description="Unique username",
                          examples=["user123", "MarkusPerson", "DBDev"])
    name: str = Field(description="Display name",
                      examples=["User 123", "Markus Person",
                                "DBDev - best user ever"])
    description: Optional[str] = Field(description="User description",
                                       default=None)
    avatar: Optional[str] = Field(description="Base64 encoded jpg image")
    is_banned: bool = Field(description="Is user banned",
                            examples=[True, False])
    created_at: str = Field(description="Registration date")
    is_admin: bool = Field(description="Is user admin", examples=[True, False])


class AllUserData(BaseModel):
    id: int = Field(description="Unique user id", examples=[1, 2, 3])
    username: str = Field(description="Unique username",
                          examples=["user123", "MarkusPerson", "DBDev"])
    name: str = Field(description="Display name",
                      examples=["User 123", "Markus Person",
                                "DBDev - best user ever"])
    avatar: Optional[str] = Field(description="Base64 encoded jpg image",
                                  default=None)
    description: Optional[str] = Field(description="User description",
                                       default=None)
    email: str = Field(description="User email",
                       examples=["dbdev@gmail.com", "vasa.belkin@yandex.ru"])
    created_at: str = Field(description="Registration date")
    is_admin: bool = Field(description="Is user admin", examples=[True, False])
    is_banned: bool = Field(description="Is user banned",
                            examples=[True, False])


class UserEditData(BaseModel):
    name: Optional[str] = Field(description="Display name", default=None,
                                examples=["User 123", "Markus Person",
                                          "DBDev - best user ever"])
    avatar: Optional[str] = Field(description="Base64 encoded jpg image",
                                  default=None)
    description: Optional[str] = Field(description="User description",
                                       default=None)


class ProjectCreate(BaseModel):
    name: str = Field(description="Project name",
                      examples=["Project 123", "Kitten Parkour", "Untitled-1"])
    description: str = Field(description="Project description",
                             examples=["Best project, controls - ..."])
    file: str = Field(description="Project file in base64 format")
    is_public: bool = Field(description="Is project public",
                            examples=[True, False])


class ProjectEdit(BaseModel):
    pid: int = Field(description="Project id", examples=[7385, 866747, 67485])
    name: Optional[str] = Field(description="Project name",
                                examples=["Project 123", "Kitten Parkour",
                                          "Untitled-1"],
                                default=None)
    description: Optional[str] = Field(description="Project description",
                                       examples=["Best project, controls - ..."],
                                       default=None)
    file: Optional[str] = Field(description="Project file in base64 format",
                                default=None)
    is_public: Optional[bool] = Field(description="Is project public",
                                      examples=[True, False], default=None)


class ProjectData(BaseModel):
    name: str = Field(description="Project name",
                      examples=["Project 123", "Kitten Parkour", "Untitled-1"])
    description: str = Field(description="Project description",
                             examples=["Best project, controls - ..."])
    author: str = Field(description="Project author",
                        examples=["user123", "MarkusPerson", "DBDev"])
    file: str = Field(description="Project file in base64 format")
    created_at: str = Field(description="Project creation date")
    is_public: bool = Field(description="Is project public",
                            examples=[True, False])


async def get_current_user(token: str) ->  int:
    credentials_exception = fastapi.HTTPException(
            status_code=fastapi.status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
            )
    try:
        uid = await lg.get_uid_from_token(token, JWT_SECRET)
        if uid is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception
    return int(uid)


async def is_admin(token: str):
    uid = await get_current_user(token)
    return lg.dbm.get_user(uid)["is_admin"]


async def is_banned(uid: int) -> bool:
    return lg.dbm.get_user(uid)["is_banned"]


async def get_public_user_data(uid: int) -> PublicUserData:
    result = lg.dbm.get_user(uid)
    return PublicUserData(
        id=result["id"],
        username=result["username"],
        name=result["name"],
        avatar=result["avatar"],
        description=result["description"],
        created_at=result["created_at"],
        is_admin=result["is_admin"],
        is_banned=result["is_banned"],
    )


async def get_all_user_data(uid: int) -> AllUserData:
    result = lg.dbm.get_user(uid)
    return AllUserData(
            id=result["id"],
            username=result["username"],
            name=result["name"],
            avatar=result["avatar"],
            description=result["description"],
            email=result["email"],
            created_at=result["created_at"],
            is_admin=result["is_admin"],
            is_banned=result["is_banned"],
            )


@app.get("/")
def index():
    return "Welcome to BlockServices. Docs - blockservices.duckdns.org/docs"


@app.post("/dash/auth/register",
          summary="Register new user",
          response_model=UIDResponse,
          responses={400: {"description": "User already exists"}},
          status_code=201)
@limiter.limit("1/day")
async def register(user: UserCreate, request: Request):
    logger.log(20, f"Register start {user.username}, {user.name}, "
                   f"{user.email}, {user.password}")
    try:
        uid = await lg.register_user(user.password,
                                     user.username,
                                     user.name,
                                     user.email)
    except UserAlreadyExists:
        logger.log(20, f"User {user.username} already exists")
        raise fastapi.HTTPException(status_code=400,
                                    detail="User already exists")
    logger.log(20, f"Successfully registered {user.username}")
    return UIDResponse(uid=uid)


@app.post("/dash/auth/login",
          summary="Login into account",
          response_model=JWTResponse,
          responses={400: {"description": "Incorrect username or password"}})
@limiter.limit("5/minute")
async def login(user: UserLogin, request: Request):
    logger.log(20, f"Login start {user.username}")
    if await lg.check_password(user.password, user.username):
        try:
            uid = lg.dbm.get_user_id(user.username)
        except UserDoesntExist:
            logger.log(20, f"User {user.username} doesn't exist")
            raise fastapi.HTTPException(status_code=400,
                                        detail="User doesn't exist")
        if lg.dbm.get_user(uid)["is_banned"]:
            logger.log(20, f"User {user.username} is banned")
            raise fastapi.HTTPException(status_code=403,
                                        detail="You are banned")
        access_token = await lg.create_access_token({"uid": uid},
                                                    TOKEN_EXPIRE_MINUTES,
                                                    JWT_SECRET)
        logger.log(20, f"Issued JWT token for {user.username} with "
                       f"id {uid}")
        return JWTResponse(access_token=access_token, token_type="Bearer")
    else:
        logger.log(20, f"User {user.username} wrong credentials")
        raise fastapi.HTTPException(status_code=400,
                                    detail="Incorrect username or password")


@app.get("/dash/user/{username}",
         summary="Public information about user",
         response_model=PublicUserData)
async def get_user(username: str, request: Request):
     try:
         uid = lg.dbm.get_user_id(username)
     except UserDoesntExist:
         raise fastapi.HTTPException(status_code=404,
                                     detail="User doesn't exist")
     logger.log(20, f"Successfully get public user data {username}")
     return await get_public_user_data(uid)


@app.get("/dash/me", summary="All information about you",
         response_model=AllUserData,
         responses={400: {"description": "Incorrect token"}})
async def account(request: Request,
                  credentials: HTTPAuthorizationCredentials =
                  fastapi.Depends(security)):
    try:
        token = credentials.credentials
        uid = await get_current_user(token)
        result = lg.dbm.get_user(uid)
    except (InvalidTokenError, UserDoesntExist, AttributeError):
        raise fastapi.HTTPException(status_code=400, detail="Incorrect token")
    logger.log(20, f"Get all user data {uid}")
    return await get_all_user_data(uid)


@app.patch("/dash/me", summary="Edit your name, avatar or description",
          responses={
              400: {"description": "Incorrect token or nothing to change"}
              },
           status_code=201)
@limiter.limit("5/minute")
async def edit_data(request: Request, data: UserEditData,
                    credentials: HTTPAuthorizationCredentials =
                    fastapi.Depends(security)):
    try:
        uid = await get_current_user(credentials.credentials)
    except (InvalidTokenError, UserDoesntExist, AttributeError):
        raise fastapi.HTTPException(status_code=400, detail="Incorrect token")
    logger.log(20, f"Edit user data {uid}")
    if not data.name is None:
        lg.dbm.set_name(uid, data.name)
    if not data.avatar is None:
        lg.dbm.set_avatar(uid, data.avatar)
    if not data.description is None:
        lg.dbm.set_user_description(uid, data.description)
    if not (data.avatar or data.description or data.name):
        raise fastapi.HTTPException(status_code=400,
                                    detail="Nothing to change")


@app.get("/dash/user/{username}/admin_data",
         summary="Info about user. Admins only",
         response_model=AllUserData,
         responses={
             400: {"description": "Incorrect token"},
             403: {"description": "Not admin"},
             404: {"description": "User not found"},
             })
async def get_user_data_admin(request: Request, username: str,
                    credentials: HTTPAuthorizationCredentials =
                    fastapi.Depends(security)):
    try:
        token = credentials.credentials
        is_adm = await is_admin(token)
    except (InvalidTokenError, UserDoesntExist, AttributeError):
        raise fastapi.HTTPException(status_code=400, detail="Incorrect token")
    if not is_adm:
        raise fastapi.HTTPException(status_code=403, detail="Not admin")
    try:
        user = lg.dbm.get_user(lg.dbm.get_user_id(username))
    except UserDoesntExist:
        raise fastapi.HTTPException(status_code=404, detail="User not found")
    logger.log(20, f"Get admin user data of {username} for "
                   f"{await get_current_user(token)}")
    return get_all_user_data(user["id"])


@app.post("/dash/user/{username}/promote",
          summary="Promote a user, pardon a banned user. Admins only",
          responses={400: {"description": "Incorrect token or user is"
                                          "already banned"},
                     403: {"description": "Not admin"},
                     404: {"description": "User not found"}
              },
          status_code=201)
async def promote(username: str,
                  credentials: HTTPAuthorizationCredentials =
                  fastapi.Depends(security)):
    try:
        is_adm = await is_admin(credentials.credentials)
    except (InvalidTokenError, UserDoesntExist, AttributeError):
        raise fastapi.HTTPException(status_code=400, detail="Incorrect token")
    if not is_adm:
        raise fastapi.HTTPException(status_code=403, detail="Not admin")
    try:
        await lg.promote_user(username)
    except UserDoesntExist:
        raise fastapi.HTTPException(status_code=404,
                                    detail="User doesn't exist")
    except lg.NothingChangedException:
        raise fastapi.HTTPException(status_code=400,
                                    detail="User is already admin")
    logger.log(20, f"Successfully promote user {username}")


@app.post(
    "/dash/user/{username}/demote",
    summary="Demote an admin, ban a user. Admins only",
    responses={
        400: {"description": "Incorrect token or user is already banned"},
        403: {"description": "Not admin"},
        404: {"description": "User not found"},
        },
    status_code=201,
)
async def demote(username: str,
                 credentials: HTTPAuthorizationCredentials =
                 fastapi.Depends(security)):
    try:
        is_adm = await is_admin(credentials.credentials)
    except (InvalidTokenError, UserDoesntExist, AttributeError):
        raise fastapi.HTTPException(status_code=400, detail="Incorrect token")
    if not is_adm:
        raise fastapi.HTTPException(status_code=403, detail="Not admin")
    try:
        await lg.demote_user(username)
    except UserDoesntExist:
        raise fastapi.HTTPException(status_code=404,
                                    detail="User doesn't exist")
    except PermissionError:
        raise fastapi.HTTPException(status_code=403,
                                    detail="Cant demote root user")
    except lg.NothingChangedException:
        raise fastapi.HTTPException(status_code=400,
                                    detail="User is already banned")
    logger.log(20, f"Successfully demote user {username}")


@app.post("/dash/project",
          summary="Upload new project to cloud",
          responses={400: {"description": "Incorrect token"}},
          status_code=201)
@limiter.limit("1/hour")
async def upload_project(request: Request, data: ProjectCreate,
                         credentials: HTTPAuthorizationCredentials
                         = fastapi.Depends(security)):
    try:
        uid = await get_current_user(credentials.credentials)
    except (InvalidTokenError, UserDoesntExist, AttributeError):
        raise fastapi.HTTPException(status_code=400, detail="Incorrect token")
    logger.log(20, f"Uploading project {data.name} for user {uid}")
    return await lg.dbm.add_project(data.name, data.description, uid,
                                    data.file, data.is_public)


@app.patch("/dash/project",
           summary="Update existing project",
           responses={400: {"description":  "Incorrect token or nothing to "
                                           "change"},
                      404: {"description": "Project not found"},
                      403: {"description": "Private project of other user"}},
           status_code=201)
@limiter.limit("1/minute")
async def update_project(request: Request, data: ProjectEdit,
                         credentials: HTTPAuthorizationCredentials =
                         fastapi.Depends(security)):
    try:
        uid = await get_current_user(credentials.credentials)
    except (InvalidTokenError, UserDoesntExist, AttributeError):
        raise fastapi.HTTPException(status_code=400, detail="Incorrect token")
    if not ((pdata := await lg.get_project(data.pid))["is_public"]
            or pdata["uid"] == uid):
        raise fastapi.HTTPException(status_code=403,
                                    detail="Private project of other user")
    logger.log(20, f"Updating project {data.name} for user {uid}")
    pid = data.pid
    if not data.name is None:
        lg.dbm.edit_project_name(pid, data.name)
    if not data.description is None:
        lg.dbm.edit_project_description(pid, data.description)
    if not data.file is None:
        lg.dbm.edit_project_file(pid, data.file)
    if not data.is_public is None:
        lg.dbm.edit_project_publicity(pid, data.is_public)
    if not (data.name or data.description or data.file or data.is_public):
        raise fastapi.HTTPException(status_code=400,
                                    detail="Nothing to change")



@app.get("/dash/project/{pid}",
         summary="Get project from cloud. Token is optional, "
                 "only needed for getting your private projects. Admins can"
                 "see all private projects.",
         responses={
             400: {"description": "Incorrect token"},
             403: {"description": "Private project"},
             404: {"description": "Project not found"}
             },
         response_model=ProjectData)
async def get_project(pid: int,
                      credentials: Optional[HTTPAuthorizationCredentials] =
                      fastapi.Depends(security)):
    try:
        if credentials is None:
            uid = -1
        else:
            uid = await get_current_user(credentials.credentials)
    except (InvalidTokenError, UserDoesntExist):
        raise fastapi.HTTPException(status_code=400, detail="Incorrect token")
    try:
        data = await lg.get_project(pid)
    except ProjectDoesntExist:
        raise fastapi.HTTPException(status_code=404,
                                    detail="Project doesn't exist")
    if (data["is_public"] or data["uid"] == uid
            or await is_admin(credentials.credentials)):
        logger.log(20, f"Successfully get project {pid} for "
                       f"user {uid}, public: {data['is_public']}")
        return ProjectData(name=data["name"],
                           description=data["description"],
                           file=data["file"],
                           author=data["author"],
                           created_at=data["created_at"],
                           is_public=data["is_public"])
    else:
        raise fastapi.HTTPException(status_code=403,
                                    detail="Private project of other user")


@app.get("/robots.txt")
async def robots(request: fastapi.Request):
     logger.log(20, f"Robot with ip {request.client.host}")
     return {"Content-Type": "text/plain",
             "body": "User-agent: *\nDisallow: /"}
