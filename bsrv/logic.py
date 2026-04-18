# coding=utf-8
import bsrv.hashing
import bcrypt
from bsrv.dbm import *
import datetime
import jwt

dbm = DBM()

class NothingChangedException(Exception):
    pass

async def create_access_token(data: dict, expires_time: int,
                              secret_key: str) -> str:
    to_encode = data.copy()
    expire = (datetime.datetime.now(datetime.timezone.utc)
              + datetime.timedelta(minutes=expires_time))
    to_encode.update({"exp": expire,
                      "iat": datetime.datetime.now(datetime.timezone.utc),
                      "iss": "blockservices"})
    encoded_jwt = jwt.encode(to_encode, secret_key)
    return encoded_jwt


async def get_uid_from_token(token, secret_key) -> str:
    payload = jwt.decode(token, secret_key, algorithms={"HS256"},
                         issuer="blockservices")
    return payload["uid"]


async def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(),
                         bcrypt.gensalt()).decode()


async def check_password(password: str, username: str) -> bool:
    try:
        password_in_db = dbm.get_user_psw_by_username(username)
    except UserDoesntExist:
        return False
    old_method = await bsrv.hashing.check_hash(password,
                                               password_in_db)
    try:
        new_method = bcrypt.checkpw(password.encode(),
                                    password_in_db.encode())
    except ValueError:
        new_method = False
    if old_method:
        print(f"old method for {username}")
        dbm.edit_password(dbm.get_user_id(username),
                          await hash_password(password))
        return True
    if new_method:
        print(f"new method for {username}")
        return True
    return False


async def register_user(password, username, name, email):
    uid = dbm.add_user(username, name,
                       await hash_password(password), email)
    return uid


async def is_admin(user_id: int) -> bool:
    return dbm.get_user(user_id)["is_admin"]


async def promote_user(username: str):
    uid = dbm.get_user_id(username)
    if dbm.get_user(uid)["is_banned"]:
        dbm.change_user_banned_status(uid, False)
    elif not dbm.get_user(uid)["is_admin"]:
        dbm.change_user_admin_status(uid, True)
    else:
        raise NothingChangedException
    
    
async def demote_user(username: str):
    uid = dbm.get_user_id(username)
    if uid == 1:
        raise PermissionError
    if dbm.get_user(uid)["is_admin"]:
        dbm.change_user_admin_status(uid, False)
    elif not dbm.get_user(uid)["is_banned"]:
        dbm.change_user_banned_status(uid, True)
    else:
        raise NothingChangedException


async def get_project(pid: int) -> dict:
    data =  dbm.get_project(pid)
    return {"name": data["name"],
            "description": data["description"],
            "author": dbm.get_user(data["author_id"])["username"],
            "uid": data["author_id"],
            "file": data["file"],
            "created_at": data["created_at"],
            "is_public": data["is_public"]}
