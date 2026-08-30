# coding=utf-8

#  BlockServices
#  Copyright (C) 2026  BlockMaster
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sqlite3
import os
import base64
from typing import Any

class UserDoesntExist(Exception):
    pass

class UserAlreadyExists(Exception):
    pass

class DBM:
    def __init__(self, db_file: str="db.db",
                 avatars_path: str="data/avatars/usr_") -> None:
        self.db_file = db_file
        self.avatars_path = avatars_path
        self.__create_tables()

    def __cursor_and_connection(self) -> tuple[sqlite3.Cursor,
                                               sqlite3.Connection]:
        connection = sqlite3.connect(self.db_file)
        return connection.cursor(), connection

    @staticmethod
    def __write_to_file(path: str, data: bytes):
        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
        with open(path, "wb") as f:
            f.write(data)

    @staticmethod
    def __read_from_file(path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    def __create_tables(self) -> None:
        cur, conn = self.__cursor_and_connection()
        cur.execute("BEGIN TRANSACTION")
        cur.execute("CREATE TABLE IF NOT EXISTS users("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "username TEXT NOT NULL UNIQUE,"
                    "name TEXT NOT NULL,"
                    "description TEXT,"
                    "email TEXT NOT NULL,"
                    "password_hash TEXT NOT NULL,"
                    "created_at TIMESTAMP NOT NULL DEFAULT "
                    "CURRENT_TIMESTAMP,"
                    "is_admin BOOLEAN NOT NULL DEFAULT FALSE,"
                    "is_banned BOOLEAN NOT NULL DEFAULT FALSE);")

        cur.execute("SELECT COUNT(*) AS CNTREC "
                    "FROM pragma_table_info('users') WHERE name='description'")
        if not cur.fetchone()[0]:
            cur.execute("""ALTER TABLE users ADD COLUMN description TEXT""")
            
        conn.commit()
        conn.close()

    def __does_user_exist(self, user_id: int) -> bool:
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("""SELECT * FROM users WHERE id = ?;""",
                        (user_id,))
            return bool(cur.fetchone())

    def __does_username_exist(self, username: str) -> bool:
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("""SELECT * FROM users WHERE username = ?;""",
                        (username,))
            return bool(cur.fetchone())

    def get_user(self, user_id: int) -> dict[str, Any]:
        if not self.__does_user_exist(user_id):
            raise UserDoesntExist
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("""SELECT * FROM users WHERE id = ?;""",
                        (user_id,))
            result = cur.fetchone()
        try:
            avatar = base64.b64encode(
                    self.__read_from_file(
                            self.avatars_path + str(user_id))).decode()
        except FileNotFoundError:
            avatar = None
        return {"id": result[0],
                "username": result[1],
                "name": result[2],
                "avatar": avatar,
                "description": result[8],
                "email": result[3],
                "password_hash": result[4],
                "created_at": result[5],
                "is_admin": bool(result[6]),
                "is_banned": bool(result[7])}

    def add_user(self, username: str, name: str,
                 password_hash: str, email: str) -> int:
        if self.__does_username_exist(username):
            raise UserAlreadyExists
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("BEGIN TRANSACTION;")
            cur.execute("INSERT INTO "
                        "users(username, name, password_hash, email) "
                        "VALUES (?, ?, ?, ?) RETURNING id;",
                        (username, name, password_hash, email))
            uid = cur.fetchone()[0]
            conn.commit()
        return uid

    def set_avatar(self, uid, avatar: str):
        if not self.__does_user_exist(uid):
            raise UserDoesntExist
        file_data = base64.b64decode(avatar.encode())
        self.__write_to_file(self.avatars_path + str(uid), file_data)

    def set_name(self, uid: int, name: str):
        if not self.__does_user_exist(uid):
            raise UserDoesntExist
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("BEGIN TRANSACTION;")
            cur.execute("UPDATE users SET name = ? WHERE id = ?;",
                        (name, uid))
            conn.commit()

    def set_user_description(self, uid: int, description: str):
        if not self.__does_user_exist(uid):
            raise UserDoesntExist
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("BEGIN TRANSACTION;")
            cur.execute("UPDATE users SET description = ? WHERE id = ?;",
                        (description, uid))
            conn.commit()

    def get_user_id(self, username: str) -> int:
        if not self.__does_username_exist(username):
            raise UserDoesntExist
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("""SELECT id FROM users WHERE username = ?;""",
                        (username,))
            uid = cur.fetchone()[0]
        return uid

    def get_user_psw_by_username(self, username: str) -> str:
        return self.get_user(self.get_user_id(username))["password_hash"]

    def edit_password(self, uid: int, new_password: str):
        if not self.__does_user_exist(uid):
            raise UserDoesntExist
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("BEGIN TRANSACTION;")
            cur.execute("UPDATE users SET password_hash = ? WHERE id = ?;",
                        (new_password, uid))
            conn.commit()

    def change_user_admin_status(self, uid: int, status: bool):
        if not self.__does_user_exist(uid):
            raise UserDoesntExist
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("BEGIN TRANSACTION;")
            cur.execute("UPDATE users SET is_admin = ? WHERE id = ?;",
                        (status, uid))
            conn.commit()

    def change_user_banned_status(self, uid: int, status: bool):
        if not self.__does_user_exist(uid):
            raise UserDoesntExist
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("BEGIN TRANSACTION;")
            cur.execute("UPDATE users SET is_banned = ? WHERE id = ?;",
                        (status, uid))
            conn.commit()
