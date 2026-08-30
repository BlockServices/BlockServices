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

import uvicorn
from  bsrv.main import logger
import os

if __name__ == "__main__":
    logger.log(20, "Starting server")
    if bool(int(os.getenv("DEBUG", False))):
        logger.log(20, "Running in debug mode")
        uvicorn.run("bsrv.main:app", reload=True, log_level="debug")
    else:
        logger.log(20, "Running in production mode")
        uvicorn.run("bsrv.main:app", host="0.0.0.0", port=8001,
                    ssl_keyfile=os.getenv("PRIVKEY_PATH"),
                    ssl_certfile=os.getenv("FULLCHAIN_PATH"))
