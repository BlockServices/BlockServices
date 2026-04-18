import uvicorn
from  bsrv.main import logger
import os

if __name__ == "__main__":
    logger.log(20, "Starting server")
    if bool(int(os.getenv("DEBUG", False))):
        logger.log(20, "Debug mode enabled")
        uvicorn.run("bsrv.main:app", reload=True, log_level="debug")
    else:
        logger.log(20, "Running in production mode")
        uvicorn.run("bsrv.main:app", host="0.0.0.0", port=8443,
                    ssl_keyfile=os.getenv("PRIVKEY_PATH"),
                    ssl_certfile=os.getenv("FULLCHAIN_PATH"))
