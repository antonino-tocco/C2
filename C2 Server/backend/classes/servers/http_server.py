import os
import signal
from threading import Thread
from time import sleep

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.classes.database import init_db
from backend.classes.helpers.seed import seed_admin
from backend.classes.routes import api_router
from .server import Server


def create_app() -> FastAPI:
    app = FastAPI(title="C2 Server")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router)

    @app.on_event("startup")
    async def on_startup():
        init_db()
        seed_admin()

    @app.on_event("shutdown")
    async def on_shutdown():
        print("Server shutting down...")
        sleep(1)

    return app


app = create_app()


class _HTTPServer:
    def __init__(self, port: int = 8000):
        self.__port = port

    def start(self):
        try:
            uvicorn.run(app, host="0.0.0.0", port=self.__port)
        except KeyboardInterrupt:
            print("Server stopped")
        except Exception as e:
            print(e)

    def stop(self):
        os.kill(os.getpid(), signal.SIGTERM)
        print("Server stopped")


class HttpServer(Server):
    def __init__(self, port: int = 8000):
        super().__init__()
        self.__port = port
        self.__server = _HTTPServer(self.__port)
        self._thread = Thread(target=self.__server.start)

    def start(self):
        print(f"Server starting at port: {self.__port}")
        self._thread.start()
        print(f"Server started at port: {self.__port}")

    def stop(self):
        self.__server.stop()
        self._thread.join()


if __name__ == "__main__":
    server = HttpServer()
    try:
        server.start()
    except Exception as e:
        print(f"There was an error running the server: {e}")

    while True:
        try:
            sleep(1)
        except KeyboardInterrupt:
            server.stop()
            break
