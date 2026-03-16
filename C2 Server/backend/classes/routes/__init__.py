from fastapi import APIRouter

from backend.classes.routes.auth_routes import router as auth_router
from backend.classes.routes.target_routes import router as target_router
from backend.classes.routes.command_routes import router as command_router
from backend.classes.routes.agent_routes import router as agent_router
from backend.classes.routes.dropper_routes import router as dropper_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth_router)
api_router.include_router(target_router)
api_router.include_router(command_router)
api_router.include_router(agent_router)
api_router.include_router(dropper_router)
