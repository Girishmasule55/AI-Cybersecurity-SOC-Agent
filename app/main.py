from fastapi import FastAPI

from app.api.routes import router
from app.core.config import get_settings
from app.db.session import Base, engine
from app.models import soc  # noqa: F401


settings = get_settings()
app = FastAPI(title=settings.app_name)


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(router)
