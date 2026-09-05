"""Application entrypoint."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import config, worker
from .db import init_db
from .events import broker
from .routers import api, ui
from .templating import templates

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("volatilegui")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    broker.bind_loop(asyncio.get_running_loop())
    worker.start()
    log.info("%s %s ready — %d worker thread(s)", config.APP_NAME,
             config.VERSION, config.WORKERS)
    log.info("evidence dir: %s | data dir: %s", config.EVIDENCE_DIR,
             config.DATA_DIR)
    try:
        yield
    finally:
        worker.stop()


app = FastAPI(
    title=config.APP_NAME,
    description=config.APP_TAGLINE,
    version=config.VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(ui.router)
app.include_router(api.router)


@app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": "not found"}, status_code=404)
    return templates.TemplateResponse(request, "error.html",
        {"request": request, "code": 404, "title": "Not found",
         "message": "That page or record does not exist."},
        status_code=404)


@app.exception_handler(500)
async def server_error(request: Request, exc):
    log.exception("unhandled error on %s", request.url.path)
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": str(exc)}, status_code=500)
    return HTMLResponse(
        "<h1>500 — internal error</h1><pre>%s</pre>" % exc, status_code=500)
