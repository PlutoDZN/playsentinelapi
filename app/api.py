from collections import deque
from datetime import datetime
from typing import Any, Dict

from fastapi import Depends, FastAPI, Header, HTTPException, Request, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .config import Settings
from .schemas import AnalyzeRequest, AnalyzeResponse, HealthResponse
from .store import InMemorySessionStore
from .detector import Detector
from .policy_engine import PolicyEngine


settings = Settings()
policy_engine = PolicyEngine()

if not settings.api_key:
    raise RuntimeError("PLAY_SENTINEL_API_KEY must be set")

app = FastAPI(title="PlaySentinel API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://plutodzn.github.io"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# store + detector
store = InMemorySessionStore(
    sessions_file=settings.sessions_path,
    max_messages=settings.max_session_messages,
    ttl_hours=settings.session_ttl_hours,
)

detector = Detector(
    keyword_file=settings.keywords_path,
    store=store,
    log_path=settings.incidents_log,
    alert_threshold=settings.alert_threshold,
    log_messages=settings.log_messages,
)

# in-memory rate limiter (sliding window)
_rate_store: Dict[str, deque] = {}
RATE_LIMIT_PER_MIN = settings.rate_limit_per_min


class ResetSessionRequest(BaseModel):
    user_id: str
    target_id: str
    platform: str = "discord"


def _check_api_key(x_api_key: str = Header(...)) -> str:
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="invalid api key")
    return x_api_key


def _rate_limit(request: Request, api_key: str = Depends(_check_api_key)):
    identifier = f"{api_key}:{request.client.host}"
    now = datetime.utcnow().timestamp()
    bucket = _rate_store.setdefault(identifier, deque())

    while bucket and bucket[0] <= now - 60:
        bucket.popleft()

    if len(bucket) >= RATE_LIMIT_PER_MIN:
        raise HTTPException(status_code=429, detail="rate limit exceeded", headers={"Retry-After": "60"})

    bucket.append(now)


def _cleanup_sessions() -> None:
    """Apply session TTL during normal traffic too, not only on debug endpoints."""
    try:
        store.cleanup()
    except Exception as exc:
        print(f"[SESSION CLEANUP WARN] {exc}")


def _delete_session(user_id: str, target_id: str) -> bool:
    """Delete one session, even if the store implementation has no public delete method."""
    key = (user_id, target_id)

    # Preferred explicit store methods
    for method_name in ("delete", "remove", "reset_session", "delete_session", "clear_session"):
        method = getattr(store, method_name, None)
        if callable(method):
            try:
                method(user_id, target_id)
                return True
            except TypeError:
                try:
                    method(key)
                    return True
                except Exception:
                    pass
            except Exception:
                pass

    # Fallback: mutate common dict attributes directly
    for attr_name in ("sessions", "_sessions", "store", "_store"):
        sessions_obj = getattr(store, attr_name, None)
        if isinstance(sessions_obj, dict) and key in sessions_obj:
            del sessions_obj[key]
            for save_name in ("save", "persist", "_save", "flush"):
                save_fn = getattr(store, save_name, None)
                if callable(save_fn):
                    try:
                        save_fn()
                    except Exception as exc:
                        print(f"[SESSION SAVE WARN] {exc}")
            return True

    return False


router = APIRouter(prefix="/v1", dependencies=[Depends(_rate_limit)])


@router.get("/health", response_model=HealthResponse)
def health():
    _cleanup_sessions()
    return HealthResponse(status="ok", active_sessions=len(store.snapshot()))


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    _cleanup_sessions()

    score, conv_risk, cats, matched, stage, lang, reasons = detector.analyze(
        req.message, user_id=req.user_id, target_id=req.target_id
    )

    risk_level = detector.get_risk_level(int(conv_risk))

    policy_result = policy_engine.evaluate({
        "risk_level": risk_level,
        "stage": stage,
    })

    return AnalyzeResponse(
        score=int(score),
        conversation_risk=int(conv_risk),
        risk_level=risk_level,
        stage=stage,
        language=lang,
        categories=cats,
        matched=matched,
        reasons=reasons,
        actions=policy_result.get("actions", []),
        action_reasons=policy_result.get("action_reasons", []),
        policy_version=policy_result.get("policy_version", ""),
    )


@router.get("/sessions")
def sessions():
    _cleanup_sessions()
    snaps = store.snapshot()
    out = {}
    for (u, t), s in snaps.items():
        conv = int(s.get("conversation_risk", 0))
        out[f"{u}→{t}"] = {
            "conversation_risk": conv,
            "risk_level": detector.get_risk_level(conv),
            "stage": s.get("stage", "LOW"),
            "messages_count": len(s.get("messages", [])),
            "updated_at": s.get("updated_at"),
        }
    return out


@router.get("/session/{user_id}/{target_id}")
def session(user_id: str, target_id: str):
    _cleanup_sessions()
    snaps = store.snapshot()
    key = (user_id, target_id)
    if key not in snaps:
        raise HTTPException(status_code=404, detail="Session not found")
    s = snaps[key]
    conv = int(s.get("conversation_risk", 0))
    return {
        "user_id": user_id,
        "target_id": target_id,
        "conversation_risk": conv,
        "risk_level": detector.get_risk_level(conv),
        "stage": s.get("stage", "LOW"),
        "messages": s.get("messages", []),
        "category_history": s.get("category_history", {}),
        "created_at": s.get("created_at"),
        "updated_at": s.get("updated_at"),
    }


@router.delete("/session/{user_id}/{target_id}")
def delete_session(user_id: str, target_id: str):
    _cleanup_sessions()
    deleted = _delete_session(user_id, target_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "status": "reset",
        "user_id": user_id,
        "target_id": target_id,
    }


@router.post("/reset_session")
def reset_session(req: ResetSessionRequest):
    _cleanup_sessions()
    deleted = _delete_session(req.user_id, req.target_id)
    if not deleted:
        return {
            "status": "no_session",
            "user_id": req.user_id,
            "target_id": req.target_id,
            "platform": req.platform,
        }
    return {
        "status": "reset",
        "user_id": req.user_id,
        "target_id": req.target_id,
        "platform": req.platform,
    }


app.include_router(router)
