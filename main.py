import os
import json
import time
import uuid
import hmac
import hashlib
import secrets
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Optional, Literal

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, Header, Depends, status, Request, Form, File, UploadFile
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="Portal Les Privat Kak Fiona",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
TEACHER_PIN = os.getenv("TEACHER_PIN", "").strip()
_raw_supabase_url = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
for _suffix in ("/rest/v1", "/storage/v1"):
    if _raw_supabase_url.endswith(_suffix):
        _raw_supabase_url = _raw_supabase_url[: -len(_suffix)]
SUPABASE_URL = _raw_supabase_url
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
STORAGE_BUCKET = "attendance-proofs"
SESSION_TTL_SECONDS = 7 * 24 * 3600
MAX_IMAGE_BYTES = 3 * 1024 * 1024  # Maksimal 3 MB setelah kompresi browser

# --- In-Memory Rate Limiter ---
_rate_buckets: dict[str, list[float]] = defaultdict(list)


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def enforce_rate_limit(request: Request, scope: str, max_hits: int, window_sec: int):
    now = time.time()
    key = f"{scope}:{get_client_ip(request)}"
    timestamps = [t for t in _rate_buckets[key] if now - t < window_sec]
    if len(timestamps) >= max_hits:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Terlalu banyak percobaan. Silakan tunggu beberapa menit lalu coba lagi.",
        )
    timestamps.append(now)
    _rate_buckets[key] = timestamps


# --- Token Sesi HMAC-SHA256 ---
def _require_configured_pin() -> str:
    if not TEACHER_PIN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Konfigurasi PIN server belum diatur.",
        )
    return TEACHER_PIN


def create_session_token(secret_pin: str) -> str:
    expires_at = int(time.time()) + SESSION_TTL_SECONDS
    payload = f"teacher:{expires_at}".encode("utf-8")
    sig = hmac.new(secret_pin.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"{expires_at}.{sig}"


def is_valid_session_token(token: Optional[str]) -> bool:
    if not token or not TEACHER_PIN or "." not in token:
        return False
    try:
        expires_str, sig = token.split(".", 1)
        expires_at = int(expires_str)
        if expires_at <= int(time.time()):
            return False
        expected_payload = f"teacher:{expires_at}".encode("utf-8")
        expected_sig = hmac.new(
            TEACHER_PIN.encode("utf-8"), expected_payload, hashlib.sha256
        ).hexdigest()
        return secrets.compare_digest(sig, expected_sig)
    except (ValueError, TypeError):
        return False


# --- Helper Supabase Storage (Ringan tanpa SDK eksternal) ---
def detect_image_type(data: bytes) -> Optional[tuple[str, str]]:
    if data[:3] == b"\xff\xd8\xff":
        return ("image/jpeg", "jpg")
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return ("image/png", "png")
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ("image/webp", "webp")
    return None


def upload_proof_to_supabase(file_bytes: bytes, content_type: str, ext: str) -> str:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Konfigurasi SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY belum diatur di server.",
        )

    object_path = f"{datetime.now(timezone.utc).strftime('%Y/%m')}/{uuid.uuid4().hex}.{ext}"
    url = f"{SUPABASE_URL}/storage/v1/object/{STORAGE_BUCKET}/{object_path}"
    req = urllib.request.Request(
        url,
        data=file_bytes,
        method="POST",
        headers={
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Content-Type": content_type,
            "x-upsert": "true",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status not in (200, 201):
                raise RuntimeError(f"Storage status {resp.status}")
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Gagal upload ke Supabase Storage ({e.code}): {err_body}")

    return object_path


def create_signed_proof_url(object_path: str, expires_in: int = 300) -> str:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=503, detail="Konfigurasi Storage belum diatur.")

    url = f"{SUPABASE_URL}/storage/v1/object/sign/{STORAGE_BUCKET}/{object_path}"
    body = json.dumps({"expiresIn": expires_in}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
        signed_rel = payload.get("signedURL") or payload.get("signedUrl")
        if not signed_rel:
            raise RuntimeError("Signed URL tidak ditemukan dari respons Supabase.")
        if signed_rel.startswith("http"):
            return signed_rel
        return f"{SUPABASE_URL}/storage/v1{signed_rel}"


def delete_proof_from_supabase(object_path: Optional[str]):
    if not object_path or not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        return
    url = f"{SUPABASE_URL}/storage/v1/object/{STORAGE_BUCKET}/{object_path}"
    req = urllib.request.Request(
        url,
        method="DELETE",
        headers={
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception:
        pass


# --- Security Headers Middleware ---
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://vercel.live; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://vercel.live; "
        "font-src 'self' https://fonts.gstatic.com https://vercel.live; "
        "img-src 'self' data: blob: https://*.supabase.co https://vercel.live; "
        "connect-src 'self' https://vercel.live wss://ws-us3.pusher.com; "
        "frame-src 'self' https://vercel.live; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    token = request.headers.get("x-teacher-pin")
    if is_valid_session_token(token):
        return JSONResponse(
            status_code=500,
            content={"detail": f"{type(exc).__name__}: {str(exc)}"},
        )
    return JSONResponse(
        status_code=500,
        content={"detail": "Terjadi kesalahan internal pada server. Silakan coba lagi."},
    )


def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL belum diatur di environment variables.")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


# --- Schemas ---
class TeacherLogin(BaseModel):
    pin: str = Field(..., min_length=4, max_length=64)


class LogCreate(BaseModel):
    student_id: int = Field(..., gt=0)
    date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    attendance_status: Literal["Hadir", "Izin", "Sakit", "Alpa"]
    topic: Optional[str] = Field(default="", max_length=250)
    score: Optional[str] = Field(default=None, max_length=5)
    notes: Optional[str] = Field(default="", max_length=1000)

    @field_validator("date")
    @classmethod
    def validate_real_date(cls, v: str) -> str:
        datetime.strptime(v, "%Y-%m-%d")
        return v

    @field_validator("score")
    @classmethod
    def validate_score(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        cleaned = v.strip().upper()
        if cleaned not in {"A", "B", "C"}:
            raise ValueError("Predikat nilai harus A, B, atau C.")
        return cleaned


class ScheduleUpdate(BaseModel):
    schedule_days: str = Field(..., min_length=2, max_length=100)
    schedule_time: str = Field(..., min_length=3, max_length=50)
    access_code: str = Field(
        ..., min_length=5, max_length=32, pattern=r"^[A-Za-z0-9_-]+$"
    )


def verify_teacher(request: Request, x_teacher_pin: str = Header(None)):
    enforce_rate_limit(request, "admin_api", max_hits=60, window_sec=60)
    if not is_valid_session_token(x_teacher_pin):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesi guru tidak valid atau sudah kedaluwarsa. Silakan login ulang.",
        )
    return True


# --- Public / Parent Endpoints ---
@app.get("/")
def serve_home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/portal/{access_code}")
def get_parent_portal(access_code: str, request: Request):
    enforce_rate_limit(request, "parent_portal", max_hits=15, window_sec=60)

    cleaned_code = access_code.strip()
    if not cleaned_code or len(cleaned_code) > 32:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Format kode akses tidak valid.",
        )

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, name, schedule_days, schedule_time FROM students WHERE UPPER(access_code) = UPPER(%s)",
            (cleaned_code,),
        )
        student = cur.fetchone()
        if not student:
            time.sleep(0.4)
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Kode akses murid tidak ditemukan.",
            )

        cur.execute(
            """
            SELECT id, date, logged_at, attendance_status, topic, score, notes, proof_path
            FROM learning_logs
            WHERE student_id = %s
            ORDER BY date DESC, id DESC
            """,
            (student["id"],),
        )
        raw_logs = cur.fetchall()
        logs = []
        for row in raw_logs:
            item = dict(row)
            item["has_proof"] = bool(item.pop("proof_path", None))
            logs.append(item)
    finally:
        cur.close()
        conn.close()

    hadir_count = sum(1 for l in logs if l["attendance_status"] == "Hadir")
    absent_count = sum(1 for l in logs if l["attendance_status"] != "Hadir")

    grade_points = {"A": 3, "B": 2, "C": 1}
    valid_points = [
        grade_points[str(l["score"]).upper()]
        for l in logs
        if l["score"] and str(l["score"]).upper() in grade_points
    ]

    if valid_points:
        avg_num = sum(valid_points) / len(valid_points)
        if avg_num >= 2.5:
            avg_grade = "A"
        elif avg_num >= 1.5:
            avg_grade = "B"
        else:
            avg_grade = "C"
    else:
        avg_grade = None

    return {
        "student": dict(student),
        "summary": {
            "hadir": hadir_count,
            "tidak_masuk": absent_count,
            "rata_rata_nilai": avg_grade,
        },
        "logs": logs,
    }


@app.get("/api/portal/{access_code}/proof/{log_id}")
def get_parent_proof_photo(access_code: str, log_id: int, request: Request):
    enforce_rate_limit(request, "parent_proof", max_hits=30, window_sec=60)
    cleaned_code = access_code.strip()
    if not cleaned_code or len(cleaned_code) > 32 or log_id <= 0:
        raise HTTPException(status_code=400, detail="Permintaan tidak valid.")

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT l.proof_path
            FROM learning_logs l
            JOIN students s ON l.student_id = s.id
            WHERE l.id = %s AND UPPER(s.access_code) = UPPER(%s)
            """,
            (log_id, cleaned_code),
        )
        row = cur.fetchone()
    finally:
        cur.close()
        conn.close()

    if not row or not row.get("proof_path"):
        raise HTTPException(status_code=404, detail="Bukti absensi tidak ditemukan.")

    signed_url = create_signed_proof_url(row["proof_path"], expires_in=300)
    return {"url": signed_url}


# --- Teacher Admin Endpoints ---
@app.post("/api/admin/login")
def teacher_login(payload: TeacherLogin, request: Request):
    enforce_rate_limit(request, "teacher_login", max_hits=5, window_sec=300)
    secret_pin = _require_configured_pin()

    if not secrets.compare_digest(payload.pin.strip(), secret_pin):
        time.sleep(0.6)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="PIN Guru salah.",
        )

    return {"status": "ok", "token": create_session_token(secret_pin)}


@app.get("/api/admin/overview", dependencies=[Depends(verify_teacher)])
def admin_overview():
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM students ORDER BY id ASC")
        students = [dict(row) for row in cur.fetchall()]

        cur.execute(
            """
            SELECT l.*, s.name AS student_name
            FROM learning_logs l
            JOIN students s ON l.student_id = s.id
            ORDER BY l.date DESC, l.id DESC
            """
        )
        logs = []
        for row in cur.fetchall():
            item = dict(row)
            item["has_proof"] = bool(item.pop("proof_path", None))
            logs.append(item)
    finally:
        cur.close()
        conn.close()

    return {"students": students, "logs": logs}


@app.get("/api/admin/logs/{log_id}/proof", dependencies=[Depends(verify_teacher)])
def get_admin_proof_photo(log_id: int):
    if log_id <= 0:
        raise HTTPException(status_code=400, detail="ID laporan tidak valid.")

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT proof_path FROM learning_logs WHERE id = %s", (log_id,))
        row = cur.fetchone()
    finally:
        cur.close()
        conn.close()

    if not row or not row.get("proof_path"):
        raise HTTPException(status_code=404, detail="Bukti absensi tidak ditemukan.")

    signed_url = create_signed_proof_url(row["proof_path"], expires_in=300)
    return {"url": signed_url}


@app.post("/api/admin/logs", dependencies=[Depends(verify_teacher)])
async def create_log(
    student_id: int = Form(...),
    date: str = Form(...),
    attendance_status: str = Form(...),
    topic: str = Form(""),
    score: str = Form(""),
    notes: str = Form(""),
    proof_file: Optional[UploadFile] = File(None),
):
    validated = LogCreate(
        student_id=student_id,
        date=date,
        attendance_status=attendance_status,
        topic=topic,
        score=score if score.strip() else None,
        notes=notes,
    )

    proof_path: Optional[str] = None
    if proof_file and proof_file.filename:
        file_bytes = await proof_file.read()
        if len(file_bytes) > MAX_IMAGE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Ukuran foto terlalu besar (maksimal 3 MB).",
            )
        detected = detect_image_type(file_bytes)
        if not detected:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Format file harus berupa gambar JPG, PNG, atau WEBP.",
            )
        content_type, ext = detected
        proof_path = upload_proof_to_supabase(file_bytes, content_type, ext)

    conn = get_db()
    cur = conn.cursor()
    try:
        clean_topic = (validated.topic or "").strip() if validated.attendance_status == "Hadir" else "-"
        clean_score = validated.score if validated.attendance_status == "Hadir" else None
        clean_notes = (validated.notes or "").strip()

        wib = timezone(timedelta(hours=7))
        current_time_str = datetime.now(wib).strftime("%H:%M")

        cur.execute(
            """
            INSERT INTO learning_logs (student_id, date, logged_at, attendance_status, topic, score, notes, proof_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                validated.student_id,
                validated.date,
                current_time_str,
                validated.attendance_status,
                clean_topic,
                clean_score,
                clean_notes,
                proof_path,
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        delete_proof_from_supabase(proof_path)
        raise
    finally:
        cur.close()
        conn.close()

    return {"status": "created"}

@app.put("/api/admin/logs/{log_id}", dependencies=[Depends(verify_teacher)])
async def update_log(
    log_id: int,
    student_id: int = Form(...),
    date: str = Form(...),
    attendance_status: str = Form(...),
    topic: str = Form(""),
    score: str = Form(""),
    notes: str = Form(""),
    remove_proof: bool = Form(False),
    proof_file: Optional[UploadFile] = File(None),
):
    if log_id <= 0:
        raise HTTPException(status_code=400, detail="ID laporan tidak valid.")

    validated = LogCreate(
        student_id=student_id,
        date=date,
        attendance_status=attendance_status,
        topic=topic,
        score=score if score.strip() else None,
        notes=notes,
    )

    new_proof_path: Optional[str] = None
    has_new_file = bool(proof_file and proof_file.filename)

    if has_new_file:
        file_bytes = await proof_file.read()
        if len(file_bytes) > MAX_IMAGE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Ukuran foto terlalu besar (maksimal 3 MB).",
            )
        detected = detect_image_type(file_bytes)
        if not detected:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Format file harus berupa gambar JPG, PNG, atau WEBP.",
            )
        content_type, ext = detected
        new_proof_path = upload_proof_to_supabase(file_bytes, content_type, ext)

    conn = get_db()
    cur = conn.cursor()
    old_proof_path: Optional[str] = None
    try:
        cur.execute("SELECT proof_path FROM learning_logs WHERE id = %s", (log_id,))
        existing = cur.fetchone()
        if not existing:
            delete_proof_from_supabase(new_proof_path)
            raise HTTPException(status_code=404, detail="Laporan tidak ditemukan.")

        old_proof_path = existing.get("proof_path")

        if has_new_file:
            final_proof_path = new_proof_path
        elif remove_proof:
            final_proof_path = None
        else:
            final_proof_path = old_proof_path

        clean_topic = (validated.topic or "").strip() if validated.attendance_status == "Hadir" else "-"
        clean_score = validated.score if validated.attendance_status == "Hadir" else None
        clean_notes = (validated.notes or "").strip()

        cur.execute(
            """
            UPDATE learning_logs
            SET student_id = %s,
                date = %s,
                attendance_status = %s,
                topic = %s,
                score = %s,
                notes = %s,
                proof_path = %s
            WHERE id = %s
            """,
            (
                validated.student_id,
                validated.date,
                validated.attendance_status,
                clean_topic,
                clean_score,
                clean_notes,
                final_proof_path,
                log_id,
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        delete_proof_from_supabase(new_proof_path)
        raise
    finally:
        cur.close()
        conn.close()

    # Hapus foto lama di Supabase Storage jika diganti foto baru atau dihapus
    if old_proof_path and (has_new_file or remove_proof):
        delete_proof_from_supabase(old_proof_path)

    return {"status": "updated"}

@app.delete("/api/admin/logs/{log_id}", dependencies=[Depends(verify_teacher)])
def delete_log(log_id: int):
    if log_id <= 0:
        raise HTTPException(status_code=400, detail="ID laporan tidak valid.")

    conn = get_db()
    cur = conn.cursor()
    proof_path = None
    try:
        cur.execute("SELECT proof_path FROM learning_logs WHERE id = %s", (log_id,))
        row = cur.fetchone()
        if row:
            proof_path = row.get("proof_path")

        cur.execute("DELETE FROM learning_logs WHERE id = %s", (log_id,))
        conn.commit()
    finally:
        cur.close()
        conn.close()

    delete_proof_from_supabase(proof_path)
    return {"status": "deleted"}


@app.put("/api/admin/students/{student_id}", dependencies=[Depends(verify_teacher)])
def update_student_schedule(student_id: int, payload: ScheduleUpdate):
    if student_id <= 0:
        raise HTTPException(status_code=400, detail="ID murid tidak valid.")

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE students
            SET schedule_days = %s, schedule_time = %s, access_code = UPPER(%s)
            WHERE id = %s
            """,
            (
                payload.schedule_days.strip(),
                payload.schedule_time.strip(),
                payload.access_code.strip(),
                student_id,
            ),
        )
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Kode akses tersebut sudah digunakan oleh murid lain.",
        )
    finally:
        cur.close()
        conn.close()

    return {"status": "updated"}


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")