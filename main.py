import os
from pathlib import Path
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Portal Les Privat Kak Fiona")

DATABASE_URL = os.getenv("DATABASE_URL")
TEACHER_PIN = os.getenv("TEACHER_PIN", "FIONA2026")


def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL belum diatur di environment variables.")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            access_code TEXT UNIQUE NOT NULL,
            schedule_days TEXT NOT NULL,
            schedule_time TEXT DEFAULT '15:30 - 17:00'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS learning_logs (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
            date TEXT NOT NULL,
            attendance_status TEXT NOT NULL,
            topic TEXT,
            score TEXT,
            notes TEXT
        )
    """)

    # Seed data Sahla & Bina (bersih tanpa dummy log) jika database baru pertama dibuat
    cur.execute("SELECT COUNT(*) AS total FROM students")
    if cur.fetchone()["total"] == 0:
        cur.executemany(
            "INSERT INTO students (name, access_code, schedule_days, schedule_time) VALUES (%s, %s, %s, %s)",
            [
                ("Sahla", "SAHLA2026", "Senin, Selasa, Rabu, Kamis", "15:30 - 17:00"),
                ("Bina", "BINA2026", "Senin, Rabu", "16:00 - 17:30"),
            ],
        )

    conn.commit()
    cur.close()
    conn.close()


@app.on_event("startup")
def startup_event():
    init_db()


# --- Schemas ---
class TeacherLogin(BaseModel):
    pin: str


class LogCreate(BaseModel):
    student_id: int
    date: str
    attendance_status: str
    topic: Optional[str] = ""
    score: Optional[str] = None
    notes: Optional[str] = ""


class ScheduleUpdate(BaseModel):
    schedule_days: str
    schedule_time: str
    access_code: str


# --- Auth Dependency ---
def verify_teacher(x_teacher_pin: str = Header(None)):
    if x_teacher_pin != TEACHER_PIN:
        raise HTTPException(status_code=401, detail="PIN Guru tidak valid.")
    return True


# --- Public / Parent Endpoints ---
@app.get("/")
def serve_home():
    return FileResponse("static/index.html")


@app.get("/api/portal/{access_code}")
def get_parent_portal(access_code: str):
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM students WHERE UPPER(access_code) = UPPER(%s)",
        (access_code.strip(),),
    )
    student = cur.fetchone()
    if not student:
        cur.close()
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Kode akses murid tidak ditemukan.",
        )

    cur.execute(
        """
        SELECT * FROM learning_logs
        WHERE student_id = %s
        ORDER BY date DESC, id DESC
        """,
        (student["id"],),
    )
    logs = [dict(row) for row in cur.fetchall()]
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


# --- Teacher Admin Endpoints ---
@app.post("/api/admin/login")
def teacher_login(payload: TeacherLogin):
    if payload.pin.strip() != TEACHER_PIN:
        raise HTTPException(status_code=401, detail="PIN Guru salah.")
    return {"status": "ok", "token": TEACHER_PIN}


@app.get("/api/admin/overview", dependencies=[Depends(verify_teacher)])
def admin_overview():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM students ORDER BY id ASC")
    students = [dict(row) for row in cur.fetchall()]

    cur.execute("""
        SELECT l.*, s.name AS student_name
        FROM learning_logs l
        JOIN students s ON l.student_id = s.id
        ORDER BY l.date DESC, l.id DESC
    """)
    logs = [dict(row) for row in cur.fetchall()]
    cur.close()
    conn.close()

    return {"students": students, "logs": logs}


@app.post("/api/admin/logs", dependencies=[Depends(verify_teacher)])
def create_log(payload: LogCreate):
    conn = get_db()
    cur = conn.cursor()

    topic = payload.topic if payload.attendance_status == "Hadir" else "-"
    score = (
        payload.score.strip().upper()
        if (payload.attendance_status == "Hadir" and payload.score)
        else None
    )

    cur.execute(
        """
        INSERT INTO learning_logs (student_id, date, attendance_status, topic, score, notes)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            payload.student_id,
            payload.date,
            payload.attendance_status,
            topic,
            score,
            payload.notes,
        ),
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"status": "created"}


@app.delete("/api/admin/logs/{log_id}", dependencies=[Depends(verify_teacher)])
def delete_log(log_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM learning_logs WHERE id = %s", (log_id,))
    conn.commit()
    cur.close()
    conn.close()
    return {"status": "deleted"}


@app.put("/api/admin/students/{student_id}", dependencies=[Depends(verify_teacher)])
def update_student_schedule(student_id: int, payload: ScheduleUpdate):
    conn = get_db()
    cur = conn.cursor()
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
    cur.close()
    conn.close()
    return {"status": "updated"}


app.mount("/static", StaticFiles(directory="static"), name="static")