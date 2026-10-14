
import os
import sqlite3
import secrets
import functools
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort, g
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)

BASE = Path(__file__).resolve().parent

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get(
        "SECRET_KEY", secrets.token_hex(32)
    ),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get("COOKIE_SECURE", "0") == "1"
    ),
    MAX_CONTENT_LENGTH=1024 * 1024
)

DB_PATH = os.environ.get(
    "DATABASE_PATH",
    str(BASE / "cyberaware.sqlite3")
)

# ==========================================
# SIX CYBERSECURITY TRAINING MODULES
# ==========================================

MODULES = [
    (
        1, "Phishing Awareness",
        "Recognise fake emails and messages",
        "Phishing is when a criminal pretends to be someone "
        "you trust to steal information. The message may ask "
        "you to click a link, open a file or enter a password. "
        "It may look like it came from your bank, employer or "
        "delivery company.",
        "Check the sender address carefully.|"
        "Be cautious of urgent requests and unexpected attachments.|"
        "Do not enter passwords after clicking an unexpected link.|"
        "Report suspicious messages to your IT or security team.",
        "Suspicious message",
        "Pause and check",
        "Report or delete",
        "#2563eb"
    ),
    (
        2, "Password Security",
        "Build strong account protection",
        "A password protects your account. Weak, reused passwords "
        "make it easier for an attacker to access several systems. "
        "A long, unique passphrase is easier to remember and harder "
        "to guess. A password manager can generate and store unique "
        "passwords.",
        "Use a long and unique password for each service.|"
        "Store passwords in an approved password manager.|"
        "Never share passwords or verification codes.|"
        "Change credentials promptly if you suspect compromise.",
        "Unique passphrase",
        "Password manager",
        "Protected account",
        "#8b5cf6"
    ),
    (
        3, "Social Engineering",
        "Verify unusual requests",
        "Social engineering is when someone tricks a person into "
        "sharing data, money or access. Criminals can impersonate "
        "a manager or colleague. They might call, text or send a "
        "convincing email and create a feeling of urgency.",
        "Verify payment or account changes using a trusted channel.|"
        "Do not trust a caller just because they know a name.|"
        "Never bypass security checks for urgent requests.|"
        "Inform your supervisor or IT team about suspicious contact.",
        "Unexpected request",
        "Verify identity",
        "Act safely",
        "#db2777"
    ),
    (
        4, "Malware Protection",
        "Keep devices and files safe",
        "Malware is harmful software such as ransomware, spyware "
        "and viruses. It can arrive through unsafe downloads, "
        "infected attachments or compromised websites. Updated "
        "software and careful file handling reduce the risk.",
        "Install software only from approved sources.|"
        "Keep operating systems and apps updated.|"
        "Do not open unknown attachments or macros.|"
        "Report unusual pop-ups, lock screens or device behaviour.",
        "Unknown file",
        "Scan and verify",
        "Safe device",
        "#ea580c"
    ),
    (
        5, "Safe Browsing",
        "Stay alert on websites",
        "Websites can imitate trusted organisations. HTTPS encrypts "
        "the connection but does not guarantee that a website is "
        "honest. Check addresses before logging in, and be careful "
        "with downloads, browser warnings and public Wi-Fi.",
        "Check the full website address before entering details.|"
        "Do not ignore browser security warnings.|"
        "Avoid unexpected downloads and suspicious advertisements.|"
        "Use company-approved tools when accessing work data remotely.",
        "Open link",
        "Inspect address",
        "Browse safely",
        "#0891b2"
    ),
    (
        6, "Multi-Factor Authentication",
        "Add a second verification step",
        "Multi-factor authentication (MFA) asks for another proof "
        "of identity in addition to a password. This may be an "
        "authenticator app or hardware security key. MFA helps "
        "even if a password is stolen, but attackers may still "
        "try to trick you into approving requests.",
        "Use an approved authenticator or security key.|"
        "Never share a one-time code with anyone.|"
        "Reject unexpected MFA approval requests.|"
        "Report repeated or suspicious prompts immediately.",
        "Enter password",
        "Verify second factor",
        "Access account",
        "#16a34a"
    )
]


# ==========================================
# DATABASE CONNECTION
# ==========================================

def db():
    if "db" not in g:
        p = Path(DB_PATH)
        p.parent.mkdir(parents=True, exist_ok=True)

        g.db = sqlite3.connect(str(p), timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")

    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def initialize():
    d = db()

    d.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(
                role IN ('admin','employee')
            ),
            must_change INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS assignments(
            user_id INTEGER NOT NULL
                REFERENCES users(id) ON DELETE CASCADE,
            module_id INTEGER NOT NULL
                CHECK(module_id BETWEEN 1 AND 6),
            PRIMARY KEY(user_id,module_id)
        );

        CREATE TABLE IF NOT EXISTS progress(
            user_id INTEGER NOT NULL
                REFERENCES users(id) ON DELETE CASCADE,
            module_id INTEGER NOT NULL
                CHECK(module_id BETWEEN 1 AND 6),
            completed_at TEXT NOT NULL,
            PRIMARY KEY(user_id,module_id)
        );

        CREATE TABLE IF NOT EXISTS quiz_attempts(
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL
                REFERENCES users(id) ON DELETE CASCADE,
            module_id INTEGER NOT NULL
                CHECK(module_id BETWEEN 1 AND 6),
            correct INTEGER NOT NULL,
            total INTEGER NOT NULL,
            taken_at TEXT NOT NULL
        );
    """)

    email = os.environ.get(
        "ADMIN_EMAIL", ""
    ).strip().lower()

    password = os.environ.get(
        "ADMIN_PASSWORD", ""
    )

    if email and len(password) >= 12:
        admin = d.execute(
            "SELECT id FROM users "
            "WHERE role='admin' LIMIT 1"
        ).fetchone()

        if not admin:
            d.execute(
                "INSERT INTO users("
                "name,email,password_hash,role"
                ") VALUES(?,?,?,?)",
                (
                    "CyberAware Admin",
                    email,
                    generate_password_hash(password),
                    "admin"
                )
            )

    d.commit()


# ==========================================
# SECURITY AND AUTHENTICATION
# ==========================================

@app.before_request
def prepare():
    if request.endpoint == "static":
        return

    initialize()
    g.user = None

    uid = session.get("uid")

    if uid:
        g.user = db().execute(
            "SELECT * FROM users WHERE id=?",
            (uid,)
        ).fetchone()

    if request.method == "POST":
        if not secrets.compare_digest(
            str(session.get("csrf", "")),
            str(request.form.get("_csrf", "x"))
        ):
            abort(
                400,
                "Invalid security token. Refresh and try again."
            )

    if (
        g.user
        and g.user["must_change"]
        and request.endpoint not in (
            "change_password",
            "logout",
            "static"
        )
    ):
        return redirect(
            url_for("change_password")
        )


@app.context_processor
def common():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)

    return {
        "csrf": session["csrf"],
        "current_user": g.get("user")
    }


def login_required(role=None):
    def deco(fn):
        @functools.wraps(fn)
        def inner(*a, **kw):
            if not g.user:
                return redirect(
                    url_for("login")
                )

            if role and g.user["role"] != role:
                abort(403)

            return fn(*a, **kw)

        return inner

    return deco


def module_by_id(mid):
    return next(
        (m for m in MODULES if m[0] == mid),
        None
    )


def assigned(uid):
    return {
        r["module_id"]
        for r in db().execute(
            "SELECT module_id FROM assignments "
            "WHERE user_id=?",
            (uid,)
        )
    }


# ==========================================
# HOME AND LOGIN
# ==========================================

@app.route("/")
def home():
    if not g.user:
        return redirect(
            url_for("login")
        )

    if g.user["role"] == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    return redirect(
        url_for("my_training")
    )


@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():
    if request.method == "POST":
        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        user = db().execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        ).fetchone()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):
            session.clear()

            session["uid"] = user["id"]
            session["csrf"] = secrets.token_urlsafe(32)

            return redirect(
                url_for("home")
            )

        flash(
            "Invalid email or password.",
            "error"
        )

    has_admin = bool(
        db().execute(
            "SELECT 1 FROM users WHERE role='admin'"
        ).fetchone()
    )

    return render_template(
        "login.html",
        has_admin=has_admin
    )


@app.post("/logout")
def logout():
    session.clear()

    return redirect(
        url_for("login")
    )


# ==========================================
# CHANGE PASSWORD
# ==========================================

@app.route(
    "/change-password",
    methods=["GET", "POST"]
)
@login_required()
def change_password():
    if request.method == "POST":
        old = request.form.get(
            "old_password", ""
        )

        new = request.form.get(
            "new_password", ""
        )

        if not check_password_hash(
            g.user["password_hash"],
            old
        ):
            flash(
                "Current password is incorrect.",
                "error"
            )

        elif len(new) < 12:
            flash(
                "Use at least 12 characters.",
                "error"
            )

        else:
            db().execute(
                "UPDATE users SET "
                "password_hash=?, must_change=0 "
                "WHERE id=?",
                (
                    generate_password_hash(new),
                    g.user["id"]
                )
            )

            db().commit()

            flash(
                "Password changed successfully.",
                "success"
            )

            return redirect(
                url_for("home")
            )

    return render_template(
        "password.html"
    )


# ==========================================
# ADMIN DASHBOARD
# ==========================================

@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    employees = db().execute(
        "SELECT id,name,email FROM users "
        "WHERE role='employee' ORDER BY name"
    ).fetchall()

    data = []

    for e in employees:
        aids = assigned(e["id"])

        finished = {
            r["module_id"]
            for r in db().execute(
                "SELECT module_id FROM progress "
                "WHERE user_id=?",
                (e["id"],)
            )
        }

        data.append({
            "user": e,
            "assigned": len(aids),
            "completed": len(aids & finished)
        })

    return render_template(
        "admin.html",
        employees=data,
        modules=MODULES
    )


# ==========================================
# ADD NEW EMPLOYEE
# ==========================================

@app.route(
    "/admin/employees/new",
    methods=["GET", "POST"]
)
@login_required("admin")
def add_employee():
    if request.method == "POST":
        name = request.form.get(
            "name", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        selected = request.form.getlist(
            "modules"
        )

        valid_ids = {
            str(m[0]) for m in MODULES
        }

        if (
            not name
            or len(name) > 100
            or "@" not in email
            or len(email) > 200
        ):
            flash(
                "Enter a valid name and email.",
                "error"
            )

        elif (
            not selected
            or not all(
                x in valid_ids for x in selected
            )
        ):
            flash(
                "Choose at least one valid training module.",
                "error"
            )

        else:
            password = secrets.token_urlsafe(15)

            try:
                cur = db().execute(
                    "INSERT INTO users("
                    "name,email,password_hash,role,must_change"
                    ") VALUES(?,?,?,?,1)",
                    (
                        name,
                        email,
                        generate_password_hash(password),
                        "employee"
                    )
                )

                db().executemany(
                    "INSERT INTO assignments("
                    "user_id,module_id"
                    ") VALUES(?,?)",
                    [
                        (cur.lastrowid, int(x))
                        for x in set(selected)
                    ]
                )

                db().commit()

                return render_template(
                    "credentials.html",
                    email=email,
                    password=password,
                    name=name
                )

            except sqlite3.IntegrityError:
                db().rollback()

                flash(
                    "An account with this email already exists.",
                    "error"
                )

    return render_template(
        "employee_form.html",
        modules=MODULES,
        employee=None,
        chosen=set()
    )


# ==========================================
# EDIT EMPLOYEE AND ASSIGNED MODULES
# ==========================================

@app.route(
    "/admin/employees/<int:uid>/edit",
    methods=["GET", "POST"]
)
@login_required("admin")
def edit_employee(uid):
    employee = db().execute(
        "SELECT * FROM users "
        "WHERE id=? AND role='employee'",
        (uid,)
    ).fetchone()

    if not employee:
        abort(404)

    if request.method == "POST":
        name = request.form.get(
            "name", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        selected = request.form.getlist(
            "modules"
        )

        valid_ids = {
            str(m[0]) for m in MODULES
        }

        if (
            not name
            or "@" not in email
            or len(name) > 100
            or len(email) > 200
            or not selected
            or not all(
                x in valid_ids for x in selected
            )
        ):
            flash(
                "Provide a valid name, email and at least one module.",
                "error"
            )

        else:
            try:
                db().execute(
                    "UPDATE users "
                    "SET name=?, email=? WHERE id=?",
                    (name, email, uid)
                )

                db().execute(
                    "DELETE FROM assignments "
                    "WHERE user_id=?",
                    (uid,)
                )

                db().executemany(
                    "INSERT INTO assignments("
                    "user_id,module_id"
                    ") VALUES(?,?)",
                    [
                        (uid, int(x))
                        for x in set(selected)
                    ]
                )

                db().commit()

                flash(
                    "Employee details and module assignments saved.",
                    "success"
                )

                return redirect(
                    url_for("admin_dashboard")
                )

            except sqlite3.IntegrityError:
                db().rollback()

                flash(
                    "This email is already in use.",
                    "error"
                )

    return render_template(
        "employee_form.html",
        modules=MODULES,
        employee=employee,
        chosen=assigned(uid)
    )


# ==========================================
# RESET EMPLOYEE PASSWORD
# ==========================================

@app.post(
    "/admin/employees/<int:uid>/reset"
)
@login_required("admin")
def reset_employee(uid):
    employee = db().execute(
        "SELECT * FROM users "
        "WHERE id=? AND role='employee'",
        (uid,)
    ).fetchone()

    if not employee:
        abort(404)

    password = secrets.token_urlsafe(15)

    db().execute(
        "UPDATE users SET "
        "password_hash=?, must_change=1 "
        "WHERE id=?",
        (
            generate_password_hash(password),
            uid
        )
    )

    db().commit()

    return render_template(
        "credentials.html",
        name=employee["name"],
        email=employee["email"],
        password=password
    )


# ==========================================
# DELETE EMPLOYEE
# ==========================================

@app.post(
    "/admin/employees/<int:uid>/delete"
)
@login_required("admin")
def delete_employee(uid):
    db().execute(
        "DELETE FROM users "
        "WHERE id=? AND role='employee'",
        (uid,)
    )

    db().commit()

    flash(
        "Employee removed.",
        "success"
    )

    return redirect(
        url_for("admin_dashboard")
    )


# ==========================================
# EMPLOYEE TRAINING DASHBOARD
# ==========================================

@app.route("/training")
@login_required("employee")
def my_training():
    ids = assigned(
        g.user["id"]
    )

    done = {
        r["module_id"]
        for r in db().execute(
            "SELECT module_id FROM progress "
            "WHERE user_id=?",
            (g.user["id"],)
        )
    }

    return render_template(
        "training.html",
        modules=[
            m for m in MODULES
            if m[0] in ids
        ],
        done=done
    )


# ==========================================
# INDIVIDUAL TRAINING MODULE
# ==========================================

@app.route("/training/<int:mid>")
@login_required("employee")
def module_detail(mid):
    mod = module_by_id(mid)

    if not mod:
        abort(404)

    if mid not in assigned(
        g.user["id"]
    ):
        abort(403)

    done = bool(
        db().execute(
            "SELECT 1 FROM progress "
            "WHERE user_id=? AND module_id=?",
            (g.user["id"], mid)
        ).fetchone()
    )

    return render_template(
        "lesson.html",
        module=mod,
        points=mod[4].split("|"),
        done=done
    )


@app.post(
    "/training/<int:mid>/complete"
)
@login_required("employee")
def finish_module(mid):
    if mid not in assigned(
        g.user["id"]
    ):
        abort(403)

    db().execute(
        "INSERT OR IGNORE INTO progress("
        "user_id,module_id,completed_at"
        ") VALUES(?,?,?)",
        (
            g.user["id"],
            mid,
            datetime.now(
                timezone.utc
            ).isoformat()
        )
    )

    db().commit()

    flash(
        "Training marked complete.",
        "success"
    )

    return redirect(
        url_for("my_training")
    )


# ==========================================
# CYBERSECURITY QUIZ QUESTIONS
# ==========================================

QUIZZES = {
    1: [
        (
            "What is a common sign of phishing?",
            [
                "Unexpected urgent request",
                "Expected team meeting",
                "Known contact in person",
                "Scheduled software update"
            ],
            0
        ),
        (
            "What should you do with a suspicious link?",
            [
                "Click to test",
                "Report without clicking",
                "Share with coworkers",
                "Enter your password"
            ],
            1
        ),
        (
            "A sender address looks unusual. What is best?",
            [
                "Verify independently",
                "Trust the display name",
                "Reply with password",
                "Ignore warnings"
            ],
            0
        )
    ],
    2: [
        (
            "Which password approach is best?",
            [
                "Reuse one password",
                "Use a long unique passphrase",
                "Use your birthday",
                "Share with coworkers"
            ],
            1
        ),
        (
            "Where should work passwords be stored?",
            [
                "In an approved password manager",
                "On a desk note",
                "In a public document",
                "In a group chat"
            ],
            0
        ),
        (
            "If a password might be stolen, what should you do?",
            [
                "Wait for an alert",
                "Tell no one",
                "Change it and report promptly",
                "Reuse it elsewhere"
            ],
            2
        )
    ],
    3: [
        (
            "Your manager requests an unusual urgent payment. What next?",
            [
                "Pay immediately",
                "Verify through a trusted channel",
                "Share login details",
                "Ignore all messages"
            ],
            1
        ),
        (
            "Social engineering usually targets what?",
            [
                "Only software",
                "People and their trust",
                "Only routers",
                "Only printers"
            ],
            1
        ),
        (
            "A caller asks for a one-time code. What should you do?",
            [
                "Read it aloud",
                "Send it by email",
                "Refuse and report",
                "Post it publicly"
            ],
            2
        )
    ],
    4: [
        (
            "You receive an unknown attachment. What is safest?",
            [
                "Open it immediately",
                "Enable macros",
                "Verify sender and file first",
                "Forward to everyone"
            ],
            2
        ),
        (
            "Why update work software?",
            [
                "For new wallpapers",
                "To reduce known security weaknesses",
                "To remove passwords",
                "To disable protection"
            ],
            1
        ),
        (
            "A device displays a ransomware message. What now?",
            [
                "Report to IT promptly",
                "Pay without telling anyone",
                "Download random repair tools",
                "Ignore it"
            ],
            0
        )
    ],
    5: [
        (
            "Does HTTPS guarantee a site is trustworthy?",
            [
                "Yes, always",
                "No, it only protects the connection",
                "Yes, for all payments",
                "Yes, against phishing"
            ],
            1
        ),
        (
            "Before logging in to a website, you should:",
            [
                "Check the full address",
                "Trust every search ad",
                "Disable warnings",
                "Ignore typos"
            ],
            0
        ),
        (
            "An unexpected browser warning appears. You should:",
            [
                "Ignore it",
                "Share credentials",
                "Stop and investigate",
                "Install suggested unknown app"
            ],
            2
        )
    ],
    6: [
        (
            "What does MFA provide?",
            [
                "A second verification layer",
                "A shorter password",
                "Public passwords",
                "No login checks"
            ],
            0
        ),
        (
            "An MFA request arrives that you did not start. You should:",
            [
                "Approve to stop it",
                "Reject and report",
                "Share the code",
                "Ignore repeated requests"
            ],
            1
        ),
        (
            "Should you share your one-time code with IT by phone?",
            [
                "Yes whenever asked",
                "Only in group chat",
                "No, never share it",
                "Post it in a ticket"
            ],
            2
        )
    ]
}


# ==========================================
# EMPLOYEE QUIZ DASHBOARD
# ==========================================

@app.route("/quiz")
@login_required("employee")
def quiz_index():
    ids = assigned(
        g.user["id"]
    )

    scores = {
        r["module_id"]: r["score"]
        for r in db().execute(
            "SELECT module_id,"
            "round(100.0*correct/total) AS score "
            "FROM quiz_attempts "
            "WHERE user_id=? ORDER BY id",
            (g.user["id"],)
        )
    }

    return render_template(
        "quizzes.html",
        modules=[
            m for m in MODULES
            if m[0] in ids
        ],
        scores=scores
    )


# ==========================================
# TAKE QUIZ AND STORE RESULTS
# ==========================================

@app.route(
    "/quiz/<int:mid>",
    methods=["GET", "POST"]
)
@login_required("employee")
def quiz_module(mid):
    if not module_by_id(mid):
        abort(404)

    if mid not in assigned(
        g.user["id"]
    ):
        abort(403)

    questions = QUIZZES[mid]

    if request.method == "POST":
        answers = [
            request.form.get(f"q{i}")
            for i in range(len(questions))
        ]

        if any(
            a not in ["0", "1", "2", "3"]
            for a in answers
        ):
            flash(
                "Please answer every question.",
                "error"
            )

        else:
            correct = sum(
                int(a) == q[2]
                for a, q in zip(
                    answers,
                    questions
                )
            )

            db().execute(
                "INSERT INTO quiz_attempts("
                "user_id,module_id,correct,total,taken_at"
                ") VALUES(?,?,?,?,?)",
                (
                    g.user["id"],
                    mid,
                    correct,
                    len(questions),
                    datetime.now(
                        timezone.utc
                    ).isoformat()
                )
            )

            db().commit()

            return render_template(
                "quiz_result.html",
                module=module_by_id(mid),
                correct=correct,
                total=len(questions),
                questions=questions,
                answers=answers
            )

    return render_template(
        "quiz.html",
        module=module_by_id(mid),
        questions=questions
    )


# ==========================================
# HEALTH CHECK
# ==========================================

@app.get("/health")
def health():
    return {
        "status": "ok"
    }


# ==========================================
# START CYBERAWARE WEBSITE
# ==========================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get("PORT", 5000)
        ),
        debug=(
            os.environ.get("FLASK_DEBUG") == "1"
        )
    )
