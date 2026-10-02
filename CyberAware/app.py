from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cyberaware-development-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///cyberaware.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -------------------------
# DATABASE MODELS
# -------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="employee", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TrainingModule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)

class ModuleProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    module_id = db.Column(db.Integer, db.ForeignKey("training_module.id"), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime)
    __table_args__ = (db.UniqueConstraint("user_id", "module_id", name="uq_user_module"),)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(100), nullable=False)
    question = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(255), nullable=False)
    option_b = db.Column(db.String(255), nullable=False)
    option_c = db.Column(db.String(255), nullable=False)
    option_d = db.Column(db.String(255), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    score = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TopicScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attempt_id = db.Column(db.Integer, db.ForeignKey("quiz_attempt.id"), nullable=False)
    topic = db.Column(db.String(100), nullable=False)
    score = db.Column(db.Float, nullable=False)

class QuizAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attempt_id = db.Column(db.Integer, db.ForeignKey("quiz_attempt.id"), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    selected_answer = db.Column(db.String(1), nullable=False)
    correct = db.Column(db.Boolean, nullable=False)

class PhishingScenario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(150), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    malicious = db.Column(db.Boolean, nullable=False)
    explanation = db.Column(db.Text, nullable=False)

class PhishingAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    scenario_id = db.Column(db.Integer, db.ForeignKey("phishing_scenario.id"), nullable=False)
    correct = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# -------------------------
# AUTH HELPERS
# -------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped

# -------------------------
# SCORING
# -------------------------

def awareness_score(user_id):
    quiz_attempts = QuizAttempt.query.filter_by(user_id=user_id).all()
    phishing_attempts = PhishingAttempt.query.filter_by(user_id=user_id).all()
    completed_modules = ModuleProgress.query.filter_by(user_id=user_id, completed=True).count()
    total_modules = TrainingModule.query.count()

    quiz_average = (
        sum(a.score for a in quiz_attempts) / len(quiz_attempts)
        if quiz_attempts else 0
    )

    phishing_score = (
        sum(1 for a in phishing_attempts if a.correct) / len(phishing_attempts) * 100
        if phishing_attempts else 0
    )

    completion = (
        completed_modules / total_modules * 100
        if total_modules else 0
    )

    final_score = 0.50 * quiz_average + 0.30 * phishing_score + 0.20 * completion

    return (
        round(final_score, 1),
        round(quiz_average, 1),
        round(phishing_score, 1),
        round(completion, 1),
    )

def risk_level(score):
    if score >= 80:
        return "Low"
    if score >= 60:
        return "Moderate"
    if score >= 40:
        return "High"
    return "Critical"

def recommendations_for_user(user_id):
    recommendations = []

    latest_attempt = QuizAttempt.query.filter_by(user_id=user_id).order_by(
        QuizAttempt.created_at.desc()
    ).first()

    if latest_attempt:
        topic_scores = TopicScore.query.filter_by(attempt_id=latest_attempt.id).all()
        for topic_score in topic_scores:
            if topic_score.score < 60:
                recommendations.append(
                    f"Review the {topic_score.topic} training module and practise related questions."
                )
    else:
        recommendations.append("Complete the cybersecurity quiz.")

    _, _, phishing_score, completion = awareness_score(user_id)

    if phishing_score < 60:
        recommendations.append("Practise more phishing scenarios.")
    if completion < 100:
        recommendations.append("Complete all training modules.")
    if not recommendations:
        recommendations.append("Good progress. Continue practising cybersecurity awareness activities.")

    return recommendations

# -------------------------
# ROUTES
# -------------------------

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name:
            flash("Name is required.", "danger")
            return redirect(url_for("register"))
        if not email:
            flash("Email is required.", "danger")
            return redirect(url_for("register"))
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))

        db.session.add(User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
            role="employee"
        ))
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            session["name"] = user.name
            session["role"] = user.role

            if user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    score, quiz_average, phishing_score, completion = awareness_score(user_id)

    attempts = QuizAttempt.query.filter_by(user_id=user_id).order_by(
        QuizAttempt.created_at.asc()
    ).all()

    labels = [f"Attempt {i}" for i in range(1, len(attempts) + 1)]
    values = [a.score for a in attempts]

    return render_template(
        "dashboard.html",
        score=score,
        quiz_avg=quiz_average,
        phishing_score=phishing_score,
        completion=completion,
        risk=risk_level(score),
        labels=labels,
        values=values,
        recommendations=recommendations_for_user(user_id),
    )

@app.route("/training")
@login_required
def training():
    modules = TrainingModule.query.order_by(TrainingModule.id.asc()).all()
    completed = ModuleProgress.query.filter_by(
        user_id=session["user_id"], completed=True
    ).all()
    done = {p.module_id for p in completed}
    return render_template("training.html", modules=modules, done=done)

@app.route("/training/<int:module_id>")
@login_required
def training_module(module_id):
    module = TrainingModule.query.get_or_404(module_id)
    progress = ModuleProgress.query.filter_by(
        user_id=session["user_id"], module_id=module.id, completed=True
    ).first()
    return render_template("training_module.html", module=module, completed=bool(progress))

@app.route(
    "/training/<int:module_id>/complete",
    methods=["GET", "POST"]
)
@login_required
def complete_module(module_id):

    user_id = session["user_id"]

    module = TrainingModule.query.get_or_404(module_id)

    progress = ModuleProgress.query.filter_by(
        user_id=user_id,
        module_id=module.id
    ).first()

    if not progress:
        progress = ModuleProgress(
            user_id=user_id,
            module_id=module.id
        )
        db.session.add(progress)

    progress.completed = True
    progress.completed_at = datetime.utcnow()

    db.session.commit()

    flash(
        "Module marked as completed.",
        "success"
    )

    return redirect(
        url_for("training")
    )

@app.route("/quiz", methods=["GET", "POST"])
@login_required
def quiz():
    questions = Question.query.order_by(Question.id.asc()).all()

    if request.method == "POST":
        if not questions:
            flash("No quiz questions are available.", "warning")
            return redirect(url_for("dashboard"))

        total_correct = 0
        topic_results = {}
        submitted_answers = {}

        for question in questions:
            selected_answer = request.form.get(f"q{question.id}")

            if not selected_answer:
                flash("Please answer every quiz question.", "warning")
                return redirect(url_for("quiz"))

            submitted_answers[question.id] = selected_answer
            topic_results.setdefault(question.topic, {"correct": 0, "total": 0})
            topic_results[question.topic]["total"] += 1

            if selected_answer == question.correct_answer:
                total_correct += 1
                topic_results[question.topic]["correct"] += 1

        score = round((total_correct / len(questions)) * 100, 1)

        attempt = QuizAttempt(user_id=session["user_id"], score=score)
        db.session.add(attempt)
        db.session.flush()

        for question in questions:
            selected_answer = submitted_answers[question.id]
            db.session.add(QuizAnswer(
                attempt_id=attempt.id,
                question_id=question.id,
                selected_answer=selected_answer,
                correct=(selected_answer == question.correct_answer),
            ))

        for topic, result in topic_results.items():
            topic_score = round((result["correct"] / result["total"]) * 100, 1)
            db.session.add(TopicScore(
                attempt_id=attempt.id,
                topic=topic,
                score=topic_score,
            ))

        db.session.commit()
        flash(f"Quiz completed. Your score is {score}%.", "success")
        return redirect(url_for("dashboard"))

    return render_template("quiz.html", questions=questions)

@app.route("/phishing")
@login_required
def phishing():
    scenarios = PhishingScenario.query.order_by(PhishingScenario.id.asc()).all()
    return render_template("phishing.html", scenarios=scenarios)

@app.route("/phishing/<int:scenario_id>", methods=["GET", "POST"])
@login_required
def phishing_scenario(scenario_id):
    scenario = PhishingScenario.query.get_or_404(scenario_id)
    result = None

    if request.method == "POST":
        choice = request.form.get("choice")

        if choice not in ["malicious", "legitimate"]:
            flash("Please select an answer.", "warning")
            return redirect(url_for("phishing_scenario", scenario_id=scenario.id))

        selected_malicious = choice == "malicious"
        correct = selected_malicious == scenario.malicious

        db.session.add(PhishingAttempt(
            user_id=session["user_id"],
            scenario_id=scenario.id,
            correct=correct,
        ))
        db.session.commit()

        result = {
            "correct": correct,
            "explanation": scenario.explanation,
        }

    return render_template("phishing_scenario.html", scenario=scenario, result=result)

@app.route("/admin")
@admin_required
def admin_dashboard():
    users = User.query.filter_by(role="employee").all()
    rows = []

    for user in users:
        score, quiz_average, phishing_score, completion = awareness_score(user.id)
        rows.append({
            "name": user.name,
            "email": user.email,
            "score": score,
            "quiz_avg": quiz_average,
            "quiz_attempts": QuizAttempt.query.filter_by(user_id=user.id).count(),
            "phishing_score": phishing_score,
            "completion": completion,
            "risk": risk_level(score),
        })

    avg_score = round(sum(r["score"] for r in rows) / len(rows), 1) if rows else 0
    avg_quiz_score = round(sum(r["quiz_avg"] for r in rows) / len(rows), 1) if rows else 0
    overall_training_completion = round(
        sum(r["completion"] for r in rows) / len(rows), 1
    ) if rows else 0

    all_quiz_attempts = QuizAttempt.query.order_by(QuizAttempt.created_at.asc()).all()
    quiz_attempt_count = len(all_quiz_attempts)

    risk_counts = {"Low": 0, "Moderate": 0, "High": 0, "Critical": 0}
    for row in rows:
        risk_counts[row["risk"]] += 1

    quiz_chart_labels = [f"Attempt {i}" for i in range(1, len(all_quiz_attempts) + 1)]
    quiz_chart_values = [a.score for a in all_quiz_attempts]

    incorrect_questions = []
    for question in Question.query.all():
        total_answers = QuizAnswer.query.filter_by(question_id=question.id).count()
        wrong_count = QuizAnswer.query.filter_by(
            question_id=question.id, correct=False
        ).count()
        incorrect_percentage = round(
            (wrong_count / total_answers) * 100, 1
        ) if total_answers else 0

        incorrect_questions.append({
            "question": question.question,
            "topic": question.topic,
            "wrong_count": wrong_count,
            "incorrect_percentage": incorrect_percentage,
        })

    incorrect_questions.sort(key=lambda item: item["wrong_count"], reverse=True)

    return render_template(
        "admin.html",
        rows=rows,
        avg_score=avg_score,
        avg_quiz_score=avg_quiz_score,
        quiz_attempt_count=quiz_attempt_count,
        overall_training_completion=overall_training_completion,
        risk_counts=risk_counts,
        quiz_chart_labels=quiz_chart_labels,
        quiz_chart_values=quiz_chart_values,
        incorrect_questions=incorrect_questions,
    )

@app.route("/api/stats")
@admin_required
def stats_api():
    users = User.query.filter_by(role="employee").all()
    data = []

    for user in users:
        score, quiz_average, phishing_score, completion = awareness_score(user.id)
        data.append({
            "name": user.name,
            "score": score,
            "quiz_average": quiz_average,
            "phishing_score": phishing_score,
            "completion": completion,
            "risk": risk_level(score),
            "quiz_attempts": QuizAttempt.query.filter_by(user_id=user.id).count(),
        })

    return jsonify(data)

# -------------------------
# SEED DATA
# -------------------------

def seed_data():
    if TrainingModule.query.count() == 0:
        modules = [
            ("Phishing", "Recognising Phishing",
             "Check sender addresses, suspicious links, urgent language, spelling mistakes and unexpected attachments."),
            ("Password Security", "Strong Password Practices",
             "Use long unique passwords, avoid password reuse and use a password manager where possible."),
            ("Social Engineering", "Social Engineering Awareness",
             "Verify unusual requests for money, credentials or sensitive information through a trusted channel."),
            ("Malware", "Malware Basics",
             "Avoid unknown downloads, keep software updated and report suspicious system behaviour."),
            ("Safe Browsing", "Safe Browsing Habits",
             "Use HTTPS where appropriate, avoid suspicious sites and pay attention to browser warnings."),
            ("Multi-Factor Authentication", "Using MFA",
             "Multi-factor authentication adds another verification step and reduces the impact of stolen passwords."),
        ]
        for topic, title, content in modules:
            db.session.add(TrainingModule(topic=topic, title=title, content=content))

    if Question.query.count() == 0:
        questions = [
            ("Phishing", "Which is a common phishing warning sign?",
             "Unexpected urgent request", "Normal company signature", "Known sender", "Expected invoice", "A"),
            ("Password Security", "Which password is safest?",
             "password123", "Company2026", "A long unique passphrase", "12345678", "C"),
            ("Social Engineering", "What should you do with an unusual payment request?",
             "Pay immediately", "Verify through a trusted channel", "Forward it to everyone", "Ignore company policy", "B"),
            ("Malware", "What is the safest action for an unknown attachment?",
             "Open it immediately", "Disable antivirus", "Verify before opening", "Upload it publicly", "C"),
            ("Safe Browsing", "What does HTTPS mainly indicate?",
             "Encrypted browser-server connection", "Website is always trustworthy", "No malware can exist", "Website is government-owned", "A"),
            ("Multi-Factor Authentication", "Why use MFA?",
             "It removes passwords", "It adds another verification layer", "It makes usernames secret", "It blocks every phishing attack", "B"),
        ]
        for item in questions:
            db.session.add(Question(
                topic=item[0],
                question=item[1],
                option_a=item[2],
                option_b=item[3],
                option_c=item[4],
                option_d=item[5],
                correct_answer=item[6],
            ))

    if PhishingScenario.query.count() == 0:
        db.session.add(PhishingScenario(
            sender="security-update@micr0soft-support.example",
            subject="URGENT: Your account will be closed today",
            body="Click the link immediately and verify your password to keep your account active.",
            malicious=True,
            explanation="This message uses urgency, a suspicious sender domain and requests credentials.",
        ))
        db.session.add(PhishingScenario(
            sender="hr@smallbizconnect.local",
            subject="Updated staff meeting agenda",
            body="The updated agenda is available in the internal staff portal. No login link is included in this email.",
            malicious=False,
            explanation="This message does not pressure the user, request credentials or use a suspicious link.",
        ))

    admin_email = "admin@cyberaware.local"
    existing_admin = User.query.filter_by(email=admin_email).first()

    if existing_admin:
        existing_admin.name = "CyberAware Admin"
        existing_admin.role = "admin"
        existing_admin.password_hash = generate_password_hash("Admin123!")
    else:
        db.session.add(User(
            name="CyberAware Admin",
            email=admin_email,
            password_hash=generate_password_hash("Admin123!"),
            role="admin",
        ))

    db.session.commit()

with app.app_context():
    db.create_all()
    seed_data()
    print("Training modules:", TrainingModule.query.count())
    print("Quiz questions:", Question.query.count())
    print("Phishing scenarios:", PhishingScenario.query.count())
    print("Users:", User.query.count())

if __name__ == "__main__":
    app.run(debug=True)
