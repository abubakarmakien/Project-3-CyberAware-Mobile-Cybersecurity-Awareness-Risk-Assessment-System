from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify
)

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import os


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key"
)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    "sqlite:///cyberaware.db"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# =========================================================
# DATABASE MODELS
# =========================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        default="employee"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class TrainingModule(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True
    )

    topic = db.Column(
        db.String(100),
        nullable=False
    )

    title = db.Column(
        db.String(150),
        nullable=False
    )

    content = db.Column(
        db.Text,
        nullable=False
    )


class Question(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True
    )

    topic = db.Column(
        db.String(100),
        nullable=False
    )

    question = db.Column(
        db.Text,
        nullable=False
    )

    option_a = db.Column(
        db.String(255),
        nullable=False
    )

    option_b = db.Column(
        db.String(255),
        nullable=False
    )

    option_c = db.Column(
        db.String(255),
        nullable=False
    )

    option_d = db.Column(
        db.String(255),
        nullable=False
    )

    correct_answer = db.Column(
        db.String(1),
        nullable=False
    )


class QuizAttempt(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    score = db.Column(
        db.Float,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class TopicScore(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True
    )

    attempt_id = db.Column(
        db.Integer,
        db.ForeignKey("quiz_attempt.id"),
        nullable=False
    )

    topic = db.Column(
        db.String(100),
        nullable=False
    )

    score = db.Column(
        db.Float,
        nullable=False
    )


class PhishingScenario(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True
    )

    sender = db.Column(
        db.String(150),
        nullable=False
    )

    subject = db.Column(
        db.String(255),
        nullable=False
    )

    body = db.Column(
        db.Text,
        nullable=False
    )

    malicious = db.Column(
        db.Boolean,
        nullable=False
    )

    explanation = db.Column(
        db.Text,
        nullable=False
    )


class PhishingAttempt(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    scenario_id = db.Column(
        db.Integer,
        db.ForeignKey("phishing_scenario.id"),
        nullable=False
    )

    correct = db.Column(
        db.Boolean,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class ModuleProgress(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    module_id = db.Column(
        db.Integer,
        db.ForeignKey("training_module.id"),
        nullable=False
    )

    completed = db.Column(
        db.Boolean,
        default=False
    )

    completed_at = db.Column(
        db.DateTime
    )


# =========================================================
# LOGIN / ROLE DECORATORS
# =========================================================

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please log in first.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):

        if (
            "user_id" not in session
            or session.get("role") != "admin"
        ):

            flash(
                "Administrator access required.",
                "danger"
            )

            return redirect(
                url_for("dashboard")
            )

        return view(*args, **kwargs)

    return wrapped


# =========================================================
# AWARENESS SCORE
# =========================================================

def awareness_score(user_id):

    quizzes = QuizAttempt.query.filter_by(
        user_id=user_id
    ).all()

    phishing_attempts = PhishingAttempt.query.filter_by(
        user_id=user_id
    ).all()

    progress = ModuleProgress.query.filter_by(
        user_id=user_id
    ).all()

    total_modules = TrainingModule.query.count()


    # ------------------------------
    # Quiz Average
    # ------------------------------

    if quizzes:

        quiz_average = (
            sum(q.score for q in quizzes)
            / len(quizzes)
        )

    else:

        quiz_average = 0


    # ------------------------------
    # Phishing Score
    # ------------------------------

    if phishing_attempts:

        correct_phishing = sum(
            1
            for p in phishing_attempts
            if p.correct
        )

        phishing_score = (
            correct_phishing
            / len(phishing_attempts)
        ) * 100

    else:

        phishing_score = 0


    # ------------------------------
    # Training Completion
    # ------------------------------

    completed_modules = sum(
        1
        for p in progress
        if p.completed
    )

    if total_modules:

        completion_percentage = (
            completed_modules
            / total_modules
        ) * 100

    else:

        completion_percentage = 0


    # ------------------------------
    # Final Awareness Score
    # ------------------------------

    # 50% Quiz
    # 30% Phishing
    # 20% Training Completion

    final_score = (
        0.50 * quiz_average
        + 0.30 * phishing_score
        + 0.20 * completion_percentage
    )


    return (
        round(final_score, 1),
        round(quiz_average, 1),
        round(phishing_score, 1),
        round(completion_percentage, 1)
    )


# =========================================================
# RISK LEVEL
# =========================================================

def risk_level(score):

    if score >= 80:
        return "Low"

    elif score >= 60:
        return "Moderate"

    elif score >= 40:
        return "High"

    else:
        return "Critical"


# =========================================================
# PERSONAL RECOMMENDATIONS
# =========================================================

def recommendations_for_user(user_id):

    recommendations = []

    latest_attempt = QuizAttempt.query.filter_by(
        user_id=user_id
    ).order_by(
        QuizAttempt.created_at.desc()
    ).first()


    # Topic-specific recommendations

    if latest_attempt:

        topic_scores = TopicScore.query.filter_by(
            attempt_id=latest_attempt.id
        ).all()

        for topic_score in topic_scores:

            if topic_score.score < 60:

                recommendations.append(
                    f"Review the {topic_score.topic} "
                    f"training module and retake related questions."
                )

    else:

        recommendations.append(
            "Review the training modules and retake the quiz."
        )


    score, quiz_avg, phishing_score, completion = awareness_score(
        user_id
    )


    if phishing_score < 60:

        recommendations.append(
            "Practise more phishing scenarios."
        )


    if completion < 100:

        recommendations.append(
            "Complete all training modules."
        )


    if not recommendations:

        recommendations.append(
            "Good progress. Continue practising cybersecurity "
            "scenarios and review modules regularly."
        )


    return recommendations


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

    return render_template(
        "home.html"
    )


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        name = request.form[
            "name"
        ].strip()

        email = request.form[
            "email"
        ].strip().lower()

        password = request.form[
            "password"
        ]


        # Minimum password length

        if len(password) < 8:

            flash(
                "Password must be at least 8 characters.",
                "danger"
            )

            return redirect(
                url_for("register")
            )


        # Check existing email

        existing_user = User.query.filter_by(
            email=email
        ).first()

        if existing_user:

            flash(
                "Email already registered.",
                "danger"
            )

            return redirect(
                url_for("register")
            )


        # Create user

        user = User(

            name=name,

            email=email,

            password_hash=
            generate_password_hash(password),

            role="employee"
        )


        db.session.add(user)

        db.session.commit()


        flash(
            "Registration successful. Please log in.",
            "success"
        )


        return redirect(
            url_for("login")
        )


    return render_template(
        "register.html"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        email = request.form[
            "email"
        ].strip().lower()

        password = request.form[
            "password"
        ]


        user = User.query.filter_by(
            email=email
        ).first()


        if user and check_password_hash(
            user.password_hash,
            password
        ):

            session["user_id"] = user.id

            session["name"] = user.name

            session["role"] = user.role


            return redirect(
                url_for("dashboard")
            )


        flash(
            "Invalid email or password.",
            "danger"
        )


    return render_template(
        "login.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("home")
    )


# =========================================================
# EMPLOYEE DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    user_id = session["user_id"]


    score, quiz_avg, phishing_score, completion = awareness_score(
        user_id
    )


    attempts = QuizAttempt.query.filter_by(
        user_id=user_id
    ).order_by(
        QuizAttempt.created_at.asc()
    ).all()


    labels = []

    values = []


    for index, attempt in enumerate(
        attempts,
        start=1
    ):

        labels.append(
            f"Attempt {index}"
        )

        values.append(
            attempt.score
        )


    return render_template(

        "dashboard.html",

        score=score,

        quiz_avg=quiz_avg,

        phishing_score=phishing_score,

        completion=completion,

        risk=risk_level(score),

        labels=labels,

        values=values,

        recommendations=
        recommendations_for_user(user_id)
    )


# =========================================================
# TRAINING LIST
# =========================================================

@app.route("/training")
@login_required
def training():

    modules = TrainingModule.query.all()


    completed_progress = ModuleProgress.query.filter_by(
        user_id=session["user_id"],
        completed=True
    ).all()


    completed_ids = {
        progress.module_id
        for progress in completed_progress
    }


    return render_template(

        "training.html",

        modules=modules,

        done=completed_ids
    )


# =========================================================
# TRAINING MODULE
# =========================================================

@app.route(
    "/training/<int:module_id>"
)
@login_required
def training_module(module_id):

    module = TrainingModule.query.get_or_404(
        module_id
    )


    return render_template(

        "training_module.html",

        module=module
    )


# =========================================================
# COMPLETE TRAINING MODULE
# =========================================================

@app.route(
    "/training/<int:module_id>/complete",
    methods=["POST"]
)
@login_required
def complete_module(module_id):

    user_id = session[
        "user_id"
    ]


    progress = ModuleProgress.query.filter_by(

        user_id=user_id,

        module_id=module_id

    ).first()


    if not progress:

        progress = ModuleProgress(

            user_id=user_id,

            module_id=module_id
        )

        db.session.add(
            progress
        )


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


# =========================================================
# QUIZ
# =========================================================

@app.route(
    "/quiz",
    methods=["GET", "POST"]
)
@login_required
def quiz():

    questions = Question.query.all()


    if request.method == "POST":

        total_questions = len(
            questions
        )

        total_correct = 0

        topic_results = {}


        for question in questions:

            selected_answer = request.form.get(
                f"q{question.id}"
            )


            if question.topic not in topic_results:

                topic_results[
                    question.topic
                ] = {
                    "correct": 0,
                    "total": 0
                }


            topic_results[
                question.topic
            ]["total"] += 1


            if (
                selected_answer
                == question.correct_answer
            ):

                total_correct += 1

                topic_results[
                    question.topic
                ]["correct"] += 1


        # Calculate quiz score

        if total_questions:

            score = (
                total_correct
                / total_questions
            ) * 100

        else:

            score = 0


        score = round(
            score,
            1
        )


        # Save quiz attempt

        attempt = QuizAttempt(

            user_id=session["user_id"],

            score=score
        )


        db.session.add(
            attempt
        )


        db.session.flush()


        # Save topic scores

        for topic, result in topic_results.items():

            if result["total"]:

                topic_score = (
                    result["correct"]
                    / result["total"]
                ) * 100

            else:

                topic_score = 0


            record = TopicScore(

                attempt_id=attempt.id,

                topic=topic,

                score=topic_score
            )


            db.session.add(
                record
            )


        db.session.commit()


        flash(
            f"Quiz completed. Your score is {score}%.",
            "success"
        )


        return redirect(
            url_for("dashboard")
        )


    return render_template(

        "quiz.html",

        questions=questions
    )


# =========================================================
# PHISHING SCENARIOS LIST
# =========================================================

@app.route("/phishing")
@login_required
def phishing():

    scenarios = PhishingScenario.query.all()


    return render_template(

        "phishing.html",

        scenarios=scenarios
    )


# =========================================================
# PHISHING SCENARIO
# =========================================================

@app.route(
    "/phishing/<int:scenario_id>",
    methods=["GET", "POST"]
)
@login_required
def phishing_scenario(
    scenario_id
):

    scenario = PhishingScenario.query.get_or_404(
        scenario_id
    )


    result = None


    if request.method == "POST":

        choice = request.form.get(
            "choice"
        )


        selected_malicious = (
            choice == "malicious"
        )


        correct = (
            selected_malicious
            == scenario.malicious
        )


        phishing_attempt = PhishingAttempt(

            user_id=session["user_id"],

            scenario_id=scenario.id,

            correct=correct
        )


        db.session.add(
            phishing_attempt
        )


        db.session.commit()


        result = {

            "correct": correct,

            "explanation":
            scenario.explanation
        }


    return render_template(

        "phishing_scenario.html",

        scenario=scenario,

        result=result
    )


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.route("/admin")
@admin_required
def admin_dashboard():

    users = User.query.filter_by(
        role="employee"
    ).all()


    employee_rows = []


    # -----------------------------------------------------
    # EMPLOYEE-WISE STATISTICS
    # -----------------------------------------------------

    for user in users:

        score, quiz_avg, phishing_score, completion = awareness_score(
            user.id
        )


        quiz_attempts = QuizAttempt.query.filter_by(
            user_id=user.id
        ).count()


        employee_rows.append({

            "name":
            user.name,

            "email":
            user.email,

            "score":
            score,

            "quiz_avg":
            quiz_avg,

            "quiz_attempts":
            quiz_attempts,

            "phishing_score":
            phishing_score,

            "risk":
            risk_level(score),

            "completion":
            completion
        })


    # -----------------------------------------------------
    # AVERAGE AWARENESS SCORE
    # -----------------------------------------------------

    if employee_rows:

        avg_score = round(

            sum(
                row["score"]
                for row in employee_rows
            )
            / len(employee_rows),

            1
        )

    else:

        avg_score = 0


    # -----------------------------------------------------
    # QUIZ PERFORMANCE
    # -----------------------------------------------------

    all_quiz_attempts = QuizAttempt.query.all()


    # Average Quiz Score

    if all_quiz_attempts:

        avg_quiz_score = round(

            sum(
                attempt.score
                for attempt in all_quiz_attempts
            )
            / len(all_quiz_attempts),

            1
        )

    else:

        avg_quiz_score = 0


    # Number of Quiz Attempts

    quiz_attempt_count = QuizAttempt.query.count()


    # -----------------------------------------------------
    # OVERALL TRAINING COMPLETION
    # -----------------------------------------------------

    if employee_rows:

        overall_training_completion = round(

            sum(
                row["completion"]
                for row in employee_rows
            )
            / len(employee_rows),

            1
        )

    else:

        overall_training_completion = 0


    # -----------------------------------------------------
    # RISK DISTRIBUTION
    # -----------------------------------------------------

    risk_counts = {

        "Low": 0,

        "Moderate": 0,

        "High": 0,

        "Critical": 0
    }


    for row in employee_rows:

        risk_counts[
            row["risk"]
        ] += 1


    # -----------------------------------------------------
    # QUIZ PERFORMANCE CHART
    # -----------------------------------------------------

    quiz_chart_labels = []

    quiz_chart_values = []


    for index, attempt in enumerate(
        all_quiz_attempts,
        start=1
    ):

        quiz_chart_labels.append(
            f"Attempt {index}"
        )

        quiz_chart_values.append(
            attempt.score
        )


    # -----------------------------------------------------
    # RENDER ADMIN PAGE
    # -----------------------------------------------------

    return render_template(

        "admin.html",

        rows=employee_rows,

        avg_score=avg_score,

        avg_quiz_score=avg_quiz_score,

        quiz_attempt_count=quiz_attempt_count,

        overall_training_completion=
        overall_training_completion,

        risk_counts=risk_counts,

        quiz_chart_labels=
        quiz_chart_labels,

        quiz_chart_values=
        quiz_chart_values
    )


# =========================================================
# ADMIN API
# =========================================================

@app.route("/api/stats")
@admin_required
def stats_api():

    users = User.query.filter_by(
        role="employee"
    ).all()


    data = []


    for user in users:

        score, quiz_avg, phishing_score, completion = awareness_score(
            user.id
        )


        data.append({

            "name":
            user.name,

            "score":
            score,

            "quiz_average":
            quiz_avg,

            "phishing_score":
            phishing_score,

            "risk":
            risk_level(score),

            "completion":
            completion,

            "quiz_attempts":
            QuizAttempt.query.filter_by(
                user_id=user.id
            ).count()
        })


    return jsonify(
        data
    )


# =========================================================
# INITIAL SAMPLE DATA
# =========================================================

def seed_data():


    # -----------------------------------------------------
    # TRAINING MODULES
    # -----------------------------------------------------

    if TrainingModule.query.count() == 0:

        modules = [

            (
                "Phishing",
                "Recognising Phishing",
                "Check sender addresses, suspicious links, "
                "urgent language, spelling, and unexpected attachments."
            ),

            (
                "Password Security",
                "Strong Password Practices",
                "Use long unique passwords, avoid password reuse, "
                "and use a password manager where possible."
            ),

            (
                "Social Engineering",
                "Social Engineering Awareness",
                "Verify unusual requests, especially requests "
                "for money, credentials, or sensitive information."
            ),

            (
                "Malware",
                "Malware Basics",
                "Avoid unknown downloads, keep software updated, "
                "and report suspicious behaviour."
            ),

            (
                "Safe Browsing",
                "Safe Browsing Habits",
                "Use HTTPS, avoid suspicious websites, "
                "keep browsers updated, and do not bypass warnings."
            ),

            (
                "Multi-Factor Authentication",
                "Using MFA",
                "MFA adds another verification step and reduces "
                "the impact of stolen passwords."
            )
        ]


        for topic, title, content in modules:

            db.session.add(

                TrainingModule(

                    topic=topic,

                    title=title,

                    content=content
                )
            )


    # -----------------------------------------------------
    # QUIZ QUESTIONS
    # -----------------------------------------------------

    if Question.query.count() == 0:

        questions = [

            (
                "Phishing",
                "Which is a common phishing warning sign?",
                "Unexpected urgent request",
                "Normal company signature",
                "Known sender",
                "Expected invoice",
                "A"
            ),

            (
                "Password Security",
                "Which password is safest?",
                "password123",
                "Company2026",
                "A long unique passphrase",
                "12345678",
                "C"
            ),

            (
                "Social Engineering",
                "What should you do with an unusual payment request?",
                "Pay immediately",
                "Verify through a trusted channel",
                "Forward to everyone",
                "Ignore policy",
                "B"
            ),

            (
                "Malware",
                "What is the safest action for an unknown attachment?",
                "Open it",
                "Disable antivirus",
                "Verify before opening",
                "Upload it publicly",
                "C"
            ),

            (
                "Safe Browsing",
                "What does HTTPS mainly indicate?",
                "Encrypted browser-server connection",
                "Website is always trustworthy",
                "No malware exists",
                "The site is government-owned",
                "A"
            ),

            (
                "Multi-Factor Authentication",
                "Why use MFA?",
                "It removes passwords",
                "It adds another verification layer",
                "It makes usernames secret",
                "It blocks all phishing",
                "B"
            )
        ]


        for item in questions:

            question = Question(

                topic=item[0],

                question=item[1],

                option_a=item[2],

                option_b=item[3],

                option_c=item[4],

                option_d=item[5],

                correct_answer=item[6]
            )


            db.session.add(
                question
            )


    # -----------------------------------------------------
    # PHISHING SCENARIOS
    # -----------------------------------------------------

    if PhishingScenario.query.count() == 0:

        phishing_one = PhishingScenario(

            sender=
            "security-update@micr0soft-support.example",

            subject=
            "URGENT: Your account will be closed today",

            body=
            "Click the link immediately and verify your password "
            "to keep your account active.",

            malicious=True,

            explanation=
            "The message uses urgency, a suspicious sender domain, "
            "and asks for credentials."
        )


        phishing_two = PhishingScenario(

            sender=
            "hr@smallbizconnect.local",

            subject=
            "Updated staff meeting agenda",

            body=
            "The updated agenda is available in the internal staff "
            "portal. No login link is included in this email.",

            malicious=False,

            explanation=
            "This message does not pressure the user, request "
            "credentials, or use a suspicious external link."
        )


        db.session.add(
            phishing_one
        )

        db.session.add(
            phishing_two
        )


    # -----------------------------------------------------
    # ADMIN ACCOUNT
    # -----------------------------------------------------

    admin_email = (
        "admin@cyberaware.local"
    )


    existing_admin = User.query.filter_by(
        email=admin_email
    ).first()


    if not existing_admin:

        admin = User(

            name=
            "CyberAware Admin",

            email=
            admin_email,

            password_hash=
            generate_password_hash(
                "Admin123!"
            ),

            role=
            "admin"
        )


        db.session.add(
            admin
        )


    db.session.commit()


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":

    with app.app_context():

        db.create_all()

        seed_data()


    app.run(
        debug=True
    )