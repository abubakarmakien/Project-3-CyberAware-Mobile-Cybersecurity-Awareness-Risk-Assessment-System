                    option_c=item[4],
                    option_d=item[5],
                    correct_answer=item[6]
                )
            )


    # -----------------------------------------------------
    # PHISHING SCENARIOS
    # -----------------------------------------------------

    if PhishingScenario.query.count() == 0:

        db.session.add(
            PhishingScenario(
                sender=
                "security-update@micr0soft-support.example",

                subject=
                "URGENT: Your account will be closed today",

                body=
                "Click the link immediately and verify "
                "your password to keep your account active.",

                malicious=True,

                explanation=
                "This message uses urgency, a suspicious "
                "sender domain and requests credentials."
            )
        )


        db.session.add(
            PhishingScenario(
                sender=
                "hr@smallbizconnect.local",

                subject=
                "Updated staff meeting agenda",

                body=
                "The updated agenda is available in the "
                "internal staff portal. No login link is "
                "included in this email.",

                malicious=False,

                explanation=
                "This message does not pressure the user, "
                "request credentials or use a suspicious link."
            )
        )


    # -----------------------------------------------------
    # ADMIN USER
    # -----------------------------------------------------

    admin_email = "admin@cyberaware.local"

    existing_admin = User.query.filter_by(
        email=admin_email
    ).first()

    if existing_admin:
        existing_admin.name = "CyberAware Admin"
        existing_admin.role = "admin"
        existing_admin.password_hash = generate_password_hash(
            "Admin123!"
        )
    else:
        admin = User(
            name="CyberAware Admin",
            email=admin_email,
            password_hash=generate_password_hash(
                "Admin123!"
            ),
            role="admin"
        )
        db.session.add(admin)

    db.session.commit()


# =========================================================
# INITIALISE DATABASE AND SEED DATA
# =========================================================

with app.app_context():
    db.create_all()
    seed_data()


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)
