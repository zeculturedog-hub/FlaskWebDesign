from functools import wraps
import sqlite3

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"
app.config["DATABASE"] = "expenses.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            amount REAL NOT NULL,
            spent_on TEXT NOT NULL,
            note TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    db.commit()


@app.before_request
def load_logged_in_user():
    init_db()
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
        return

    g.user = get_db().execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))

        if g.user["role"] != "admin":
            flash("Only admins can access that page.", "danger")
            return redirect(url_for("dashboard"))

        return view(**kwargs)

    return wrapped_view


@app.route("/")
def home():
    if g.user:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        db = get_db()
        existing_users = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        role = "admin" if existing_users["count"] == 0 else "user"

        if not name or not email or not password:
            flash("Name, email, and password are required.", "danger")
        else:
            try:
                db.execute(
                    """
                    INSERT INTO users (name, email, password_hash, role)
                    VALUES (?, ?, ?, ?)
                    """,
                    (name, email, generate_password_hash(password), role),
                )
                db.commit()
                flash("Account created. You can log in now.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("An account with that email already exists.", "danger")

    return render_template("register.html")


@app.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        user = get_db().execute(
            "SELECT * FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Incorrect email or password.", "danger")
        else:
            session.clear()
            session["user_id"] = user["id"]
            flash("Welcome back.", "success")
            return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    expenses = get_db().execute(
        """
        SELECT * FROM expenses
        WHERE user_id = ?
        ORDER BY spent_on DESC, created_at DESC
        """,
        (g.user["id"],),
    ).fetchall()
    total = sum(expense["amount"] for expense in expenses)
    return render_template("dashboard.html", expenses=expenses, total=total)


@app.route("/expenses/add", methods=("POST",))
@login_required
def add_expense():
    title = request.form["title"].strip()
    category = request.form["category"].strip()
    amount = request.form["amount"]
    spent_on = request.form["spent_on"]
    note = request.form["note"].strip()

    if not title or not category or not amount or not spent_on:
        flash("Title, category, amount, and date are required.", "danger")
        return redirect(url_for("dashboard"))

    try:
        amount_value = float(amount)
    except ValueError:
        flash("Amount must be a valid number.", "danger")
        return redirect(url_for("dashboard"))

    get_db().execute(
        """
        INSERT INTO expenses (user_id, title, category, amount, spent_on, note)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (g.user["id"], title, category, amount_value, spent_on, note),
    )
    get_db().commit()
    flash("Expense added.", "success")
    return redirect(url_for("dashboard"))


@app.route("/expenses/<int:expense_id>/delete", methods=("POST",))
@login_required
def delete_expense(expense_id):
    get_db().execute(
        "DELETE FROM expenses WHERE id = ? AND user_id = ?",
        (expense_id, g.user["id"]),
    )
    get_db().commit()
    flash("Expense deleted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/admin")
@admin_required
def admin():
    users = get_db().execute(
        """
        SELECT users.id, users.name, users.email, users.role,
               COUNT(expenses.id) AS expense_count,
               COALESCE(SUM(expenses.amount), 0) AS total_spent
        FROM users
        LEFT JOIN expenses ON expenses.user_id = users.id
        GROUP BY users.id
        ORDER BY users.created_at DESC
        """
    ).fetchall()
    expenses = get_db().execute(
        """
        SELECT expenses.*, users.name AS user_name
        FROM expenses
        JOIN users ON users.id = expenses.user_id
        ORDER BY expenses.spent_on DESC, expenses.created_at DESC
        """
    ).fetchall()
    total = sum(expense["amount"] for expense in expenses)
    return render_template("admin.html", users=users, expenses=expenses, total=total)


@app.route("/about")
def about():
    return render_template("about.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
