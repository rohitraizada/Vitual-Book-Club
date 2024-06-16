import pyodbc
import bcrypt
import string
import re
from functools import wraps
from flask import Flask, request, redirect, render_template, session

app = Flask(__name__, static_folder="static")
app.secret_key = "MNFsbNZDbbZMfusdfGHjdfgTidf9024#%@-y3rdsf"

# Connecting with MSSQL connection details
conn_str = (
    "DRIVER={ODBC Driver 17 for SQL Server};"   
    "SERVER=localhost\\SQLEXPRESS;"
    "DATABASE=BookStore;"
    "Trusted_Connection=yes;"
)

# Executing the SQL query to create the table for storing the maximum book ID
create_max_book_id_table_query = """
CREATE TABLE max_book_id (
    max_id INT NOT NULL DEFAULT 0
)s
"""

# Executing the SQL query to create the table for storing login attempts
create_table_query = """
CREATE TABLE login_attempts (
    email VARCHAR(255) NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    PRIMARY KEY (email)
)
"""

cnxn = pyodbc.connect(conn_str)
cursor = cnxn.cursor()

# Insert the initial maximum book ID value (e.g., 1000)
initial_max_book_id = 1000
insert_initial_max_book_id_query = "INSERT INTO max_book_id (max_id) VALUES (?)"
cursor.execute(insert_initial_max_book_id_query, (initial_max_book_id,))
cnxn.commit()


# Role-Based Access Control (RBAC)
def is_admin(user_role):
    return user_role == "admin"


# Protect Routes and Actions with a decorator
def requires_role(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "user" in session:
                # Get the user's role from the session
                user_role = session["user"]["role"]

                # Check if the user has the required role to access the protected route
                if required_role(user_role):
                    return func(*args, **kwargs)
                else:
                    return "Unauthorized. You do not have access to this resource."

            # If the user is not logged in, redirect to the login page
            return redirect("/signin")

        return wrapper

    return decorator


# Hardcoded admin credentials
ADMIN_EMAIL = "admin420@admin.com"
ADMIN_PASSWORD_HASH = bcrypt.hashpw(b"Aladin024@", bcrypt.gensalt())


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


def insert_audit_log(user_id, action, details):
    # Storing the user data in Audit_log while signing up
    query_insert_log = "INSERT INTO audit_log (user_id, action, timestamp, details) VALUES (?, ?, GETDATE(), ?)"
    params_insert_log = (user_id, action, details)

    try:
        cursor.execute(query_insert_log, params_insert_log)
        cnxn.commit()
    except Exception as e:
        print(f"Error occurred while inserting audit log: {str(e)}")
        cnxn.rollback()


@app.route("/signup", methods=["POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"].lower()
        password = request.form["password"]

        # Check if the email already exists in the database
        query_check_email = "SELECT COUNT(*) FROM users WHERE email=?"
        params_check_email = (email,)
        cursor.execute(query_check_email, params_check_email)
        result = cursor.fetchone()

        if result[0] > 0:
            return "Email already exists. Please use a different email."

        # Password policies
        min_password_length = 8
        requires_uppercase = True
        requires_lowercase = True
        requires_digit = True
        requires_special_char = True

        # Check if password meets the other policies
        if len(password) < min_password_length:
            return "Password must be at least {} characters long.".format(
                min_password_length
            )

        if requires_uppercase and not any(char.isupper() for char in password):
            return "Password must contain at least one uppercase letter."

        if requires_lowercase and not any(char.islower() for char in password):
            return "Password must contain at least one lowercase letter."

        if requires_digit and not any(char.isdigit() for char in password):
            return "Password must contain at least one digit."

        if requires_special_char and not any(
            char in password for char in "!@#$%^&*()_-+=[]{}|;:,.<>?"
        ):
            return "Password must contain at least one special character (!@#$%^&*()_-+=[]{}|;:,.<>?)."

        # Check if any substring of the email (before the @ sign) exists in the password
        # Before the "@" symbol, the password cannot contain any substring of two characters from the email.
        # If the email address is "john12@gmail.com," for instance, the password cannot contain the letters "jo," "oh," "hn," "n1," or "12."
        # It can, however, contain "j" and "12" separately.
        email_parts = email.split("@")
        email_substrings = [
            email_parts[0][i : i + 2] for i in range(len(email_parts[0]) - 1)
        ]
        for substring in email_substrings:
            if substring.lower() in password.lower():
                return "Password cannot contain your email address or its substrings."

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        query_insert_user = "INSERT INTO users (email, password) VALUES (?, ?)"
        params_insert_user = (email, hashed_password)

        try:
            cursor.execute(query_insert_user, params_insert_user)
            cnxn.commit()

            # Fetch the last inserted user ID using SCOPE_IDENTITY()
            cursor.execute("SELECT SCOPE_IDENTITY()")
            user_id = cursor.fetchone()[0]

            # Insert audit log for successful sign-up
            insert_audit_log(
                user_id=user_id,
                action="sign_up",
                details=f"User registered with email: {email}",
            )

            print(f"User with email '{email}' signed up successfully.")
            # Redirect the user to the success page after successful sign-up
            return redirect("/success")
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            cnxn.rollback()
            # Redirect the user to the error page if sign-up fails
            return redirect("/error")

    # If the request method is not POST, just show the sign-up form
    return redirect("/")


def reset_login_attempts(email):
    # function to reset the login attempts for the given email in the login_attempts table
    # First, check if the email exists in the table
    query_select = "SELECT COUNT(*) FROM login_attempts WHERE email=?"
    cursor.execute(query_select, (email,))
    result = cursor.fetchone()

    if result[0] == 0:
        # If the email does not exist in the table, insert a new row with attempts=0
        query_insert = "INSERT INTO login_attempts (email, attempts) VALUES (?, 0)"
        cursor.execute(query_insert, (email,))
    else:
        # If the email already exists, reset the attempts count to 0
        query_reset = "UPDATE login_attempts SET attempts=0 WHERE email=?"
        cursor.execute(query_reset, (email,))

    cnxn.commit()


def increment_login_attempts(email):
    # function to increment the login attempts for the given email in the login_attempts table
    # First, check if the email exists in the table
    query_select = "SELECT COUNT(*) FROM login_attempts WHERE email=?"
    cursor.execute(query_select, (email,))
    result = cursor.fetchone()

    if result[0] == 0:
        # If the email does not exist in the table, insert a new row
        query_insert = "INSERT INTO login_attempts (email, attempts) VALUES (?, 1)"
        cursor.execute(query_insert, (email,))
    else:
        # If the email already exists, update the attempts count
        query_update = "UPDATE login_attempts SET attempts=attempts+1 WHERE email=?"
        cursor.execute(query_update, (email,))

    cnxn.commit()


def get_login_attempts(email):
    # function to get the number of login attempts for the given email from the login_attempts table
    query_select = "SELECT attempts FROM login_attempts WHERE email=?"
    cursor.execute(query_select, (email,))
    result = cursor.fetchone()

    # If the email does not exist in the table, return 0 attempts
    if not result:
        return 0

    return result[0]


def delete_user(email):
    # function to delete the user with the given email from the users table
    query_delete_user = "DELETE FROM users WHERE email=?"
    cursor.execute(query_delete_user, (email,))
    cnxn.commit()

    # Reset login attempts for the user after deleting them from the users table
    reset_login_attempts(email)


@app.route("/signin", methods=["POST"])
def signin():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Check if the user credentials match the admin credentials
        if email == ADMIN_EMAIL and bcrypt.checkpw(
            password.encode("utf-8"), ADMIN_PASSWORD_HASH
        ):
            # Admin login successful
            session["user"] = {"email": email, "role": "admin"}
            return redirect("/admindashboard")  # Redirecting to the admin dashboard

        query = "SELECT COUNT(*) FROM users WHERE email=email AND password=password"
        return redirect("/dashboard")
        # params = (email, password)

        # cursor.execute(query, params)
        # result = cursor.fetchone()
        # if result[0] == 1:
        #     print(f"User with email '{email}' signed in successfully.")
        #     # Reset login attempts for the user since login was successful
        #     reset_login_attempts(email)
        #     # Redirect the user to the dashboard page after successful sign-in
        # return redirect("/dashboard")
        # else:
        #     print(f"Sign-in failed for email '{email}'. Invalid credentials.")
        #     # Increment login attempts for the user since login failed
        #     increment_login_attempts(email)
        #     # Check if the user has reached the maximum login attempts (e.g., 3)
        #     login_attempts = get_login_attempts(email)
        #     # Check if the user has exceeded the maximum login attempts
        #     if login_attempts >= 3:
        #         # Delete the user
        #         delete_user(email)
        #         return "You have reached the maximum login attempts. Your account has been deleted."
        #     # Redirect the user to the error page if sign-in fails
        #     return redirect("/error")

    # If the request method is not POST, just show the sign-in form
    return redirect("/")


@app.route("/success")
def success():
    return render_template("success.html")


@app.route("/error")
def error():
    return render_template("error.html")


@app.route("/dashboard")
def dashboard():
    query = "SELECT * FROM books"
    cursor.execute(query)
    books = cursor.fetchall()

    return render_template("dashboard.html", books=books)


@app.route("/admindashboard")
@requires_role(is_admin)
def admindashboard():
    query = "SELECT * FROM books"
    cursor.execute(query)
    books = cursor.fetchall()

    return render_template("admindashboard.html", books=books)


@app.route("/delete_book/<int:book_id>", methods=["POST"])
@requires_role(is_admin)
def delete_book(book_id):
    query_delete = "DELETE FROM books WHERE book_id=?"
    params = (book_id,)
    cursor.execute(query_delete, params)
    cnxn.commit()

    return redirect(
        "/admindashboard"
    )  # Redirect back to the admin dashboard after deleting the book


@app.route("/update_book/<int:book_id>", methods=["GET", "POST"])
@requires_role(is_admin)
def update_book(book_id):
    if request.method == "GET":
        query_select = "SELECT * FROM books WHERE book_id=?"
        params_select = (book_id,)
        cursor.execute(query_select, params_select)
        book = cursor.fetchone()

        if book:
            return render_template("update.html", book=book)
        else:
            return "Book not found."

    elif request.method == "POST":
        title = request.form["title"]
        author = request.form["author"]
        publication_year = request.form["publication_year"]
        query_update = (
            "UPDATE books SET title=?, author=?, publication_year=? WHERE book_id=?"
        )
        params_update = (title, author, publication_year, book_id)

        try:
            cursor.execute(query_update, params_update)
            cnxn.commit()
            print(f"Book with ID '{book_id}' updated successfully.")
            return redirect(
                "/admindashboard"
            )  # Redirect back to the admin dashboard after updating the book
        except Exception as e:
            print(f"Error occurred while updating book: {str(e)}")
            cnxn.rollback()
            return redirect("/error")  # Redirect to the error page if the update fails


@app.route("/create_book", methods=["GET", "POST"])
@requires_role(is_admin)
def create_book():
    if request.method == "GET":
        return render_template("create.html")

    elif request.method == "POST":
        title = request.form["title"]
        author = request.form["author"]
        publication_year = request.form["publication_year"]

        # Get the current maximum book ID from the books table
        query_max_id = "SELECT MAX(book_id) FROM books"
        cursor.execute(query_max_id)
        max_id = cursor.fetchone()[0]

        # Increment the maximum book ID by 1 for the next book
        next_book_id = max_id + 1

        # Insert the new book with the generated book ID into the books table
        query_insert = "INSERT INTO books (book_id, title, author, publication_year) VALUES (?, ?, ?, ?)"
        params_insert = (next_book_id, title, author, publication_year)

        try:
            cursor.execute(query_insert, params_insert)
            cnxn.commit()
            print(f"Book with ID '{next_book_id}' created successfully.")
            return redirect(
                "/admindashboard"
            )  # Redirect back to the admin dashboard after creating the book
        except Exception as e:
            print(f"Error occurred while creating book: {str(e)}")
            cnxn.rollback()
            return redirect(
                "/error"
            )  # Redirect to the error page if book creation fails


if __name__ == "__main__":
    app.run(debug=True)
