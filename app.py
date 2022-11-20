import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
from datetime import datetime


# time function
def time():
    return datetime.now().isoformat(sep=" ", timespec="seconds")


# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Stock names, prices, quantities owned. Also gives stock value
    inventory = db.execute(
        "SELECT stock, shares FROM inventory WHERE user_id = ? AND inventory.shares > 0 GROUP BY stock", session.get("user_id"))
    for stock in inventory:
        stock["price"] = lookup(stock["stock"])["price"]
        stock["total"] = stock["price"] * stock["shares"]
    stockVal = sum(item['total'] for item in inventory)

    # Username, cash
    user = db.execute("SELECT username, cash FROM users WHERE id = ?", session.get("user_id"))[0]
    if not isinstance(user["cash"], float) and not isinstance(user["cash"], int):
        user["cash"] = float(user["cash"].replace(",", ""))
    totalVal = user["cash"] + stockVal

    return render_template("index.html", inventory=inventory, user=user, stockVal=stockVal, totalVal=totalVal)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        # Validate symbol
        symbol = request.form.get("symbol")
        symbol = lookup(symbol)
        if symbol is None:
            return apology("invalid symbol")

        # Validate quantity
        try:
            shares = float(request.form.get("shares"))
        except ValueError:
            return apology("quantity must be a number")

        if (not shares) or (not shares.is_integer()) or (shares < 1):
            return apology("quantity must be a positive integer")

        # Validate if user can afford transaction
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session.get("user_id"))[0]["cash"]
        buy = symbol["price"] * shares
        if balance < buy:
            return apology("insufficient balance. transaction failed.")

        """Complete the transaction"""
        # Create stock in stocks table if it doesn't exist
        stockList = [x['stock'] for x in db.execute("SELECT stock FROM stocks")]
        if symbol["symbol"] not in stockList:
            db.execute("INSERT INTO stocks (stock) VALUES(?)", symbol["symbol"])

        # Create inventory item if it doesn't exist
        userInventory = [x["stock"] for x in db.execute("""SELECT stock FROM inventory
                                                            JOIN users ON users.id = inventory.user_id
                                                            WHERE users.id = ?""",
                                                        session.get("user_id"))]
        if symbol["symbol"] not in userInventory:
            db.execute("INSERT INTO inventory (user_id, stock, shares) VALUES(?, ?, ?)",
                       session.get("user_id"), symbol["symbol"], 0)
        # Update inventory
        db.execute("UPDATE inventory SET shares = shares + ? WHERE user_id = ? AND stock = ?",
                   shares, session.get("user_id"), symbol["symbol"])

        # Create transaction
        db.execute("INSERT INTO transactions (user_id, stock, price, buy, total, time) VALUES(?, ?, ?, ?, ?, ?)",
                   session.get("user_id"), symbol["symbol"], symbol["price"], shares, buy, time())

        # Update money
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", buy, session.get("user_id"))

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Stock names, prices, quantities owned. Also gives stock value
    transactions = db.execute(
        "SELECT time, stock, price, buy, sell, total FROM transactions JOIN users ON users.id = transactions.user_id WHERE user_id = ? ORDER BY time DESC", session.get("user_id"))

    for transaction in transactions:
        if transaction["buy"] is None:
            transaction["buy"] = ""
        if transaction["sell"] is None:
            transaction["sell"] = ""
    # # Username, cash
    # user = db.execute("SELECT username, cash FROM users WHERE id = ?", session.get("user_id"))[0]
    # if not isinstance(user["cash"], float):
    #     user["cash"] = float(user["cash"].replace(",", ""))
    # totalVal = user["cash"] + stockVal

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Logs user in"""

    text = ""
    if request.method == "POST":
        # Look up symbol
        symbol = request.form.get("symbol")
        symbol = lookup(symbol)
        if symbol is None:
            return apology("invalid symbol")
        text = "The price of " + symbol["name"] + " (" + symbol["symbol"] + ") is " + str(usd(symbol["price"]))

    return render_template("quote.html", text=text)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        # Validate new username
        username = request.form.get("username")
        if not username:
            return apology("username cannot be blank")
        current_users = [user['username'] for user in db.execute("SELECT username FROM users")]
        if username in current_users:
            return apology("username taken")

        # Confirm password
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not password or not confirmation:
            return apology("please enter password and confirmation")
        if not password == confirmation:
            return apology("passwords do not match")

        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, generate_password_hash(password))

        return redirect("/register")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    userInventoryDict = db.execute("""SELECT stock, shares FROM inventory
                                JOIN users ON users.id = inventory.user_id
                                WHERE users.id = ?
                                ORDER BY stock""",
                                   session.get("user_id"))
    print(userInventoryDict)
    userInventory = [x["stock"] for x in userInventoryDict]
    print(userInventory)

    if request.method == "POST":
        # Validate symbol
        symbol = request.form.get("symbol")
        symbol = lookup(symbol)
        if (symbol["symbol"] is None) or (symbol["symbol"] not in userInventory):
            return apology("invalid symbol")

        # Validate quantity
        try:
            shares = float(request.form.get("shares"))
        except ValueError:
            return apology("quantity must be a number")

        if (not shares) or (not shares.is_integer()) or (shares < 1):
            return apology("quantity must be a positive integer")

        # Validate if user owns at least that many stock
        sharesOwned = next(x["shares"] for x in userInventoryDict if x["stock"] == symbol["symbol"])
        if shares > sharesOwned:
            return apology("you can't sell more stock than you currently own")

        """Complete the transaction"""
        sell = symbol["price"] * shares

        # Update inventory
        db.execute("UPDATE inventory SET shares = shares - ? WHERE user_id = ? AND stock = ?",
                   shares, session.get("user_id"), symbol["symbol"])

        # Create transaction
        db.execute("INSERT INTO transactions (user_id, stock, price, sell, total, time) VALUES(?, ?, ?, ?, ?, ?)",
                   session.get("user_id"), symbol["symbol"], symbol["price"], shares, sell, time())

        # Update money
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", sell, session.get("user_id"))

        # Redirect user to home page
        print("SUCCESS! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        return redirect("/")

    # GET
    else:
        return render_template("sell.html", userInventory=userInventory)