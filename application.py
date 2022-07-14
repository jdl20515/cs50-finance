import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    
    user_id = session["user_id"]
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    stocks = db.execute("SELECT symbol, name, price, SUM(shares) as totalShares FROM transactions WHERE user_id = ? GROUP BY symbol", user_id) 
    total = cash
    for stock in stocks:
        total +=stock["price"] * stock["totalShares"]
   
    return render_template("index.html", stocks=stocks, cash=cash, usd=usd, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    
    if request.method == "POST":
        symbol = request.form.get("symbol")
        item = lookup(symbol)
        
        
        if not symbol:
            return apology("Please enter a symbol", 400)
        elif not item:
            return apology("Invalid symbol", 400)
        
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Shares must be a number", 400)
            
        if shares <= 0:
            return apology("Shares must be a positive number", 400)
            
        user_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        quotePrice = item.get('price')
        quoteName = item.get('name')

        if cash < (shares * quotePrice):
            return apology("Can not afford", 400)
        
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash-(shares*quotePrice), user_id)
        db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)", user_id, quoteName, shares, quotePrice, 'buy', symbol )
        return redirect("/")
            
        
    
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    stocks = db.execute("SELECT symbol, shares, price, time FROM transactions WHERE user_id = ? GROUP BY symbol", user_id) 
    return render_template("history.html", stocks=stocks, usd=usd)



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
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("missing symbol", 400)
        quote = request.form.get("symbol")
        if lookup(quote) == None:
            return apology("invalid symbol", 400)
        quoted = lookup(quote)
        
        quoteName = quoted.get('name')
        quotePrice = usd(quoted.get('price'))
        quoteSymbol = quoted.get('symbol')
        return render_template("quoted.html", quoteName = quoteName, quotePrice = quotePrice, quoteSymbol = quoteSymbol)
    else:    
        return render_template("quote.html")
        


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)
        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)
        elif (len(request.form.get("password")) < 5):
            return apology("password must be at least 5 characters long", 400)
        elif db.execute("SELECT username FROM users WHERE username = ?", request.form.get("username")):
            return apology("username not available", 400)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 400)
        
        numbers = ['1', '2', '3', '4', '5', '6', '7', '8', '9']
        letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
        symbols = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', '{', ']', '}', '|', '/', '?', ',', '.']
        checkNumber = False
        checkLetters = False
        checkSymbols = False
        
        
        for i in range(0, len(request.form.get("password"))):
            if request.form.get("password")[i] in numbers:
                checkNumber = True
        if checkNumber == False:
            return apology("password requries number", 400)

        for i in range(0, len(request.form.get("password"))):
            if request.form.get("password")[i] in letters:
                checkLetters = True
        if checkLetters == False:
            return apology("password requries letter", 400)

        for i in range(0, len(request.form.get("password"))):
            if request.form.get("password")[i] in symbols:
                checkSymbols = True
        if checkSymbols == False:
            return apology("password requries symbol", 400)
            
            
        #store in db
        username = request.form.get("username")
        password = request.form.get("password")
        hashed = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)",username, hashed)
        
        
        
        return redirect("/login")
            
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        user_id = session["user_id"]
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        
        if not symbol:
            return apology("select symbol", 400)
        if not shares:
            return apology("select shares", 400)
            
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("select shares to sell", 400)       
       
        if shares <= 0:
            return apology("shares must be a positive integer", 400)
            
            
        item_price = lookup(symbol)["price"]
        item_name = lookup(symbol)["name"]
        price = shares * item_price
        
        shares_owned = db.execute("SELECT shares FROM transactions WHERE name = ? AND user_id = ? GROUP BY symbol", item_name, user_id)[0]["shares"]
        
        if shares_owned < shares:
            return apology("Not enough shares", 400)
        
        current_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", current_cash + price, user_id)
        db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
        user_id, item_name, -shares, item_price, "sell", symbol)
        
        
        
        return redirect("/")
    
    else:
        user_id = session["user_id"]
        stocks = db.execute("SELECT symbol, shares, price, time FROM transactions WHERE user_id = ? GROUP BY symbol", user_id) 
        return render_template("sell.html", stocks=stocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
