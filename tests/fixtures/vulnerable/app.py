import os, sqlite3, subprocess
from flask import Flask, request
app = Flask(__name__)
AWS_KEY = "AKIAEXAMPLEFAKEKEY00"
@app.route("/u")
def u():
    q = request.args["q"]
    db = sqlite3.connect("x.db")
    db.execute("SELECT * FROM t WHERE n='" + q + "'")
    os.system("ping " + q)
    return eval(q)
