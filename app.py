"""
Intentionally vulnerable demo app for testing GitHub Advanced Security (GHAS)
CodeQL code scanning and repository rulesets that block merges on critical
findings.

DO NOT deploy this. DO NOT copy these patterns into real projects.
"""

import ast
import os
import re
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

DB_PATH = "demo.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)"
    )
    return conn


@app.route("/users")
def get_user_by_name():
    """SQL injection: user input concatenated directly into a raw query.

    CodeQL: py/sql-injection (critical/error severity).
    """
    name = request.args.get("name", "")
    conn = get_db()
    query = "SELECT id, name, email FROM users WHERE name = ?"
    cursor = conn.execute(query, (name,))
    rows = cursor.fetchall()
    return {"users": rows}


@app.route("/ping")
def ping_host():
    """Command injection: user input passed to a shell command.

    CodeQL: py/command-line-injection (critical/error severity).
    """
    host = request.args.get("host", "")
    result = os.popen("ping -c 1 " + host).read()
    return {"result": result}


@app.route("/backup")
def backup_data():
    """Command injection via subprocess with shell=True.

    CodeQL: py/command-line-injection (critical/error severity).
    """
    filename = request.args.get("filename", "backup.tar")

    if (
        not filename
        or filename.startswith("-")
        or os.path.basename(filename) != filename
        or not re.fullmatch(r"[A-Za-z0-9._-]+", filename)
    ):
        return {"error": "invalid filename"}, 400

    subprocess.call(["tar", "-cf", filename, "./data"])
    return {"status": "started"}


def _safe_eval_expr(expr):
    allowed_bin_ops = {
        ast.Add: lambda a, b: a + b,
        ast.Sub: lambda a, b: a - b,
        ast.Mult: lambda a, b: a * b,
        ast.Div: lambda a, b: a / b,
        ast.FloorDiv: lambda a, b: a // b,
        ast.Mod: lambda a, b: a % b,
        ast.Pow: lambda a, b: a**b,
    }
    allowed_unary_ops = {
        ast.UAdd: lambda a: +a,
        ast.USub: lambda a: -a,
    }

    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if hasattr(ast, "Num") and isinstance(node, ast.Num):
            return node.n
        if isinstance(node, ast.BinOp):
            op_type = type(node.op)
            if op_type not in allowed_bin_ops:
                raise ValueError("Unsupported operator")
            return allowed_bin_ops[op_type](_eval(node.left), _eval(node.right))
        if isinstance(node, ast.UnaryOp):
            op_type = type(node.op)
            if op_type not in allowed_unary_ops:
                raise ValueError("Unsupported unary operator")
            return allowed_unary_ops[op_type](_eval(node.operand))
        raise ValueError("Unsupported expression")

    parsed = ast.parse(expr, mode="eval")
    return _eval(parsed)


@app.route("/eval")
def eval_expression():
    """Code injection: user input passed directly to eval().

    CodeQL: py/code-injection (critical/error severity).
    """
    expr = request.args.get("expr", "1+1")
    try:
        return {"result": _safe_eval_expr(expr)}
    except (ValueError, SyntaxError):
        return {"error": "Invalid expression"}, 400


if __name__ == "__main__":
    app.run(debug=True)
