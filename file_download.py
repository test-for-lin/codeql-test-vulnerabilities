"""
Second demo file for GHAS CodeQL testing.

Unlike app.py (which has critical-severity SQL/command/code injection),
this file contains exactly one vulnerability at HIGH severity: path
traversal via user-controlled filenames.

DO NOT deploy this. DO NOT copy these patterns into real projects.
"""

import os

from flask import Flask, request

app = Flask(__name__)

UPLOAD_DIR = "/var/demo/uploads"


@app.route("/download")
def download_file():
    """Path traversal: user input used to build a filesystem path with no
    sanitization, allowing '../' segments to escape UPLOAD_DIR.

    CodeQL: py/path-injection (CWE-022, security-severity ~7.5 -> "high").
    """
    filename = request.args.get("filename", "")
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, "rb") as f:
        return f.read()


if __name__ == "__main__":
    app.run(debug=True)
