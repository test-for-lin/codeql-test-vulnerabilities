"""
Fourth demo file for GHAS CodeQL testing.

Contains findings expected at MEDIUM and LOW severity only -- no
high/critical injection classes here (see app.py / file_download.py for
those).

Note: exact severity buckets can shift slightly between CodeQL query-pack
releases; these two are chosen to sit clearly below "high" under the
default `security-and-quality` suite.

DO NOT deploy this. DO NOT copy these patterns into real projects.
"""

import tempfile

from flask import Flask, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    """Reflected XSS: user input echoed back into an HTML response without
    escaping.

    CodeQL: py/reflected-xss (CWE-079/080, typically "medium" severity).
    """
    name = request.args.get("name", "world")
    html = "<html><body><h1>Hello, " + name + "!</h1></body></html>"
    return html


@app.route("/export")
def export_report():
    """Insecure temporary file: mktemp() returns a predictable name and
    leaves a race-condition window between name generation and file use.

    CodeQL: py/insecure-temporary-file (CWE-377, typically "low" severity).
    """
    temp_path = tempfile.mktemp(suffix=".csv")
    with open(temp_path, "w") as f:
        f.write("id,name\n")
    return {"path": temp_path}


if __name__ == "__main__":
    app.run(debug=True)
