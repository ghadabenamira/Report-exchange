import os
import secrets
import time
from functools import wraps
 
from flask import Flask, request, jsonify, g, send_from_directory
 
from db import Database
 
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024    # 10 MB
 
DATA_DIR = os.environ.get("DATA_DIR", app.root_path)   # in Docker this is /data
os.makedirs(DATA_DIR, exist_ok=True)
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXT = {".pdf", ".doc", ".docx", ".txt"}
 
# ---------- DATABASE (one object holding the connection) ----------
db = Database(os.path.join(DATA_DIR, "app.db"))
 
# Tokens are short-lived sessions, so they stay in memory (not in the database)
access_tokens = []     # {"token", "IDs", "expires_at"}
refresh_tokens = []    # {"token", "IDs", "expires_at"}
 
ACCESS_TOKEN_SECONDS = 120      # 2 minutes
REFRESH_TOKEN_SECONDS = 600     # 10 minutes
 
STUDENT_FIELDS = ["FN", "LN", "DMajor", "Level", "Email", "Password"]
REPORT_FIELDS = ["Title", "Type", "K1", "K2", "K3", "Date"]
 
 
# ---------- HELPERS ----------
def check_fields(data, required):
    if not isinstance(data, dict):
        return "Request body must be a valid JSON object"
    missing = [f for f in required if f not in data or data[f] in ("", None)]
    if missing:
        return f"Missing or empty field(s): {', '.join(missing)}"
    return None
 
 
def find_student(ids):
    return db.one("SELECT * FROM students WHERE IDs = ?", (ids,))
 
 
def find_report(idr):
    return db.one("SELECT * FROM reports WHERE IDr = ?", (idr,))
 
 
def full_name(student):
    student = student or {}
    return f"{student.get('FN', '')} {student.get('LN', '')}".strip() or "Unknown"
 
 
def public_report(r):
    """Full report info without the internal stored file name."""
    return {k: v for k, v in r.items() if k != "File"}
 
 
def access_status(report, ids):
    """owner / approved / pending / denied / none"""
    if report["IDs"] == ids:
        return "owner"
    row = db.one("SELECT Status FROM access_requests WHERE IDr = ? AND Requester = ? "
                 "ORDER BY IDq DESC LIMIT 1", (report["IDr"], ids))
    return row["Status"] if row else "none"
 
 
def report_preview(r, viewer=None):
    return {
        "IDr": r["IDr"],
        "Title": r["Title"],
        "Type": r["Type"],
        "Owner": full_name(find_student(r["IDs"])),
        "Access": access_status(r, viewer),
    }
 
 
def request_view(q):
    """An access request with names instead of student IDs."""
    report = find_report(q["IDr"]) or {}
    return {
        "IDq": q["IDq"],
        "IDr": q["IDr"],
        "Title": report.get("Title", ""),
        "Status": q["Status"],
        "RequesterName": full_name(find_student(q["Requester"])),
        "OwnerName": full_name(find_student(q["Owner"])),
    }
 
 
def remove_report_file(report):
    try:
        os.remove(os.path.join(UPLOAD_DIR, report.get("File", "")))
    except OSError:
        pass
 
 
def update_row(table, key_col, key_val, data):
    """UPDATE <table> SET <fields> WHERE key. Column names come from a whitelist only."""
    cols = list(data.keys())
    sql = f"UPDATE {table} SET " + ", ".join(f"{c} = ?" for c in cols) + f" WHERE {key_col} = ?"
    db.execute(sql, [data[c] for c in cols] + [key_val])
 
 
# ---------- TOKEN HELPERS ----------
def create_token(token_list, ids, seconds):
    item = {"token": secrets.token_hex(16), "IDs": ids, "expires_at": time.time() + seconds}
    token_list.append(item)
    return item["token"]
 
 
def find_token(token_list, token):
    return next((i for i in token_list if i["token"] == token), None)
 
 
def require_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
 
        item = find_token(access_tokens, auth.split(" ", 1)[1])
        if item is None:
            return jsonify({"error": "Invalid token"}), 403
 
        if time.time() > item["expires_at"]:
            access_tokens.remove(item)
            return jsonify({"error": "Token expired, use /refresh"}), 401
 
        g.IDs = item["IDs"]
        return f(*args, **kwargs)
    return wrapper
 
 
def current_student():
    """IDs of the logged-in student if a valid token is sent, otherwise None."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    item = find_token(access_tokens, auth.split(" ", 1)[1])
    if item is None or time.time() > item["expires_at"]:
        return None
    return item["IDs"]
 
 
# ---------- HOME PAGE ----------
@app.route("/", methods=["GET"])
def home():
    return send_from_directory(os.path.join(app.root_path, "templates"), "index.html")
 
 
# ---------- AUTH ----------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    error = check_fields(data, ["IDs", "Password"])
    if error:
        return jsonify({"error": error}), 400
 
    student = find_student(data["IDs"])
    if student is None or student["Password"] != data["Password"]:
        return jsonify({"error": "Wrong IDs or password"}), 401
 
    return jsonify({
        "access_token": create_token(access_tokens, student["IDs"], ACCESS_TOKEN_SECONDS),
        "refresh_token": create_token(refresh_tokens, student["IDs"], REFRESH_TOKEN_SECONDS),
        "access_expires_in_seconds": ACCESS_TOKEN_SECONDS,
    }), 200
 
 
@app.route("/refresh", methods=["POST"])
def refresh():
    data = request.get_json(silent=True)
    error = check_fields(data, ["refresh_token"])
    if error:
        return jsonify({"error": error}), 400
 
    item = find_token(refresh_tokens, data["refresh_token"])
    if item is None:
        return jsonify({"error": "Invalid refresh token"}), 403
 
    if time.time() > item["expires_at"]:
        refresh_tokens.remove(item)
        return jsonify({"error": "Refresh token expired, please login again"}), 401
 
    return jsonify({
        "access_token": create_token(access_tokens, item["IDs"], ACCESS_TOKEN_SECONDS),
        "access_expires_in_seconds": ACCESS_TOKEN_SECONDS,
    }), 200
 
 
# ---------- STUDENTS ----------
@app.route("/student", methods=["POST"])
def add_student():
    data = request.get_json(silent=True)
 
    error = check_fields(data, ["IDs"] + STUDENT_FIELDS)
    if error:
        return jsonify({"error": error}), 400
 
    if not isinstance(data["IDs"], int) or not 10000000 <= data["IDs"] <= 99999999:
        return jsonify({"error": "IDs must be exactly 8 digits"}), 400
 
    if "@" not in str(data["Email"]):
        return jsonify({"error": "Email is not valid"}), 400
 
    if find_student(data["IDs"]):
        return jsonify({"error": f"Student with IDs {data['IDs']} already exists"}), 409
 
    db.execute(
        "INSERT INTO students (IDs, FN, LN, DMajor, Level, Email, Password) VALUES (?,?,?,?,?,?,?)",
        (data["IDs"], data["FN"], data["LN"], data["DMajor"], data["Level"],
         data["Email"], data["Password"]))
    return jsonify({"message": "Student added successfully"}), 201
 
 
@app.route("/students", methods=["GET"])
@require_token
def get_students():
    # No IDs, emails or passwords: other students are shown by name only
    rows = db.all("SELECT FN, LN, DMajor, Level FROM students")
    return jsonify(rows), 200
 
 
@app.route("/me", methods=["GET"])
@require_token
def me():
    s = find_student(g.IDs)
    if s is None:
        return jsonify({"error": "Student not found"}), 404
    return jsonify({k: v for k, v in s.items() if k != "Password"}), 200
 
 
@app.route("/students/<int:ids>", methods=["GET"])
@require_token
def get_student(ids):
    if ids != g.IDs:
        return jsonify({"error": "You can only view your own account"}), 403
    s = find_student(ids)
    if s is None:
        return jsonify({"error": f"Student {ids} not found"}), 404
    return jsonify({k: v for k, v in s.items() if k != "Password"}), 200
 
 
@app.route("/students/<int:ids>", methods=["PUT"])
@require_token
def update_student(ids):
    if ids != g.IDs:
        return jsonify({"error": "You can only edit your own account"}), 403
    if find_student(ids) is None:
        return jsonify({"error": f"Student {ids} not found"}), 404
 
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data:
        return jsonify({"error": "Send a JSON object with the fields to update"}), 400
 
    for key, value in data.items():
        if key not in STUDENT_FIELDS:
            return jsonify({"error": f"Field '{key}' cannot be updated"}), 400
        if value in ("", None):
            return jsonify({"error": f"Field '{key}' cannot be empty"}), 400
    if "Email" in data and "@" not in str(data["Email"]):
        return jsonify({"error": "Email is not valid"}), 400
 
    update_row("students", "IDs", ids, data)
    s = find_student(ids)
    return jsonify({k: v for k, v in s.items() if k != "Password"}), 200
 
 
@app.route("/students/<int:ids>", methods=["DELETE"])
@require_token
def delete_student(ids):
    if ids != g.IDs:
        return jsonify({"error": "You can only delete your own account"}), 403
    if find_student(ids) is None:
        return jsonify({"error": f"Student {ids} not found"}), 404
 
    for r in db.all("SELECT File FROM reports WHERE IDs = ?", (ids,)):
        remove_report_file(r)
    # ON DELETE CASCADE removes this student's reports and related access requests
    db.execute("DELETE FROM students WHERE IDs = ?", (ids,))
    access_tokens[:] = [t for t in access_tokens if t["IDs"] != ids]
    refresh_tokens[:] = [t for t in refresh_tokens if t["IDs"] != ids]
    return jsonify({"message": "Account deleted"}), 200
 
 
# ---------- REPORTS ----------
@app.route("/report", methods=["POST"])
@require_token
def add_report():
    # Sent as multipart form data: text fields + one file called "file"
    data = request.form.to_dict()
 
    error = check_fields(data, REPORT_FIELDS)
    if error:
        return jsonify({"error": error}), 400
 
    file = request.files.get("file")
    if file is None or file.filename == "":
        return jsonify({"error": "A report file is required"}), 400
 
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXT:
        return jsonify({"error": "File type not allowed. Use PDF, DOC, DOCX or TXT"}), 400
 
    # Insert first (IDr is auto-generated), then store the file under that id
    cur = db.execute(
        "INSERT INTO reports (IDs, Title, Type, K1, K2, K3, File, FileName, Date) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (g.IDs, data["Title"], data["Type"], data["K1"], data["K2"], data["K3"],
         "", os.path.basename(file.filename), data["Date"]))
    idr = cur.lastrowid
    stored_name = f"report_{idr}{ext}"
    file.save(os.path.join(UPLOAD_DIR, stored_name))
    db.execute("UPDATE reports SET File = ? WHERE IDr = ?", (stored_name, idr))
    return jsonify({"message": "Report added successfully", "IDr": idr}), 201
 
 
@app.route("/reports", methods=["GET"])
def get_reports():
    viewer = current_student()
    rows = db.all("SELECT * FROM reports")
    return jsonify([report_preview(r, viewer) for r in rows]), 200
 
 
@app.route("/reports/mine", methods=["GET"])
@require_token
def my_reports():
    rows = db.all("SELECT * FROM reports WHERE IDs = ?", (g.IDs,))
    return jsonify([public_report(r) for r in rows]), 200
 
 
@app.route("/reports/search", methods=["GET"])
def search_reports():
    q = request.args.get("q", "").strip().lower()
    if not q:
        return jsonify({"error": "Missing search text, use /reports/search?q=..."}), 400
 
    like = f"%{q}%"
    rows = db.all("SELECT * FROM reports WHERE Title LIKE ? OR Type LIKE ? OR K1 LIKE ? "
                  "OR K2 LIKE ? OR K3 LIKE ?", (like,) * 5)
    viewer = current_student()
    return jsonify([report_preview(r, viewer) for r in rows]), 200
 
 
@app.route("/reports/<int:idr>", methods=["GET"])
def view_report(idr):
    report = find_report(idr)
    if report is None:
        return jsonify({"error": f"Report {idr} not found"}), 404
 
    data = public_report(report)
    status = access_status(report, current_student())
    data["Access"] = status
    data["Owner"] = full_name(find_student(report["IDs"]))
    if status != "owner":
        data.pop("IDs", None)          # the owner's student ID stays private
    return jsonify(data), 200
 
 
@app.route("/reports/<int:idr>", methods=["PUT"])
@require_token
def update_report(idr):
    report = find_report(idr)
    if report is None:
        return jsonify({"error": f"Report {idr} not found"}), 404
    if report["IDs"] != g.IDs:
        return jsonify({"error": "Only the owner can edit this report"}), 403
 
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data:
        return jsonify({"error": "Send a JSON object with the fields to update"}), 400
 
    for key, value in data.items():
        if key not in REPORT_FIELDS:
            return jsonify({"error": f"Field '{key}' cannot be updated"}), 400
        if value in ("", None):
            return jsonify({"error": f"Field '{key}' cannot be empty"}), 400
 
    update_row("reports", "IDr", idr, data)
    return jsonify(public_report(find_report(idr))), 200
 
 
@app.route("/reports/<int:idr>", methods=["DELETE"])
@require_token
def delete_report(idr):
    report = find_report(idr)
    if report is None:
        return jsonify({"error": f"Report {idr} not found"}), 404
    if report["IDs"] != g.IDs:
        return jsonify({"error": "Only the owner can delete this report"}), 403
 
    remove_report_file(report)
    db.execute("DELETE FROM reports WHERE IDr = ?", (idr,))   # its access requests cascade
    return jsonify({"message": f"Report {idr} deleted"}), 200
 
 
@app.route("/reports/<int:idr>/download", methods=["GET"])
@require_token
def download_report(idr):
    report = find_report(idr)
    if report is None:
        return jsonify({"error": f"Report {idr} not found"}), 404
 
    if access_status(report, g.IDs) not in ("owner", "approved"):
        return jsonify({"error": "Access required. Send a request to the owner."}), 403
 
    if not os.path.exists(os.path.join(UPLOAD_DIR, report.get("File", ""))):
        return jsonify({"error": "The file for this report is missing on the server"}), 404
 
    return send_from_directory(UPLOAD_DIR, report["File"],
                               as_attachment=True, download_name=report["FileName"])
 
 
# ---------- ACCESS REQUESTS ----------
@app.route("/reports/<int:idr>/request", methods=["POST"])
@require_token
def request_access(idr):
    report = find_report(idr)
    if report is None:
        return jsonify({"error": f"Report {idr} not found"}), 404
 
    if report["IDs"] == g.IDs:
        return jsonify({"error": "This is your own report"}), 400
 
    status = access_status(report, g.IDs)
    if status == "approved":
        return jsonify({"error": "You already have access"}), 409
    if status == "pending":
        return jsonify({"error": "You already have a pending request"}), 409
 
    cur = db.execute("INSERT INTO access_requests (IDr, Requester, Owner, Status) "
                     "VALUES (?,?,?,'pending')", (idr, g.IDs, report["IDs"]))
    req = db.one("SELECT * FROM access_requests WHERE IDq = ?", (cur.lastrowid,))
    owner = find_student(report["IDs"]) or {}
    return jsonify({"message": "Access request sent", "request": request_view(req),
                    "notify": owner.get("Email", ""), "title": report["Title"]}), 201
 
 
@app.route("/requests/received", methods=["GET"])
@require_token
def received_requests():
    rows = db.all("SELECT * FROM access_requests WHERE Owner = ?", (g.IDs,))
    return jsonify([request_view(q) for q in rows]), 200
 
 
@app.route("/requests/sent", methods=["GET"])
@require_token
def sent_requests():
    rows = db.all("SELECT * FROM access_requests WHERE Requester = ?", (g.IDs,))
    return jsonify([request_view(q) for q in rows]), 200
 
 
@app.route("/requests/<int:idq>", methods=["PUT"])
@require_token
def answer_request(idq):
    data = request.get_json(silent=True)
    error = check_fields(data, ["Status"])
    if error:
        return jsonify({"error": error}), 400
 
    if data["Status"] not in ("approved", "denied"):
        return jsonify({"error": "Status must be 'approved' or 'denied'"}), 400
 
    req = db.one("SELECT * FROM access_requests WHERE IDq = ?", (idq,))
    if req is None:
        return jsonify({"error": f"Request {idq} not found"}), 404
 
    if req["Owner"] != g.IDs:
        return jsonify({"error": "Only the report owner can answer this request"}), 403
 
    if req["Status"] != "pending":
        return jsonify({"error": f"Request already {req['Status']}"}), 409
 
    db.execute("UPDATE access_requests SET Status = ? WHERE IDq = ?", (data["Status"], idq))
    req["Status"] = data["Status"]
    asker = find_student(req["Requester"]) or {}
    rep = find_report(req["IDr"]) or {}
    return jsonify({"message": f"Request {data['Status']}", "request": request_view(req),
                    "notify": asker.get("Email", ""), "title": rep.get("Title", "")}), 200
 
 
# ---------- GLOBAL ERROR HANDLERS ----------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route not found"}), 404
 
 
@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405
 
 
@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large (maximum 10 MB)"}), 413
 
 
@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500
 
 
if __name__ == "__main__":
    app.run(debug=True)
 