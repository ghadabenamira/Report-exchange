import os
import json
import secrets
import time
from functools import wraps

from flask import Flask, request, jsonify, g, send_from_directory

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024    # 10 MB

UPLOAD_DIR = os.path.join(app.root_path, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXT = {".pdf", ".doc", ".docx", ".txt"}

# ---------- SAVE LISTS TO A FILE (survives restarts) ----------
DATA_FILE = os.path.join(app.root_path, "data.json")


def load_data():
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_data():
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump({"students": students, "reports": reports,
                   "access_requests": access_requests}, f, indent=2)


# ---------- ALL DATA IN LISTS ----------
_saved = load_data()
students = _saved.get("students", [])               # IDs, FN, LN, DMajor, Level, Password
reports = _saved.get("reports", [])                 # IDr, IDs, Title, Type, K1, K2, K3, File, FileName, Date
access_requests = _saved.get("access_requests", []) # IDq, IDr, Requester, Owner, Status
access_tokens = []     # {"token", "IDs", "expires_at"}
refresh_tokens = []    # {"token", "IDs", "expires_at"}

ACCESS_TOKEN_SECONDS = 120      # 2 minutes
REFRESH_TOKEN_SECONDS = 600     # 10 minutes


# ---------- HELPERS ----------
def next_id(items, key):
    return max((i[key] for i in items), default=0) + 1


def check_fields(data, required):
    if not isinstance(data, dict):
        return "Request body must be a valid JSON object"
    missing = [f for f in required if f not in data or data[f] in ("", None)]
    if missing:
        return f"Missing or empty field(s): {', '.join(missing)}"
    return None


def find_student(ids):
    return next((s for s in students if s["IDs"] == ids), None)


def find_report(idr):
    return next((r for r in reports if r["IDr"] == idr), None)


def public_report(r):
    """Full report info without the internal stored file name."""
    return {k: v for k, v in r.items() if k != "File"}


def access_status(report, ids):
    """owner / approved / pending / denied / none"""
    if report["IDs"] == ids:
        return "owner"
    status = "none"
    for req in access_requests:
        if req["IDr"] == report["IDr"] and req["Requester"] == ids:
            status = req["Status"]
    return status


def report_preview(r, viewer=None):
    owner = find_student(r["IDs"])
    return {
        "IDr": r["IDr"],
        "Title": r["Title"],
        "Type": r["Type"],
        "Owner": f"{owner['FN']} {owner['LN']}" if owner else "Unknown",
        "Access": access_status(r, viewer),
    }


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


def remove_report_file(report):
    try:
        os.remove(os.path.join(UPLOAD_DIR, report.get("File", "")))
    except OSError:
        pass

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

    error = check_fields(data, ["IDs", "FN", "LN", "DMajor", "Level", "Email", "Password"])
    if error:
        return jsonify({"error": error}), 400

    if not isinstance(data["IDs"], int) or not 10000000 <= data["IDs"] <= 99999999:
        return jsonify({"error": "IDs must be exactly 8 digits"}), 400

    if find_student(data["IDs"]):
        return jsonify({"error": f"Student with IDs {data['IDs']} already exists"}), 409

    students.append({
        "IDs": data["IDs"],
        "FN": data["FN"],
        "LN": data["LN"],
        "DMajor": data["DMajor"],
        "Level": data["Level"],
        "Email": data["Email"],
        "Password": data["Password"],
    })
    save_data()
    return jsonify({"message": "Student added successfully"}), 201


@app.route("/students", methods=["GET"])
@require_token
def get_students():
    safe = [{k: v for k, v in s.items() if k not in ("Password", "Email")} for s in students]
    return jsonify(safe), 200

@app.route("/me", methods=["GET"])
@require_token
def me():
    s = find_student(g.IDs)
    if s is None:
        return jsonify({"error": "Student not found"}), 404
    return jsonify({k: v for k, v in s.items() if k != "Password"}), 200

# ---------- REPORTS ----------
@app.route("/report", methods=["POST"])
@require_token
def add_report():
    # Sent as multipart form data: text fields + one file called "file"
    data = request.form.to_dict()

    error = check_fields(data, ["Title", "Type", "K1", "K2", "K3", "Date"])
    if error:
        return jsonify({"error": error}), 400

    file = request.files.get("file")
    if file is None or file.filename == "":
        return jsonify({"error": "A report file is required"}), 400

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXT:
        return jsonify({"error": "File type not allowed. Use PDF, DOC, DOCX or TXT"}), 400

    idr = next_id(reports, "IDr")                 # auto-generated
    stored_name = f"report_{idr}{ext}"
    file.save(os.path.join(UPLOAD_DIR, stored_name))

    report = {
        "IDr": idr,
        "IDs": g.IDs,                             # owner = logged-in student
        "Title": data["Title"],
        "Type": data["Type"],
        "K1": data["K1"],
        "K2": data["K2"],
        "K3": data["K3"],
        "File": stored_name,
        "FileName": os.path.basename(file.filename),
        "Date": data["Date"],
    }
    reports.append(report)
    save_data()
    return jsonify({"message": "Report added successfully", "IDr": idr}), 201


@app.route("/reports", methods=["GET"])
def get_reports():
    viewer = current_student()
    return jsonify([report_preview(r, viewer) for r in reports]), 200



@app.route("/reports/mine", methods=["GET"])
@require_token
def my_reports():
    return jsonify([public_report(r) for r in reports if r["IDs"] == g.IDs]), 200


@app.route("/reports/search", methods=["GET"])
def search_reports():
    q = request.args.get("q", "").strip().lower()
    if not q:
        return jsonify({"error": "Missing search text, use /reports/search?q=..."}), 400

    viewer = current_student()
    results = [
        report_preview(r, viewer) for r in reports
        if any(q in str(r[f]).lower() for f in ["Title", "Type", "K1", "K2", "K3"])
    ]
    return jsonify(results), 200


@app.route("/reports/<int:idr>", methods=["GET"])
def view_report(idr):
    report = find_report(idr)
    if report is None:
        return jsonify({"error": f"Report {idr} not found"}), 404

    data = public_report(report)
    data["Access"] = access_status(report, current_student())
    return jsonify(data), 200


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

    req = {
        "IDq": next_id(access_requests, "IDq"),
        "IDr": idr,
        "Requester": g.IDs,
        "Owner": report["IDs"],
        "Status": "pending",
    }
    access_requests.append(req)
    save_data()
    owner = find_student(report["IDs"]) or {}
    return jsonify({"message": "Access request sent", "request": req,
                    "notify": owner.get("Email", ""), "title": report["Title"]}), 201

@app.route("/requests/received", methods=["GET"])
@require_token
def received_requests():
    return jsonify([q for q in access_requests if q["Owner"] == g.IDs]), 200


@app.route("/requests/sent", methods=["GET"])
@require_token
def sent_requests():
    return jsonify([q for q in access_requests if q["Requester"] == g.IDs]), 200


@app.route("/requests/<int:idq>", methods=["PUT"])
@require_token
def answer_request(idq):
    data = request.get_json(silent=True)
    error = check_fields(data, ["Status"])
    if error:
        return jsonify({"error": error}), 400

    if data["Status"] not in ("approved", "denied"):
        return jsonify({"error": "Status must be 'approved' or 'denied'"}), 400

    req = next((q for q in access_requests if q["IDq"] == idq), None)
    if req is None:
        return jsonify({"error": f"Request {idq} not found"}), 404

    if req["Owner"] != g.IDs:
        return jsonify({"error": "Only the report owner can answer this request"}), 403

    if req["Status"] != "pending":
        return jsonify({"error": f"Request already {req['Status']}"}), 409

    req["Status"] = data["Status"]
    save_data()
    asker = find_student(req["Requester"]) or {}
    rep = find_report(req["IDr"]) or {}
    return jsonify({"message": f"Request {data['Status']}", "request": req,
                    "notify": asker.get("Email", ""), "title": rep.get("Title", "")}), 200

# ---------- STUDENT BY ID, PUT, DELETE ----------
@app.route("/students/<int:ids>", methods=["GET"])
@require_token
def get_student(ids):
    s = find_student(ids)
    if s is None:
        return jsonify({"error": f"Student {ids} not found"}), 404
    hidden = ("Password",) if ids == g.IDs else ("Password", "Email")
    return jsonify({k: v for k, v in s.items() if k not in hidden}), 200


@app.route("/students/<int:ids>", methods=["PUT"])
@require_token
def update_student(ids):
    if ids != g.IDs:
        return jsonify({"error": "You can only edit your own account"}), 403
    s = find_student(ids)
    if s is None:
        return jsonify({"error": f"Student {ids} not found"}), 404

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data:
        return jsonify({"error": "Send a JSON object with the fields to update"}), 400

    allowed = ["FN", "LN", "DMajor", "Level", "Email", "Password"]
    for key, value in data.items():
        if key not in allowed:
            return jsonify({"error": f"Field '{key}' cannot be updated"}), 400
        if value in ("", None):
            return jsonify({"error": f"Field '{key}' cannot be empty"}), 400
    if "Email" in data and "@" not in str(data["Email"]):
        return jsonify({"error": "Email is not valid"}), 400

    s.update(data)
    save_data()
    return jsonify({k: v for k, v in s.items() if k != "Password"}), 200


@app.route("/students/<int:ids>", methods=["DELETE"])
@require_token
def delete_student(ids):
    if ids != g.IDs:
        return jsonify({"error": "You can only delete your own account"}), 403
    s = find_student(ids)
    if s is None:
        return jsonify({"error": f"Student {ids} not found"}), 404

    for r in [r for r in reports if r["IDs"] == ids]:
        remove_report_file(r)
    reports[:] = [r for r in reports if r["IDs"] != ids]
    access_requests[:] = [q for q in access_requests if ids not in (q["Requester"], q["Owner"])]
    students.remove(s)
    access_tokens[:] = [t for t in access_tokens if t["IDs"] != ids]
    refresh_tokens[:] = [t for t in refresh_tokens if t["IDs"] != ids]
    save_data()
    return jsonify({"message": "Account deleted"}), 200


# ---------- REPORT PUT, DELETE ----------
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

    allowed = ["Title", "Type", "K1", "K2", "K3", "Date"]
    for key, value in data.items():
        if key not in allowed:
            return jsonify({"error": f"Field '{key}' cannot be updated"}), 400
        if value in ("", None):
            return jsonify({"error": f"Field '{key}' cannot be empty"}), 400

    report.update(data)
    save_data()
    return jsonify(public_report(report)), 200


@app.route("/reports/<int:idr>", methods=["DELETE"])
@require_token
def delete_report(idr):
    report = find_report(idr)
    if report is None:
        return jsonify({"error": f"Report {idr} not found"}), 404
    if report["IDs"] != g.IDs:
        return jsonify({"error": "Only the owner can delete this report"}), 403

    remove_report_file(report)
    reports.remove(report)
    access_requests[:] = [q for q in access_requests if q["IDr"] != idr]
    save_data()
    return jsonify({"message": f"Report {idr} deleted"}), 200


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