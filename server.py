import json
import mimetypes
import threading
import uuid
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# =========================
# CONFIG
# =========================
BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "saptha_db.json"
DB_LOCK = threading.RLock()

HOST = "127.0.0.1"
PORT = 8000

BRANCH_NAMES = {
    "CSE": "Computer Science & Engineering",
}

COORDINATORS = {
    "24SUUBECS0001": {"password": "coord123", "role": "course_coordinator", "name": "Course Coordinator"},
    "24SUUBECS0002": {"password": "coord123", "role": "director", "name": "Director"},
}

ALLOWED_COLLECTIONS = {
    "announcements",
    "activity_announcements",
    "events",
    "placements",
    "sports",
    "hrd_programs",
    "hostel_announcements",
    "hostel_info",
    "canteen_info",
    "library",
    "subjects",
    "modules",
    "module_files",
}

# =========================
# DATABASE HELPERS
# =========================
def now_iso():
    return datetime.now(timezone.utc).isoformat()


def empty_db():
    return {
        "users": {},
        "sessions": {},
        "contacts": [],
        "content": {name: [] for name in ALLOWED_COLLECTIONS},
    }


def write_db(data):
    with DB_LOCK:
        tmp = DB_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(DB_FILE)


def read_db():
    with DB_LOCK:
        if not DB_FILE.exists() or DB_FILE.stat().st_size == 0:
            data = empty_db()
            write_db(data)
            return data

        try:
            data = json.loads(DB_FILE.read_text(encoding="utf-8-sig"))
        except Exception:
            data = empty_db()
            write_db(data)

        data.setdefault("users", {})
        data.setdefault("sessions", {})
        data.setdefault("contacts", [])
        data.setdefault("content", {})

        for c in ALLOWED_COLLECTIONS:
            data["content"].setdefault(c, [])

        return data


def seed():
    data = read_db()
    for srn, d in COORDINATORS.items():
        user = data["users"].setdefault(srn, {"srn": srn, "created_at": now_iso()})
        user.update(d)
    write_db(data)


def parse_batch(srn):
    srn = srn.upper()
    if len(srn) >= 2 and srn[:2].isdigit():
        return "20" + srn[:2]
    return "2024"


def parse_branch(srn):
    srn = srn.upper()
    if "CS" in srn:
        return {"code": "CSE", "name": BRANCH_NAMES["CSE"]}
    return None


# =========================
# HTTP HANDLER
# =========================
class Handler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    # -------- CORS --------
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    # -------- ROUTING --------
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            return self.handle_api("GET", parsed)

        if parsed.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        return self.handle_api("POST", parsed)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        return self.handle_api("DELETE", parsed)

    # -------- HELPERS --------
    def send_json(self, status, data):
        raw = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.end_headers()
        self.wfile.write(raw)

    def read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode())

    def fail(self, code, msg):
        return self.send_json(code, {"detail": msg})

    # -------- AUTH --------
    def auth_user(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None

        token = auth.split(" ", 1)[1].strip()
        db = read_db()
        return db["sessions"].get(token)

    def require_user(self):
        u = self.auth_user()
        if not u:
            self.fail(401, "Unauthorized")
            return None
        return u

    # -------- API ROUTER --------
    def handle_api(self, method, parsed):
        try:
            path = parsed.path.rstrip("/")

            if path == "/api/health":
                return self.send_json(200, {"ok": True})

            if path == "/api/auth/login" and method == "POST":
                return self.login()

            if path == "/api/contact" and method == "POST":
                return self.contact()

            if path.startswith("/api/content/"):
                tail = path[len("/api/content/"):].split("/")
                tail = [t for t in tail if t]
                return self.content(method, tail, parsed)

            return self.fail(404, "API not found")

        except Exception as e:
            import traceback
            traceback.print_exc()
            return self.fail(500, str(e))

    # -------- LOGIN --------
    def login(self):
        data = read_db()
        body = self.read_json()

        srn = body.get("srn", "").upper()
        password = body.get("password", "")
        role = body.get("role", "student")

        branch = parse_branch(srn)
        if not branch:
            return self.fail(400, "Invalid SRN")

        user = data["users"].get(srn)

        if role != "student":
            if not user or user.get("password") != password:
                return self.fail(401, "Invalid login")

        if not user:
            user = {"srn": srn, "role": "student"}
            data["users"][srn] = user

        batch = parse_batch(srn)
        user.update({"batch": batch})

        token = str(uuid.uuid4())

        session = {
            "token": token,
            "srn": srn,
            "role": role,
            "branch": branch["code"],
            "batch": batch,
            "name": user.get("name", srn),
        }

        data["sessions"][token] = session
        write_db(data)

        return self.send_json(200, session)

    # -------- CONTENT API --------
    def content(self, method, tail, parsed):
        if not tail:
            return self.fail(404, "Missing collection")

        collection = tail[0]
        item_id = tail[1] if len(tail) > 1 else None

        if collection not in ALLOWED_COLLECTIONS:
            return self.fail(404, "Invalid collection")

        user = self.require_user()
        if not user:
            return

        data = read_db()

        # GET
        if method == "GET":
            items = data["content"][collection]
            scope = parse_qs(parsed.query).get("scope", [""])[0]
            batch = parse_qs(parsed.query).get("batch", [""])[0]

            def item_scope(item):
                if not isinstance(item, dict):
                    return None
                if item.get("data") and isinstance(item["data"], dict):
                    return item["data"].get("scope")
                return item.get("scope")
            def item_batch(item):
                if not isinstance(item, dict):
                    return None
                if item.get("data") and isinstance(item["data"], dict):
                    return item["data"].get("batch") or "2024"
                return item.get("batch") or "2024"

            if scope:
                items = [
                    i for i in items
                    if item_scope(i) == scope
                ]

            if batch:
                items = [
                    i for i in items
                    if item_batch(i) == batch
                ]

            return self.send_json(200, items)

        # POST
        if method == "POST":
            body = self.read_json()
            payload = body
            if "data" in body and isinstance(body["data"], dict) and len(body) == 1:
                payload = body["data"]
                
            if isinstance(payload, dict) and not payload.get("batch"):
                payload["batch"] = user.get("batch", "2024")

            new_item = {
                "id": str(uuid.uuid4()),
                "created_at": now_iso(),
                "data": payload,
            }

            data["content"][collection].append(new_item)
            write_db(data)
            return self.send_json(200, new_item)

        # DELETE
        if method == "DELETE":
            if not item_id:
                return self.fail(400, "Missing item ID")

            items = data["content"][collection]

            new_items = [
                i for i in items
                if isinstance(i, dict) and i.get("id") != item_id
            ]

            if len(new_items) == len(items):
                return self.fail(404, "Item not found")

            data["content"][collection] = new_items
            write_db(data)
            return self.send_json(200, {"deleted": item_id})

        return self.fail(405, "Method not allowed")

    # -------- CONTACT --------
    def contact(self):
        return self.send_json(200, {"ok": True})


# =========================
# START SERVER
# =========================
if __name__ == "__main__":
    mimetypes.add_type("text/javascript", ".js")
    seed()
    print(f"Running at http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()