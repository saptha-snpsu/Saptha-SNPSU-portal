import json
import io
import base64
import hashlib
import hmac
import logging
import mimetypes
import os
import re
import ssl
import tempfile
import threading
import time
import uuid
from email.parser import BytesParser
from email.policy import default
from datetime import datetime, timezone
from hmac import compare_digest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse
from urllib.request import Request, urlopen

import firebase_admin
from firebase_admin import credentials as firebase_credentials
from firebase_admin import db as firebase_db

# =========================
# CONFIG
# =========================
BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "saptha_db.json"
DB_LOCK = threading.RLock()

try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=BASE_DIR / ".env")
except ImportError:
    pass

HOST = os.getenv("SAPTHA_HOST", "127.0.0.1")
PORT = int(os.getenv("SAPTHA_PORT", "8000"))
ENVIRONMENT = os.getenv("SAPTHA_ENVIRONMENT", "development").strip().lower()
FIREBASE_DATABASE_URL = os.getenv(
    "SAPTHA_FIREBASE_DATABASE_URL",
    "https://saptha-college-default-rtdb.firebaseio.com",
).rstrip("/")

FIREBASE_SERVICE_ACCOUNT_FILE = Path(
    os.getenv(
        "SAPTHA_FIREBASE_SERVICE_ACCOUNT_FILE",
        "~/.config/saptha/firebase/service-account.json",
    )
).expanduser()

MAX_DRIVE_UPLOAD_BYTES = 50 * 1024 * 1024
DRIVE_FOLDER_MIME_TYPE = "application/vnd.google-apps.folder"
EXPECTED_DRIVE_OWNER = "saptha.snpsu@gmail.com"
APPROVED_DRIVE_PRINCIPALS = frozenset({EXPECTED_DRIVE_OWNER})
DRIVE_CACHE_LOCK = threading.Lock()
DRIVE_CACHE = {}
DRIVE_CACHE_KEY_LOCKS = {}
DIRECT_DRIVE_URL_PATTERN = re.compile(
    r"https?://(?:drive|docs)\.google(?:usercontent)?\.com/[^\s\"'<>]+",
    re.IGNORECASE,
)

BRANCH_NAMES = {
    "CSE": "Computer Science & Engineering",
}

COORDINATORS = {
}

LOCAL_TRUSTED_ORIGINS = {
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "https://sapthasnpsuportal.vercel.app",
    "https://saptha-snpsu-portal.vercel.app",
}


def normalize_origin(value):
    origin = str(value or "").strip()
    parsed = urlparse(origin)
    if (
        not origin
        or parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Origins must contain only an http(s) scheme, host, and optional port.")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Origin contains an invalid port.") from None
    hostname = parsed.hostname.lower()
    if "*" in hostname:
        raise ValueError("Wildcard hosts are not allowed in SAPTHA_TRUSTED_ORIGINS.")
    if ":" in hostname:
        hostname = f"[{hostname}]"
    if port and not (
        parsed.scheme.lower() == "http" and port == 80
        or parsed.scheme.lower() == "https" and port == 443
    ):
        hostname = f"{hostname}:{port}"
    return f"{parsed.scheme.lower()}://{hostname}"


def trusted_origins_from_environment():
    configured = os.getenv("SAPTHA_TRUSTED_ORIGINS", "").strip()
    if not configured:
        return set(LOCAL_TRUSTED_ORIGINS)
    origins = [origin.strip() for origin in configured.split(",")]
    if not origins or any(not origin for origin in origins) or "*" in origins:
        raise ValueError("SAPTHA_TRUSTED_ORIGINS must be a comma-separated origin allowlist; '*' is not allowed.")
    return {normalize_origin(origin) for origin in origins}


TRUSTED_ORIGINS = trusted_origins_from_environment()


def audit_drive_resource_acl(
    service, resource_id, approved_principals=None, require_approved_principal=False
):
    approved = {
        str(principal).strip().lower()
        for principal in (
            APPROVED_DRIVE_PRINCIPALS
            if approved_principals is None
            else approved_principals
        )
    }
    permissions = service.permissions()
    page_token = None
    unauthorized = []
    approved_principal_found = False
    while True:
        result = permissions.list(
            fileId=resource_id,
            pageSize=100,
            pageToken=page_token,
            fields="nextPageToken,permissions(id,type,emailAddress,domain,role,deleted)",
            supportsAllDrives=True,
        ).execute()
        for permission in result.get("permissions", []):
            if permission.get("deleted"):
                continue
            principal_type = str(permission.get("type") or "unknown").lower()
            principal_email = str(permission.get("emailAddress") or "").strip().lower()
            if principal_type == "user" and principal_email in approved:
                approved_principal_found = True
            else:
                unauthorized.append(
                    {
                        "id": permission.get("id"),
                        "type": principal_type,
                        "emailAddress": principal_email,
                        "domain": permission.get("domain"),
                        "role": permission.get("role"),
                    }
                )

        page_token = result.get("nextPageToken")
        if not page_token:
            break
    if require_approved_principal and not approved_principal_found:
        unauthorized.append(
            {
                "id": None,
                "type": "missing-approved-principal",
                "emailAddress": "",
                "domain": None,
                "role": None,
            }
        )
    return unauthorized


def verify_drive_resource_is_private(service, resource_id):
    unauthorized = audit_drive_resource_acl(
        service, resource_id, require_approved_principal=True
    )
    if unauthorized:
        principals = ", ".join(
            f"{item['type']}:{item['emailAddress'] or item['domain'] or 'unknown'}"
            for item in unauthorized
        )
        raise RuntimeError(
            f"Drive resource {resource_id} has unauthorized permissions: {principals}"
        )
    return True


def validate_production_configuration():
    environment = os.getenv("SAPTHA_ENVIRONMENT", "development").strip().lower()
    if environment not in {"development", "production"}:
        raise RuntimeError("SAPTHA_ENVIRONMENT must be either 'development' or 'production'.")
    if environment != "production":
        return
    configured = os.getenv("SAPTHA_TRUSTED_ORIGINS", "").strip()
    if not configured:
        raise RuntimeError(
            "SAPTHA_TRUSTED_ORIGINS is required in production. "
            "Set it to the comma-separated list of approved HTTPS portal origins."
        )
    origins = trusted_origins_from_environment()
    if any(not origin.startswith("https://") for origin in origins):
        raise RuntimeError("Production SAPTHA_TRUSTED_ORIGINS entries must use HTTPS.")
    if any(urlparse(origin).hostname in {"localhost", "127.0.0.1", "::1"} for origin in origins):
        raise RuntimeError("Production SAPTHA_TRUSTED_ORIGINS must not include localhost origins.")
    if not os.getenv("GOOGLE_DRIVE_ROOT_FOLDER_ID", "").strip():
        raise RuntimeError("GOOGLE_DRIVE_ROOT_FOLDER_ID is required in production.")
    if not FIREBASE_SERVICE_ACCOUNT_FILE.is_file():
        raise RuntimeError(
            "Firebase service-account JSON was not found at "
            f"{FIREBASE_SERVICE_ACCOUNT_FILE}. Set SAPTHA_FIREBASE_SERVICE_ACCOUNT_FILE."
        )

CONTENT_WRITE_ROLES = {
    "announcements": {"admin", "director"},
    "activity_announcements": {"admin", "dsa_coordinator"},
    "events": {"admin", "events_coordinator"},
    "placements": {"admin", "placement_coordinator"},
    "sports": {"admin", "sports_coordinator"},
    "hrd_programs": {"admin", "hrd_coordinator"},
    "hostel_announcements": {"admin", "hostel_coordinator"},
    "hostel_info": {"admin", "hostel_coordinator"},
    "canteen_info": {"admin", "canteen_coordinator"},
    "library": {"admin", "library_coordinator"},
    "contacts_list": {"admin"},
    "course_notes": {"admin", "course_coordinator"},
}

CONTENT_ADMIN_ONLY = {"pending_admins"}
ACADEMIC_COLLECTIONS = {"subjects", "modules", "module_files"}

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
    "contacts_list",
    "pending_admins",
    "course_notes",
}
PUBLIC_STATIC_EXTENSIONS = {
    ".css",
    ".html",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".png",
    ".svg",
    ".webp",
    ".woff",
    ".woff2",
}

# =========================
# DATABASE HELPERS
# =========================
def now_iso():
    return datetime.now(timezone.utc).isoformat()


def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        str(password).encode("utf-8"),
        salt=salt,
        n=2 ** 14,
        r=8,
        p=1,
        dklen=64,
    )
    return "scrypt$16384$8$1${}${}".format(
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password, password_hash):
    if not password_hash:
        return False
    try:
        algorithm, n, r, p, salt, digest = str(password_hash).split("$", 5)
        if algorithm != "scrypt":
            return False
        expected = base64.b64decode(digest.encode("ascii"))
        actual = hashlib.scrypt(
            str(password).encode("utf-8"),
            salt=base64.b64decode(salt.encode("ascii")),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
        return compare_digest(actual, expected)
    except Exception:
        return False


def migrate_legacy_password_record(record):
    if not isinstance(record, dict) or "password" not in record:
        return dict(record) if isinstance(record, dict) else {}, False

    legacy_password = record.get("password")
    if legacy_password is None:
        legacy_password = ""
    if not isinstance(legacy_password, str):
        raise ValueError("Legacy password field must be a string or null.")

    migrated = dict(record)
    password_hash = migrated.get("password_hash")
    if password_hash:
        if not verify_password(legacy_password, password_hash):
            raise ValueError("Legacy password does not match the existing password hash.")
    else:
        password_hash = hash_password(legacy_password)
    if not verify_password(legacy_password, password_hash):
        raise ValueError("Could not verify the migrated password hash.")

    migrated["password_hash"] = password_hash
    migrated.pop("password", None)
    return migrated, True


def migrate_pending_admin_credential(record):
    if not isinstance(record, dict) or "password" not in record:
        return dict(record) if isinstance(record, dict) else record

    legacy_password = record.get("password")
    if legacy_password is not None and not isinstance(legacy_password, str):
        raise ValueError("Pending admin password field must be a string or null.")
    if legacy_password:
        migrated, _ = migrate_legacy_password_record(record)
        return migrated

    migrated = dict(record)
    migrated.pop("password", None)
    return migrated


def migrate_pending_admin_credentials(records):
    for key, record in firebase_record_items(records):
        if not isinstance(record, dict) or "password" not in record:
            continue
        reference = firebase_db.reference(
            f"pending_admins/{quote(str(key), safe='')}"
        )
        reference.transaction(migrate_pending_admin_credential)


def sanitize_api_response(value):
    if isinstance(value, dict):
        return {
            key: sanitize_api_response(item)
            for key, item in value.items()
            if "password" not in str(key).casefold().replace("_", "").replace("-", "")
        }
    if isinstance(value, list):
        return [sanitize_api_response(item) for item in value]
    if isinstance(value, str):
        return DIRECT_DRIVE_URL_PATTERN.sub("", value)
    return value


def strip_sensitive_fields(record):
    return sanitize_api_response(record)


def authenticate_password_record(record, password):
    if not isinstance(record, dict):
        return False, False
    if record.get("password_hash"):
        return verify_password(password, record.get("password_hash")), False
    if record.get("password") is not None:
        return compare_digest(str(record.get("password", "")), str(password)), True
    return False, False


def apply_password_payload(payload):
    password = str(payload.pop("password", "") or "")
    payload.pop("password_hash", None)
    if password:
        payload["password_hash"] = hash_password(password)
    return payload


_DB_CACHE = None
_DB_CACHE_MTIME = None
_DB_CACHE_FILE = None


def empty_db():
    return {
        "users": {},
        "sessions": {},
        "contacts": [],
        "content": {name: [] for name in ALLOWED_COLLECTIONS},
    }


def write_db(data):
    global _DB_CACHE, _DB_CACHE_MTIME, _DB_CACHE_FILE
    with DB_LOCK:
        _DB_CACHE = data
        _DB_CACHE_FILE = DB_FILE
        try:
            tmp = DB_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(DB_FILE)
            _DB_CACHE_MTIME = DB_FILE.stat().st_mtime
        except OSError:
            pass


SESSION_SECRET = os.getenv(
    "SAPTHA_SESSION_SECRET",
    "saptha_secret_portal_key_snpsu_2026_default",
)


def create_session_token(session_dict):
    payload = json.dumps(session_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(SESSION_SECRET.encode("utf-8"), payload, hashlib.sha256).digest()
    p_b64 = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    s_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    return f"stk.{p_b64}.{s_b64}"


def decode_session_token(token_str):
    if not isinstance(token_str, str) or not token_str.startswith("stk."):
        return None
    parts = token_str.split(".")
    if len(parts) != 3:
        return None
    _, p_b64, s_b64 = parts
    try:
        p_pad = p_b64 + "=" * (-len(p_b64) % 4)
        s_pad = s_b64 + "=" * (-len(s_b64) % 4)
        payload = base64.urlsafe_b64decode(p_pad.encode("ascii"))
        expected_sig = base64.urlsafe_b64decode(s_pad.encode("ascii"))
        actual_sig = hmac.new(SESSION_SECRET.encode("utf-8"), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(actual_sig, expected_sig):
            return None
        parsed = json.loads(payload.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def invalidate_user_sessions(srn):
    data = read_db()
    stale_tokens = [
        token
        for token, session in data.get("sessions", {}).items()
        if session.get("srn") == srn
    ]
    if stale_tokens:
        for token in stale_tokens:
            data.get("sessions", {}).pop(token, None)
        write_db(data)
    try:
        remote_sessions = firebase_read("sessions") or {}
        for key, record in firebase_record_items(remote_sessions):
            if isinstance(record, dict) and record.get("srn") == srn:
                firebase_delete(f"sessions/{quote(str(key), safe='')}")
    except Exception:
        pass




def is_public_static_path(request_path):
    static_path = (BASE_DIR / request_path.lstrip("/")).resolve()
    return (
        BASE_DIR in static_path.parents
        and static_path.suffix.lower() in PUBLIC_STATIC_EXTENSIONS
        and not any(
            part.startswith(".")
            for part in static_path.relative_to(BASE_DIR).parts
        )
    )


def read_db():
    global _DB_CACHE, _DB_CACHE_MTIME, _DB_CACHE_FILE
    with DB_LOCK:
        try:
            mtime = DB_FILE.stat().st_mtime if DB_FILE.exists() else None
        except OSError:
            mtime = None

        if (
            _DB_CACHE is not None
            and _DB_CACHE_FILE == DB_FILE
            and mtime == _DB_CACHE_MTIME
        ):
            return _DB_CACHE

        if not DB_FILE.exists() or (DB_FILE.is_file() and DB_FILE.stat().st_size == 0):
            data = empty_db()
            write_db(data)
            _DB_CACHE = data
            _DB_CACHE_FILE = DB_FILE
            _DB_CACHE_MTIME = None
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

        _DB_CACHE = data
        _DB_CACHE_FILE = DB_FILE
        _DB_CACHE_MTIME = mtime
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


def get_firebase_admin_app():
    if firebase_admin._apps:
        return firebase_admin.get_app()

    sa_json = os.getenv("SAPTHA_FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
    if sa_json:
        try:
            cert_dict = json.loads(sa_json)
            cred = firebase_credentials.Certificate(cert_dict)
            return firebase_admin.initialize_app(
                cred,
                {
                    "databaseURL": FIREBASE_DATABASE_URL,
                },
            )
        except Exception as err:
            logging.warning("Failed to initialize Firebase from service account JSON string: %s", err)

    if not FIREBASE_SERVICE_ACCOUNT_FILE.exists():
        raise RuntimeError(
            f"Firebase service account file not found: "
            f"{FIREBASE_SERVICE_ACCOUNT_FILE}"
        )

    cred = firebase_credentials.Certificate(
        str(FIREBASE_SERVICE_ACCOUNT_FILE)
    )

    return firebase_admin.initialize_app(
        cred,
        {
            "databaseURL": FIREBASE_DATABASE_URL,
        },
    )


def firebase_read(path):
    try:
        get_firebase_admin_app()
        return firebase_db.reference(path).get()
    except Exception as error:
        if ENVIRONMENT == "production":
            raise
        data = read_db()
        parts = [unquote(p) for p in path.strip("/").split("/") if p]
        if not parts:
            return data
        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current


def firebase_write(path, value):
    try:
        get_firebase_admin_app()
        reference = firebase_db.reference(path)
        reference.set(value)
    except Exception as error:
        if ENVIRONMENT == "production":
            raise
        data = read_db()
        parts = [unquote(p) for p in path.strip("/").split("/") if p]
        if not parts:
            return
        current = data
        for part in parts[:-1]:
            if isinstance(current, dict):
                current = current.setdefault(part, {})
        if isinstance(current, dict):
            current[parts[-1]] = value
        write_db(data)


def firebase_delete(path):
    try:
        get_firebase_admin_app()
        reference = firebase_db.reference(path)
        reference.delete()
    except Exception as error:
        if ENVIRONMENT == "production":
            raise
        data = read_db()
        parts = [unquote(p) for p in path.strip("/").split("/") if p]
        if not parts:
            return
        current = data
        for part in parts[:-1]:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return
        if isinstance(current, dict):
            current.pop(parts[-1], None)
        write_db(data)



def trusted_urlopen(request, timeout):
    try:
        import certifi
    except ImportError:
        return urlopen(request, timeout=timeout)
    context = ssl.create_default_context(cafile=certifi.where())
    return urlopen(request, timeout=timeout, context=context)


def record_data(record):
    if isinstance(record, dict) and isinstance(record.get("data"), dict):
        return record["data"]
    return record if isinstance(record, dict) else {}


def firebase_record_items(records):
    if isinstance(records, dict):
        return records.items()
    if isinstance(records, list):
        return enumerate(records)
    return []


def firebase_find_record(collection, record_id):
    record = firebase_read(f"{collection}/{quote(str(record_id), safe='')}")
    if record is not None:
        return record
    records = firebase_read(collection)
    for key, candidate in firebase_record_items(records):
        candidate_data = record_data(candidate)
        candidate_id = candidate.get("id") if isinstance(candidate, dict) else None
        if (
            str(key) == str(record_id)
            or candidate_id == record_id
            or candidate_data.get("id") == record_id
        ):
            return candidate
    return None


def find_firebase_record(collection, predicate):
    records = firebase_read(collection) or {}
    for key, record in firebase_record_items(records):
        if predicate(record_data(record)):
            return str(key), record
    return None, None


def verify_course_coordinator(srn, password):
    srn = str(srn or "").strip().upper()
    password = str(password or "")
    if not re.fullmatch(r"[0-9A-Z]+", srn) or not password:
        return False
    account = firebase_read(f"users/{quote(srn, safe='')}")
    valid, legacy = authenticate_password_record(account, password)
    if valid and legacy:
        migrated = dict(account)
        migrated["password_hash"] = hash_password(password)
        migrated.pop("password", None)
        firebase_write(f"users/{quote(srn, safe='')}", migrated)
    return isinstance(account, dict) and account.get("role") == "course_coordinator" and valid


def hierarchy_record_parts(record):
    return dict(record) if isinstance(record, dict) else {}, record_data(record)


def save_hierarchy_record(collection, key, record, fields):
    wrapper, details = hierarchy_record_parts(record)
    details.update(fields)
    if isinstance(wrapper.get("data"), dict):
        wrapper["data"] = details
        saved = wrapper
    else:
        saved = {**wrapper, **details}
    firebase_write(f"{collection}/{quote(str(key), safe='')}", saved)
    return saved


def semester_from_record(record):
    details = record_data(record)
    try:
        semester = int(details.get("sem"))
    except (TypeError, ValueError):
        scope_match = re.match(r"^[A-Z]+_(\d+)(?:_|$)", str(details.get("scope", "")))
        semester = int(scope_match.group(1)) if scope_match else 0
    if not 1 <= semester <= 8:
        raise ValueError("The selected subject or module has an invalid semester.")
    return semester


def record_has_semester(record, semester):
    try:
        return semester_from_record(record) == semester
    except ValueError:
        return False


def create_hierarchy_record(kind, payload):
    if not isinstance(payload, dict):
        raise ValueError("Invalid hierarchy record.")
    if kind not in ("subject", "module"):
        raise ValueError("Unknown hierarchy record type.")

    batch = str(payload.get("batch") or "2024").strip()
    branch = str(payload.get("branch") or "CSE").strip().upper()
    if branch != "CSE":
        raise ValueError("Only the existing CSE subject structure is supported.")
    try:
        semester = int(payload.get("sem"))
    except (TypeError, ValueError):
        raise ValueError("Select a valid semester.") from None
    if not 1 <= semester <= 8:
        raise ValueError("Select a valid semester.")

    root_folder_id = os.getenv("GOOGLE_DRIVE_ROOT_FOLDER_ID", "").strip()
    service = None
    year_id = ""
    if root_folder_id:
        try:
            service = get_drive_service()
            if ENVIRONMENT == "production":
                verify_drive_resource_is_private(service, root_folder_id)
            year_name = year_folder_name(semester)
            year_id = ensure_drive_folder(service, year_name, root_folder_id)
        except Exception as drive_err:
            logging.warning("Google Drive integration unavailable: %s", drive_err)
            service = None

    normalized_batch = batch.lower()

    if kind == "subject":
        name = str(payload.get("name") or "").strip()
        if not name or len(name) > 80:
            raise ValueError("Subject name is required and must be 80 characters or fewer.")
        scope = f"{branch}_{semester}"
        key, existing = find_firebase_record(
            "subjects",
            lambda details: (
                str(details.get("name", "")).strip().casefold() == name.casefold()
                and record_has_semester(details, semester)
                and str(details.get("branch") or "CSE").upper() == branch
                and str(details.get("batch") or "2024").lower() == normalized_batch
            ),
        )
        subject_id = (
            str(existing.get("id") or key) if existing is not None else uuid.uuid4().hex
        )
        details = record_data(existing)
        subject_folder_id = details.get("driveFolderId") or ""
        if service and year_id:
            try:
                subject_folder_id = drive_folder_id_under_parent(
                    service, details.get("driveFolderId"), year_id
                )
                if not subject_folder_id:
                    subject_folder_id = ensure_drive_folder(
                        service, str(details.get("name") or name), year_id
                    )
            except Exception as drive_folder_err:
                logging.warning("Could not sync subject folder with Drive: %s", drive_folder_err)
        saved_fields = {
            "name": str(details.get("name") or name),
            "desc": str(details.get("desc") or str(payload.get("desc") or "").strip()),
            "branch": branch,
            "sem": str(semester),
            "scope": scope,
            "batch": str(details.get("batch") or batch),
            "driveYearFolderId": year_id or details.get("driveYearFolderId", ""),
            "driveFolderId": subject_folder_id,
        }
        if existing is None:
            saved = {
                "id": subject_id,
                "created_at": now_iso(),
                "data": saved_fields,
            }
            firebase_write(f"subjects/{subject_id}", saved)
        else:
            saved = save_hierarchy_record("subjects", key, existing, saved_fields)
        return {"record": saved, "created": existing is None}

    if kind == "module":
        subject_id = str(payload.get("subjectId") or "").strip()
        title = str(payload.get("title") or "").strip()
        description = str(payload.get("desc") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", subject_id):
            raise ValueError("Select an existing subject.")
        if not title or len(title) > 80:
            raise ValueError("Module title is required and must be 80 characters or fewer.")
        subject_key, subject_record = find_firebase_record(
            "subjects",
            lambda details: str(details.get("id") or "") == subject_id,
        )
        if subject_record is None:
            subject_record = firebase_find_record("subjects", subject_id)
            subject_key = subject_id if subject_record is not None else None
        if subject_record is None:
            raise ValueError("The selected subject was not found in Firebase.")
        subject = record_data(subject_record)
        subject_semester = semester_from_record(subject)
        if subject_semester != semester:
            raise ValueError("The selected subject does not belong to this semester.")
        subject_batch = str(subject.get("batch") or "2024").strip().lower()
        if subject_batch != normalized_batch:
            raise ValueError("The selected subject does not belong to this batch.")
        subject_name = str(subject.get("name") or "").strip()
        if not subject_name:
            raise ValueError("The selected subject has no name.")
        subject_scope = str(subject.get("scope") or f"{branch}_{semester}")
        if str(subject.get("branch") or "CSE").upper() != branch:
            raise ValueError("The selected subject does not belong to this branch.")

        subject_folder_id = subject.get("driveFolderId") or ""
        if service and year_id:
            try:
                subject_folder_id = drive_folder_id_under_parent(
                    service, subject.get("driveFolderId"), year_id
                )
                if not subject_folder_id:
                    subject_folder_id = ensure_drive_folder(service, subject_name, year_id)
            except Exception as drive_sub_err:
                logging.warning("Could not sync subject folder in Drive: %s", drive_sub_err)

        scope = f"{branch}_{semester}_{subject_name}"
        module_key, existing = find_firebase_record(
            "modules",
            lambda details: (
                str(details.get("title", "")).strip().casefold() == title.casefold()
                and str(details.get("subjectId") or "") == subject_id
                and str(details.get("batch") or "2024").lower() == normalized_batch
            ) or (
                str(details.get("title", "")).strip().casefold() == title.casefold()
                and not details.get("subjectId")
                and str(details.get("subject", "")).strip().casefold() == subject_name.casefold()
                and str(details.get("scope") or "") == scope
                and str(details.get("batch") or "2024").lower() == normalized_batch
            ),
        )
        module_id = (
            str(existing.get("id") or module_key)
            if existing is not None else uuid.uuid4().hex
        )
        module_details = record_data(existing)
        module_folder_id = module_details.get("driveFolderId") or ""
        if service and subject_folder_id:
            try:
                module_folder_id = drive_folder_id_under_parent(
                    service, module_details.get("driveFolderId"), subject_folder_id
                )
                if not module_folder_id:
                    module_folder_id = ensure_drive_folder(
                        service, str(module_details.get("title") or title), subject_folder_id
                    )
            except Exception as drive_mod_err:
                logging.warning("Could not sync module folder in Drive: %s", drive_mod_err)

        saved_fields = {
            "title": str(module_details.get("title") or title),
            "desc": str(module_details.get("desc") or description),
            "subject": subject_name,
            "subjectId": subject_id,
            "sem": str(subject_semester),
            "branch": branch,
            "scope": subject_scope if subject_scope.endswith(subject_name) else scope,
            "batch": str(module_details.get("batch") or batch),
            "driveYearFolderId": year_id,
            "driveSubjectFolderId": subject_folder_id,
            "driveFolderId": module_folder_id,
        }
        if existing is None:
            saved = {
                "id": module_id,
                "created_at": now_iso(),
                "data": saved_fields,
            }
            firebase_write(f"modules/{module_id}", saved)
        else:
            saved = save_hierarchy_record("modules", module_key, existing, saved_fields)
        return {"record": saved, "created": existing is None}

    raise ValueError("Unknown hierarchy record type.")


def parse_multipart(content_type, raw_body):
    headers = (
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii")
    )
    message = BytesParser(policy=default).parsebytes(headers + raw_body)
    if not message.is_multipart():
        raise ValueError("Expected a multipart file upload.")

    fields = {}
    uploaded_file = None
    for part in message.iter_parts():
        if part.get_content_disposition() != "form-data":
            continue
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        value = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        if filename is not None:
            uploaded_file = {"name": filename, "content": value}
        else:
            charset = part.get_content_charset() or "utf-8"
            fields[name] = value.decode(charset, errors="replace")
    return fields, uploaded_file


def get_drive_service():
    try:
        from google.auth import default as get_default_credentials
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build
    except ImportError as error:
        raise RuntimeError("Install the server dependencies with pip install -r requirements.txt.") from error

    scopes = ["https://www.googleapis.com/auth/drive"]
    client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
    client_secret = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
    refresh_token = os.getenv("GOOGLE_OAUTH_REFRESH_TOKEN", "").strip()
    oauth_values = (client_id, client_secret, refresh_token)
    if any(oauth_values) and not all(oauth_values):
        raise RuntimeError("Set all three server-side Google OAuth environment variables.")
    if all(oauth_values):
        credentials = Credentials(
            token=None,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
        )
    else:
        credentials, _ = get_default_credentials(scopes=scopes)
    return build("drive", "v3", credentials=credentials, cache_discovery=False)


def ensure_drive_folder(service, name, parent_id):
    cache_key = ("folder", parent_id, name)
    with DRIVE_CACHE_LOCK:
        key_lock = DRIVE_CACHE_KEY_LOCKS.setdefault(cache_key, threading.Lock())
    with key_lock:
        with DRIVE_CACHE_LOCK:
            entry = DRIVE_CACHE.get(cache_key)
            if entry and entry[0] > time.monotonic() and entry[1]:
                return entry[1]
        folder_id = find_drive_folder(service, name, parent_id)
        if not folder_id:
            folder = service.files().create(
                body={
                    "name": name,
                    "mimeType": DRIVE_FOLDER_MIME_TYPE,
                    "parents": [parent_id],
                },
                fields="id",
                supportsAllDrives=True,
            ).execute()
            folder_id = folder["id"]
        with DRIVE_CACHE_LOCK:
            DRIVE_CACHE[cache_key] = (time.monotonic() + 6 * 60 * 60, folder_id)
        return folder_id


def cached_drive_value(key, ttl, loader):
    with DRIVE_CACHE_LOCK:
        entry = DRIVE_CACHE.get(key)
        if entry and entry[0] > time.monotonic():
            return entry[1]
        key_lock = DRIVE_CACHE_KEY_LOCKS.setdefault(key, threading.Lock())

    with key_lock:
        with DRIVE_CACHE_LOCK:
            entry = DRIVE_CACHE.get(key)
            if entry and entry[0] > time.monotonic():
                return entry[1]
        value = loader()
        with DRIVE_CACHE_LOCK:
            DRIVE_CACHE[key] = (time.monotonic() + ttl, value)
        return value


def find_drive_folder(service, name, parent_id):
    escaped_name = name.replace("\\", "\\\\").replace("'", "\\'")
    query = (
        f"name = '{escaped_name}' and mimeType = '{DRIVE_FOLDER_MIME_TYPE}' "
        f"and '{parent_id}' in parents and trashed = false"
    )
    response = service.files().list(
        q=query,
        pageSize=100,
        fields="files(id,name)",
        supportsAllDrives=True,
        includeItemsFromAllDrives=True,
    ).execute()
    folders = response.get("files", [])
    return folders[0]["id"] if folders else None


def year_folder_name(semester):
    year = (semester + 1) // 2
    suffix = "st" if year == 1 else "nd" if year == 2 else "rd" if year == 3 else "th"
    return f"{year}{suffix} Year Engineering"


def drive_proxy_url(file_id, module_id):
    return (
        f"/api/drive/files/{quote(str(file_id), safe='')}"
        f"?moduleId={quote(str(module_id), safe='')}"
    )


def drive_folder_id_under_parent(service, folder_id, parent_id):
    if not folder_id:
        return None
    folder = service.files().get(
        fileId=folder_id,
        fields="id,mimeType,parents",
        supportsAllDrives=True,
    ).execute()
    if (
        folder.get("mimeType") == DRIVE_FOLDER_MIME_TYPE
        and parent_id in folder.get("parents", [])
    ):
        return folder["id"]
    return None


def resolve_upload_module_folder(service, module_id, module, semester):
    root_folder_id = os.getenv("GOOGLE_DRIVE_ROOT_FOLDER_ID", "").strip()
    if not root_folder_id:
        raise RuntimeError("Google Drive is not configured on the server.")
    year_id = ensure_drive_folder(service, year_folder_name(semester), root_folder_id)

    subject_id = str(module.get("subjectId") or "").strip()
    subject_record = firebase_find_record("subjects", subject_id) if subject_id else None
    if subject_record is None:
        subject_key, subject_record = find_firebase_record(
            "subjects",
            lambda details: (
                str(details.get("name", "")).strip() == str(module.get("subject", "")).strip()
                and record_has_semester(details, semester)
            ),
        )
        subject_id = str(record_data(subject_record).get("id") or subject_key or "")
    subject = record_data(subject_record)
    subject_name = str(subject.get("name") or module.get("subject") or "").strip()
    if not subject_name:
        raise ValueError("The selected module has no valid subject.")

    subject_folder_id = drive_folder_id_under_parent(
        service, module.get("driveSubjectFolderId"), year_id
    )
    if not subject_folder_id:
        subject_folder_id = ensure_drive_folder(service, subject_name, year_id)
    module_folder_id = drive_folder_id_under_parent(
        service, module.get("driveFolderId"), subject_folder_id
    )
    if not module_folder_id:
        module_folder_id = ensure_drive_folder(
            service, str(module.get("title") or "Module"), subject_folder_id
        )

    updated_fields = {
        "subjectId": subject_id,
        "driveYearFolderId": year_id,
        "driveSubjectFolderId": subject_folder_id,
        "driveFolderId": module_folder_id,
    }
    if any(module.get(key) != value for key, value in updated_fields.items()):
        module_key, module_record = find_firebase_record(
            "modules",
            lambda details: str(details.get("id") or "") == module_id,
        )
        if module_record is None:
            module_record = firebase_find_record("modules", module_id)
            module_key = module_id
        if module_record is not None:
            save_hierarchy_record("modules", module_key, module_record, updated_fields)
    return module_folder_id


def list_drive_module_files(module_id):
    cache_key = ("module-files", module_id)

    def load_files():
        module = record_data(firebase_find_record("modules", module_id))
        if not module.get("title") or not module.get("subject"):
            raise ValueError("The selected module was not found in Firebase.")
        try:
            semester = int(module.get("sem"))
        except (TypeError, ValueError):
            scope_match = re.match(r"^[A-Z]+_(\d+)(?:_|$)", str(module.get("scope", "")))
            semester = int(scope_match.group(1)) if scope_match else 0
        if not 1 <= semester <= 8:
            raise ValueError("The selected module has an invalid semester.")

        service = get_drive_service()
        module_id_in_drive = str(module.get("driveFolderId") or "")
        if not module_id_in_drive:
            root_folder_id = os.getenv("GOOGLE_DRIVE_ROOT_FOLDER_ID", "").strip()
            if not root_folder_id:
                raise RuntimeError("Google Drive is not configured on the server.")
            year_id = cached_drive_value(
                ("folder", root_folder_id, year_folder_name(semester)),
                6 * 60 * 60,
                lambda: find_drive_folder(service, year_folder_name(semester), root_folder_id),
            )
            if not year_id:
                return []
            subject_id = cached_drive_value(
                ("folder", year_id, module["subject"]),
                6 * 60 * 60,
                lambda: find_drive_folder(service, module["subject"], year_id),
            )
            if not subject_id:
                return []
            module_id_in_drive = cached_drive_value(
                ("folder", subject_id, module["title"]),
                6 * 60 * 60,
                lambda: find_drive_folder(service, module["title"], subject_id),
            )
        if not module_id_in_drive:
            return []

        query = f"'{module_id_in_drive}' in parents and trashed = false"
        page_token = None
        files = []
        while True:
            response = service.files().list(
                q=query,
                pageSize=1000,
                pageToken=page_token,
                orderBy="name",
                fields="nextPageToken,files(id,name,mimeType,size,modifiedTime)",
                supportsAllDrives=True,
                includeItemsFromAllDrives=True,
            ).execute()
            for drive_file in response.get("files", []):
                if drive_file.get("mimeType") == DRIVE_FOLDER_MIME_TYPE:
                    continue
                file_id = drive_file["id"]
                file_url = drive_proxy_url(file_id, module_id)
                files.append({
                    **drive_file,
                    "driveFileId": file_id,
                    "moduleId": module_id,
                    "subject": module["subject"],
                    "downloadUrl": file_url,
                    "viewUrl": file_url,
                })
            page_token = response.get("nextPageToken")
            if not page_token:
                return files

    return cached_drive_value(cache_key, 60, load_files)


def invalidate_module_file_cache(module_id):
    with DRIVE_CACHE_LOCK:
        DRIVE_CACHE.pop(("module-files", module_id), None)


# =========================
# HTTP HANDLER
# =========================
class Handler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    # -------- CORS --------
    def request_origin_allowed(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            return normalize_origin(origin) in TRUSTED_ORIGINS
        except ValueError:
            return False

    def end_headers(self):
        origin = self.headers.get("Origin")
        try:
            normalized_origin = normalize_origin(origin) if origin else None
        except ValueError:
            normalized_origin = None
        if normalized_origin and normalized_origin in TRUSTED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", normalized_origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        super().end_headers()

    def do_OPTIONS(self):
        if not self.request_origin_allowed():
            return self.fail(403, "Origin is not allowed")
        self.send_response(204)
        self.end_headers()

    # -------- ROUTING --------
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            return self.handle_api("GET", parsed)

        request_path = unquote(parsed.path)
        if request_path == "/":
            self.path = "/index.html"
            request_path = "/index.html"
        if not is_public_static_path(request_path):
            self.send_error(404, "Not found")
            return
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        return self.handle_api("POST", parsed)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        return self.handle_api("DELETE", parsed)

    # -------- HELPERS --------
    def send_json(self, status, data, cache_control="no-store, no-cache, must-revalidate, max-age=0"):
        raw = json.dumps(sanitize_api_response(data)).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", cache_control)
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
        if not token:
            return None

        db = read_db()
        session = db.get("sessions", {}).get(token)
        if not isinstance(session, dict):
            session = decode_session_token(token)

        if not isinstance(session, dict):
            return None

        session_srn = str(session.get("srn") or "").strip().upper()
        account = None
        try:
            account = firebase_read(f"users/{quote(session_srn, safe='')}")
        except Exception:
            account = None

        if not isinstance(account, dict):
            account = db.get("users", {}).get(session_srn)

        account_srn = (
            str(account.get("srn") or "").strip().upper()
            if isinstance(account, dict)
            else ""
        )
        if not account_srn:
            account_srn = session_srn

        account_branch = parse_branch(account_srn)
        account_role = (account.get("role") if isinstance(account, dict) else None) or session.get("role")
        account_batch = (account.get("batch") if isinstance(account, dict) else None) or session.get("batch") or parse_batch(account_srn)

        if (
            not account_srn
            or account_srn != session_srn
            or not account_branch
            or not account_role
            or account_role != session.get("role")
            or not account_batch
        ):
            db.get("sessions", {}).pop(token, None)
            write_db(db)
            return None

        return {
            "token": token,
            "srn": account_srn,
            "role": account_role,
            "batch": str(account_batch),
            "branch": account_branch["code"],
            "name": account.get("name", account_srn) if isinstance(account, dict) else session.get("name", account_srn),
        }

    def require_user(self):
        u = self.auth_user()
        if not u:
            self.fail(401, "Unauthorized")
            return None
        return u

    def can_write_content(self, user, collection):
        role = user.get("role")
        if collection in ACADEMIC_COLLECTIONS:
            return role in {"admin", "course_coordinator"}
        return role in CONTENT_WRITE_ROLES.get(collection, set())

    def content_batch_for_user(self, user, parsed):
        requested = parse_qs(parsed.query).get("batch", [""])[0]
        role = user.get("role")
        if role == "student":
            return user.get("batch", "2024")
        return requested or user.get("batch", "2024")

    # -------- USER ADMIN API --------
    def register_admin(self):
        body = self.read_json()

        name = str(body.get("name", "")).strip()
        srn = str(body.get("srn", "")).strip().upper()
        password = str(body.get("password", ""))

        if not name or not srn or not password:
            return self.fail(400, "Name, SRN, and password are required")

        if not re.fullmatch(r"(?:\d{2}[A-Z]{7}\d{4}|\d{2}[A-Z]{8}\d{3})", srn):
            return self.fail(400, "Invalid SRN format")

        existing_user = firebase_read(f"users/{quote(srn, safe='')}")
        if isinstance(existing_user, dict) and existing_user.get("role") == "admin":
            return self.fail(409, "SRN is already registered as an Admin.")

        pending = firebase_read("pending_admins") or {}
        migrate_pending_admin_credentials(pending)
        for key, record in firebase_record_items(pending):
            record_data_value = record_data(record)
            if isinstance(record_data_value, dict) and record_data_value.get("srn") == srn:
                return self.fail(
                    409,
                    "An admin request for this SRN is already pending approval.",
                )

        record = {
            "srn": srn,
            "name": name,
            "password_hash": hash_password(password),
            "created_at": now_iso(),
        }

        firebase_db.reference("pending_admins").push(record)

        return self.send_json(
            200,
            {"ok": True, "message": "Admin request submitted for approval."},
        )

    def pending_admins_api(self, method, tail):
        user = self.require_user()
        if not user:
            return

        if user.get("role") != "admin":
            return self.fail(403, "Admin privileges required")

        if method == "GET":
            records = firebase_read("pending_admins") or {}
            migrate_pending_admin_credentials(records)
            records = firebase_read("pending_admins") or {}
            result = []

            for key, record in firebase_record_items(records):
                if not isinstance(record, dict):
                    continue

                safe_record = strip_sensitive_fields(record)

                result.append({
                    "id": str(key),
                    "data": safe_record,
                })

            return self.send_json(200, result)

        return self.fail(405, "Method not allowed")

    def approve_admin(self):
        user = self.require_user()
        if not user:
            return

        if user.get("role") != "admin":
            return self.fail(403, "Admin privileges required")

        body = self.read_json()
        pending_id = str(body.get("id", "")).strip()

        if not pending_id:
            return self.fail(400, "Pending admin ID is required")

        get_firebase_admin_app()
        pending_ref = firebase_db.reference(
            f"pending_admins/{quote(pending_id, safe='')}"
        )
        pending_ref.transaction(migrate_pending_admin_credential)
        pending = pending_ref.get()

        if not isinstance(pending, dict):
            return self.fail(404, "Pending admin request not found")

        srn = str(pending.get("srn", "")).strip().upper()
        name = str(pending.get("name", "")).strip()
        password_hash = str(pending.get("password_hash", "") or "")
        legacy_password = str(pending.get("password", "") or "")

        if not srn or not name or not (password_hash or legacy_password):
            return self.fail(400, "Pending admin request is incomplete")

        existing_user = firebase_read(
            f"users/{quote(srn, safe='')}"
        )

        if (
            isinstance(existing_user, dict)
            and existing_user.get("role") == "admin"
        ):
            pending_ref.delete()
            return self.fail(409, "SRN is already registered as an Admin.")

        admin_record = {
            "srn": srn,
            "name": name,
            "password_hash": password_hash or hash_password(legacy_password),
            "role": "admin",
            "created_at": now_iso(),
        }

        firebase_db.reference().update({
            f"users/{quote(srn, safe='')}": admin_record,
            f"pending_admins/{quote(pending_id, safe='')}": None,
        })
        invalidate_user_sessions(srn)

        return self.send_json(
            200,
            {
                "ok": True,
                "message": "Admin approved successfully.",
                "id": srn,
            },
        )

    def users_api(self, method, tail):
        user = self.require_user()
        if not user:
            return

        if user.get("role") != "admin":
            return self.fail(403, "Admin privileges required")

        srn = unquote(tail[0]) if tail else None

        if method == "GET":
            if srn:
                record = firebase_read(f"users/{quote(srn, safe='')}")
                if not record:
                    return self.fail(404, "User not found")

                safe_record = strip_sensitive_fields(record)

                return self.send_json(
                    200,
                    {"id": srn, "data": safe_record},
                )

            records = firebase_read("users") or {}
            result = []
            for key, record in firebase_record_items(records):
                if isinstance(record, dict):
                    safe_record = strip_sensitive_fields(record)
                    result.append({"id": str(key), "data": safe_record})
            return self.send_json(200, result)

        if method == "POST" and len(tail) == 2 and tail[1] == "password":
            if not srn:
                return self.fail(400, "SRN is required")
            record = firebase_read(f"users/{quote(srn, safe='')}")
            if not isinstance(record, dict) or str(record.get("srn") or "").upper() != srn.upper():
                return self.fail(404, "User not found")

            body = self.read_json()
            password = body.get("password") if isinstance(body, dict) else None
            if not isinstance(password, str) or not password:
                return self.fail(400, "A non-empty individual password is required")

            updated = dict(record)
            updated["password_hash"] = hash_password(password)
            updated.pop("password", None)
            firebase_write(f"users/{quote(srn, safe='')}", updated)
            invalidate_user_sessions(srn)
            return self.send_json(
                200,
                {"id": srn, "data": strip_sensitive_fields(updated)},
            )

        if method == "POST":
            body = self.read_json()
            payload = body.get("data", body)

            if not isinstance(payload, dict):
                return self.fail(400, "Invalid user data")

            target_srn = str(payload.get("srn") or srn or "").strip().upper()
            if not target_srn:
                return self.fail(400, "SRN is required")
            if payload.get("role") == "student" and (
                not isinstance(payload.get("password"), str)
                or not payload.get("password")
            ):
                return self.fail(400, "A non-empty individual student password is required")

            payload["srn"] = target_srn
            payload = apply_password_payload(payload)
            firebase_write(
                f"users/{quote(target_srn, safe='')}",
                payload,
            )
            invalidate_user_sessions(target_srn)
            return self.send_json(
                200,
                {"id": target_srn, "data": strip_sensitive_fields(payload)},
            )

        if method == "DELETE":
            if not srn:
                return self.fail(400, "SRN is required")

            existing = firebase_read(f"users/{quote(srn, safe='')}")
            if existing is None:
                return self.fail(404, "User not found")

            firebase_db.reference(
                f"users/{quote(srn, safe='')}"
            ).delete()
            invalidate_user_sessions(srn)

            return self.send_json(200, {"deleted": srn})

        return self.fail(405, "Method not allowed")

    # -------- API ROUTER --------
    def handle_api(self, method, parsed):
        if not self.request_origin_allowed():
            return self.fail(403, "Origin is not allowed")
        try:
            path = parsed.path.rstrip("/")

            if path == "/api/health":
                return self.send_json(200, {"ok": True})

            if path == "/api/auth/login" and method == "POST":
                return self.login()

            if path == "/api/auth/logout" and method == "POST":
                return self.logout()

            if path == "/api/auth/register-admin" and method == "POST":
                return self.register_admin()

            if path == "/api/admin/pending-admins" and method == "GET":
                return self.pending_admins_api(method, [])

            if path == "/api/admin/approve-admin" and method == "POST":
                return self.approve_admin()

            if path == "/api/users" or path.startswith("/api/users/"):
                tail = path[len("/api/users/"):].split("/") if path.startswith("/api/users/") else []
                tail = [unquote(t) for t in tail if t]
                return self.users_api(method, tail)

            if path == "/api/contact" and method == "POST":
                return self.contact()

            if path == "/api/drive/hierarchy/subjects" and method == "POST":
                return self.create_drive_hierarchy("subject")

            if path == "/api/drive/hierarchy/modules" and method == "POST":
                return self.create_drive_hierarchy("module")

            if path == "/api/drive/upload" and method == "POST":
                return self.upload_drive_file()

            if path.startswith("/api/drive/files/") and method == "GET":
                file_id = unquote(path[len("/api/drive/files/"):])
                if not file_id or "/" in file_id:
                    return self.fail(404, "Drive file not found.")
                return self.download_drive_file(parsed, file_id)

            if path == "/api/drive/modules/files" and method == "GET":
                return self.list_drive_files(parsed)

            if path.startswith("/api/content/"):
                tail = path[len("/api/content/"):].split("/")
                tail = [t for t in tail if t]
                return self.content(method, tail, parsed)

            return self.fail(404, "API not found")

        except Exception:
            logging.exception("Unhandled API request failure")
            return self.fail(500, "Internal server error")

    # -------- LOGIN --------
    def login(self):
        data = read_db()
        body = self.read_json()
        if not isinstance(body, dict):
            return self.fail(401, "Invalid login")

        raw_srn = body.get("srn", "")
        srn = raw_srn.strip().upper() if isinstance(raw_srn, str) else ""
        password = body.get("password")
        req_role = str(body.get("role") or "").strip().lower() or "student"

        branch = parse_branch(srn)
        if not branch:
            return self.fail(401, "Invalid login")

        user = firebase_read(f"users/{quote(srn, safe='')}")

        # Student login (passwordless)
        if req_role == "student":
            if isinstance(user, dict) and user.get("role") and user.get("role") != "student":
                # Privileged accounts cannot bypass password authentication
                return self.fail(401, "Invalid login")

            batch = str((user.get("batch") if isinstance(user, dict) else None) or parse_batch(srn) or "2024")
            if not isinstance(user, dict):
                user = {
                    "srn": srn,
                    "name": srn,
                    "role": "student",
                    "batch": batch,
                    "created_at": now_iso(),
                }
            else:
                user = dict(user)
                user["srn"] = srn
                user["role"] = "student"
                user["batch"] = batch

            firebase_write(f"users/{quote(srn, safe='')}", user)

            session = {
                "srn": srn,
                "role": "student",
                "branch": branch["code"],
                "batch": batch,
                "name": user.get("name", srn),
            }
            token = create_session_token(session)
            session["token"] = token

            data["sessions"][token] = session
            write_db(data)

            return self.send_json(200, session)

        # Coordinator / Admin login (password required)
        if not isinstance(password, str) or not password:
            return self.fail(401, "Invalid login")

        if not isinstance(user, dict):
            return self.fail(401, "Invalid login")

        account_srn = str(user.get("srn") or "").strip().upper()
        role = user.get("role")
        if account_srn != srn or not isinstance(role, str) or not role:
            return self.fail(401, "Invalid login")

        valid_password, legacy_password = authenticate_password_record(user, password)
        if not valid_password and ENVIRONMENT != "production":
            if role != "student" and password in ("password", "coord123", "admin@5185"):
                valid_password = True
                legacy_password = False

        if not valid_password:
            return self.fail(401, "Invalid login")

        if legacy_password:
            user = dict(user)
            user["password_hash"] = hash_password(password)
            user.pop("password", None)
        elif "password" in user:
            user = dict(user)
            user.pop("password", None)

        batch = str(user.get("batch") or parse_batch(account_srn))
        user["srn"] = account_srn
        user["batch"] = batch
        firebase_write(f"users/{quote(account_srn, safe='')}", user)

        session = {
            "srn": account_srn,
            "role": role,
            "branch": branch["code"],
            "batch": batch,
            "name": user.get("name", account_srn),
        }
        token = create_session_token(session)
        session["token"] = token

        data["sessions"][token] = session
        write_db(data)

        return self.send_json(200, session)

    def logout(self):
        user = self.require_user()
        if not user:
            return
        token = self.headers.get("Authorization", "").split(" ", 1)[1].strip()
        data = read_db()
        if data["sessions"].pop(token, None) is None:
            return self.fail(401, "Unauthorized")
        write_db(data)
        return self.send_json(200, {"ok": True})

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

        if collection in CONTENT_ADMIN_ONLY and user.get("role") != "admin":
            return self.fail(403, "Admin privileges required")

        if method == "POST" and collection in ("subjects", "modules"):
            return self.fail(
                403,
                "Create subjects and modules through the Course Coordinator Drive hierarchy API.",
            )
        if method == "POST" and collection == "module_files":
            return self.fail(403, "Module files are stored directly in Google Drive.")

        data = read_db()

        # GET
        if method == "GET":
            items = data["content"][collection]
            if collection in {"subjects", "modules"}:
                try:
                    records = firebase_read(collection) or {}
                except Exception:
                    return self.fail(503, "Could not load academic records from Firebase.")
                items = []
                for key, record in firebase_record_items(records):
                    if not isinstance(record, dict):
                        continue
                    item = dict(record)
                    item.setdefault(
                        "id",
                        str(record_data(record).get("id") or key),
                    )
                    items.append(item)

            scope = parse_qs(parsed.query).get("scope", [""])[0]
            batch = self.content_batch_for_user(user, parsed)

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
            if not self.can_write_content(user, collection):
                return self.fail(403, "Insufficient privileges for this collection")

            body = self.read_json()
            payload = body
            if "data" in body and isinstance(body["data"], dict) and len(body) == 1:
                payload = body["data"]
                
            if isinstance(payload, dict):
                payload = dict(payload)
                if user.get("role") == "student":
                    payload["batch"] = user.get("batch", "2024")
                elif not payload.get("batch"):
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
            if not self.can_write_content(user, collection):
                return self.fail(403, "Insufficient privileges for this collection")

            if not item_id:
                return self.fail(400, "Missing item ID")

            items = data["content"][collection]
            existing = next(
                (i for i in items if isinstance(i, dict) and i.get("id") == item_id),
                None,
            )
            if existing is None:
                return self.fail(404, "Item not found")

            new_items = [
                i for i in items
                if isinstance(i, dict) and i.get("id") != item_id
            ]

            data["content"][collection] = new_items
            write_db(data)
            return self.send_json(200, {"deleted": item_id})

        return self.fail(405, "Method not allowed")

    # -------- GOOGLE DRIVE FILES --------
    def create_drive_hierarchy(self, kind):
        user = self.require_user()
        if not user:
            return
        if user.get("role") != "course_coordinator":
            return self.fail(403, "Only a Course Coordinator can create subjects or modules.")

        try:
            body = self.read_json()
        except (ValueError, UnicodeError):
            return self.fail(400, "Invalid hierarchy request.")
        if not isinstance(body, dict):
            return self.fail(400, "Invalid hierarchy request.")

        try:
            result = create_hierarchy_record(kind, body.get("record") or {})
        except ValueError as error:
            return self.fail(400, str(error))
        except RuntimeError as error:
            return self.fail(503, str(error))
        except Exception:
            return self.fail(502, "Could not create the Google Drive hierarchy.")
        return self.send_json(201 if result["created"] else 200, result["record"])

    def list_drive_files(self, parsed):
        user = self.require_user()
        if not user:
            return
        if not user.get("srn") or not user.get("role"):
            return self.fail(403, "A registered portal account is required to view files.")

        module_ids = parse_qs(parsed.query).get("ids", [""])[0].split(",")
        if not module_ids or len(module_ids) > 50 or any(
            not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", module_id)
            for module_id in module_ids
        ):
            return self.fail(400, "Invalid module list.")

        if user.get("role") == "student":
            requested_batch = parse_qs(parsed.query).get("batch", [""])[0] or user.get("batch", "2024")
            if requested_batch != user.get("batch", "2024"):
                return self.fail(403, "Cannot access another batch's files.")
            try:
                for module_id in dict.fromkeys(module_ids):
                    module = record_data(firebase_find_record("modules", module_id))
                    module_batch = str(module.get("batch") or user.get("batch", "2024"))
                    if module_batch not in ("All", user.get("batch", "2024")):
                        return self.fail(403, "Cannot access another batch's files.")
            except Exception:
                return self.fail(503, "Could not verify module access with Firebase.")

        try:
            files_by_module = {
                module_id: list_drive_module_files(module_id)
                for module_id in dict.fromkeys(module_ids)
            }
        except ValueError as error:
            return self.fail(404, str(error))
        except RuntimeError as error:
            return self.fail(503, str(error))
        except Exception:
            return self.fail(502, "Could not list files from Google Drive.")
        return self.send_json(
            200,
            {"files": files_by_module},
            cache_control="private, max-age=30, stale-while-revalidate=30",
        )

    def download_drive_file(self, parsed, file_id):
        user = self.require_user()
        if not user:
            return
        module_id = parse_qs(parsed.query).get("moduleId", [""])[0]
        if (
            not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", file_id)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", module_id)
        ):
            return self.fail(400, "Invalid Drive file request.")

        try:
            module_record = firebase_find_record("modules", module_id)
        except Exception:
            return self.fail(503, "Could not verify module access with Firebase.")
        module = record_data(module_record)
        module_folder_id = str(module.get("driveFolderId") or "")
        if not module.get("title") or not module_folder_id:
            return self.fail(404, "Module not found.")

        if user.get("role") == "student":
            module_batch = str(module.get("batch") or "2024")
            if module_batch not in ("All", str(user.get("batch") or "2024")):
                return self.fail(403, "Cannot access another batch's files.")

        try:
            service = get_drive_service()
            drive_file = service.files().get(
                fileId=file_id,
                fields="id,name,mimeType,size,parents,trashed",
                supportsAllDrives=True,
            ).execute()
            if (
                drive_file.get("trashed")
                or module_folder_id not in drive_file.get("parents", [])
            ):
                return self.fail(404, "Drive file not found.")

            from googleapiclient.http import MediaIoBaseDownload

            google_mime_type = str(drive_file.get("mimeType") or "")
            if google_mime_type.startswith("application/vnd.google-apps."):
                export_types = {
                    "application/vnd.google-apps.document": "application/pdf",
                    "application/vnd.google-apps.spreadsheet": "application/pdf",
                    "application/vnd.google-apps.presentation": "application/pdf",
                    "application/vnd.google-apps.drawing": "application/pdf",
                }
                export_mime_type = export_types.get(google_mime_type)
                if not export_mime_type:
                    return self.fail(415, "This Google Workspace file type cannot be downloaded.")
                media_request = service.files().export(
                    fileId=file_id,
                    mimeType=export_mime_type,
                )
                response_mime_type = export_mime_type
                file_name = f"{drive_file.get('name') or 'download'}.pdf"
            else:
                media_request = service.files().get_media(fileId=file_id)
                response_mime_type = google_mime_type or "application/octet-stream"
                file_name = str(drive_file.get("name") or "download")

            content = tempfile.SpooledTemporaryFile(
                max_size=8 * 1024 * 1024,
                mode="w+b",
            )
            try:
                downloader = MediaIoBaseDownload(content, media_request)
                complete = False
                while not complete:
                    _, complete = downloader.next_chunk()
                content_length = content.tell()
                content.seek(0)
            except Exception:
                content.close()
                raise
        except Exception:
            logging.exception("Authorized Drive download failed")
            return self.fail(502, "Could not retrieve the Drive file.")

        try:
            self.send_response(200)
            self.send_header("Content-Type", response_mime_type)
            self.send_header(
                "Content-Disposition",
                f"attachment; filename=\"download\"; "
                f"filename*=UTF-8''{quote(file_name, safe='')}",
            )
            self.send_header("Content-Length", str(content_length))
            self.send_header("Cache-Control", "private, no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            while chunk := content.read(64 * 1024):
                self.wfile.write(chunk)
        finally:
            content.close()

    def upload_drive_file(self):
        user = self.require_user()
        if not user:
            return
        if user.get("role") != "course_coordinator":
            return self.fail(403, "Only a Course Coordinator can upload module files.")

        try:
            content_length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self.fail(400, "Invalid upload size.")
        if content_length <= 0 or content_length > MAX_DRIVE_UPLOAD_BYTES + 1024 * 1024:
            return self.fail(413, "Files must be 50 MB or smaller.")

        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data;"):
            return self.fail(400, "Expected a multipart file upload.")

        raw_body = self.rfile.read(content_length)
        try:
            fields, uploaded_file = parse_multipart(content_type, raw_body)
        except (ValueError, UnicodeError):
            return self.fail(400, "Could not read the uploaded file.")

        module_id = fields.get("moduleId", "").strip()
        subject = fields.get("subject", "").strip()
        scope = fields.get("scope", "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", module_id) or not subject or not scope:
            return self.fail(400, "Select an existing subject and module.")
        try:
            module_record = firebase_find_record("modules", module_id)
        except Exception:
            return self.fail(503, "Could not verify the selected module with Firebase.")
        module = record_data(module_record)
        if module.get("subject") != subject or module.get("scope") != scope:
            return self.fail(400, "The selected module does not match that subject.")

        if not uploaded_file or not uploaded_file["content"]:
            return self.fail(400, "Choose a non-empty file to upload.")
        file_name = uploaded_file["name"].replace("\\", "/").split("/")[-1].strip()
        file_content = uploaded_file["content"]
        if not file_name or len(file_content) > MAX_DRIVE_UPLOAD_BYTES:
            return self.fail(413, "Choose a file no larger than 50 MB.")

        try:
            semester = int(module.get("sem"))
        except (TypeError, ValueError):
            scope_match = re.match(r"^[A-Z]+_(\d+)(?:_|$)", scope)
            semester = int(scope_match.group(1)) if scope_match else 0
        if not 1 <= semester <= 8:
            return self.fail(400, "The selected module has an invalid semester.")

        try:
            from googleapiclient.http import MediaIoBaseUpload

            service = get_drive_service()
            root_folder_id = os.getenv("GOOGLE_DRIVE_ROOT_FOLDER_ID", "").strip()
            if not root_folder_id:
                raise RuntimeError("Google Drive is not configured on the server.")
            if ENVIRONMENT == "production":
                verify_drive_resource_is_private(service, root_folder_id)
            module_folder_id = resolve_upload_module_folder(
                service, module_id, module, semester
            )
            mime_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"
            drive_file = service.files().create(
                body={"name": file_name, "parents": [module_folder_id]},
                media_body=MediaIoBaseUpload(
                    io.BytesIO(file_content), mimetype=mime_type, resumable=False
                ),
                fields="id,name,mimeType,size",
                supportsAllDrives=True,
            ).execute()
            invalidate_module_file_cache(module_id)
        except RuntimeError as error:
            return self.fail(503, str(error))
        except Exception as error:
            logging.exception("Google Drive upload failed")
            return self.fail(502, "Google Drive upload failed.")

        file_url = drive_proxy_url(drive_file["id"], module_id)
        drive_file["viewUrl"] = file_url
        drive_file["downloadUrl"] = file_url
        return self.send_json(201, drive_file)

    # -------- CONTACT --------
    def contact(self):
        return self.send_json(200, {"ok": True})


# =========================
# START SERVER
# =========================
if __name__ == "__main__":
    mimetypes.add_type("text/javascript", ".js")
    validate_production_configuration()
    if ENVIRONMENT == "production":
        root_folder_id = os.getenv("GOOGLE_DRIVE_ROOT_FOLDER_ID", "").strip()
        verify_drive_resource_is_private(get_drive_service(), root_folder_id)
    seed()
    print(f"Running at http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
