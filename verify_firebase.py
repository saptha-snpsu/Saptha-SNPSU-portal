#!/usr/bin/env python3
"""
Verify and Diagnose Firebase Connection for SAPTHA SNPSU Portal.
Usage:
    python verify_firebase.py
    python verify_firebase.py --sync
"""

import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Load environment
BASE_DIR = Path(__file__).resolve().parent
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=BASE_DIR / ".env")
except ImportError:
    pass

FIREBASE_DATABASE_URL = os.getenv(
    "SAPTHA_FIREBASE_DATABASE_URL",
    "https://saptha-college-default-rtdb.firebaseio.com"
).rstrip("/")

FIREBASE_SA_FILE = Path(
    os.getenv("SAPTHA_FIREBASE_SERVICE_ACCOUNT_FILE", "./service-account.json")
).expanduser()

if not FIREBASE_SA_FILE.is_absolute():
    FIREBASE_SA_FILE = (BASE_DIR / FIREBASE_SA_FILE).resolve()


def check_firebase_admin_sdk():
    print("[1/4] Checking Python Firebase Admin SDK...")
    try:
        import firebase_admin
        from firebase_admin import credentials, db
        print(f"  [OK] firebase-admin package installed (v{firebase_admin.__version__})")
        return True, (firebase_admin, credentials, db)
    except ImportError:
        print("  [FAIL] firebase-admin is not installed. Run: pip install firebase-admin")
        return False, None


def check_service_account():
    print(f"\n[2/4] Checking Service Account credentials...")
    sa_json = os.getenv("SAPTHA_FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
    if sa_json:
        try:
            parsed = json.loads(sa_json)
            project_id = parsed.get("project_id", "unknown")
            print(f"  [OK] SAPTHA_FIREBASE_SERVICE_ACCOUNT_JSON detected for project: {project_id}")
            return "json_env", parsed
        except Exception as e:
            print(f"  [FAIL] Invalid SAPTHA_FIREBASE_SERVICE_ACCOUNT_JSON: {e}")

    if FIREBASE_SA_FILE.exists():
        try:
            content = json.loads(FIREBASE_SA_FILE.read_text(encoding="utf-8"))
            project_id = content.get("project_id", "unknown")
            client_email = content.get("client_email", "unknown")
            print(f"  [OK] Service account file found: {FIREBASE_SA_FILE}")
            print(f"    - Project ID: {project_id}")
            print(f"    - Client Email: {client_email}")
            return "file", FIREBASE_SA_FILE
        except Exception as e:
            print(f"  [FAIL] Could not parse service account file: {e}")
    else:
        print(f"  [INFO] Service account file not found at: {FIREBASE_SA_FILE}")
        print("    (Running in development mode with fallback to local saptha_db.json)")
    return None, None


def test_rtdb_rest():
    print(f"\n[3/4] Testing REST connection to Firebase RTDB ({FIREBASE_DATABASE_URL})...")
    url = f"{FIREBASE_DATABASE_URL}/.json?shallow=true"
    req = Request(url, headers={"User-Agent": "Saptha-Diagnostic/1.0"})
    try:
        with urlopen(req, timeout=5) as response:
            status = response.status
            body = response.read().decode("utf-8")
            print(f"  [OK] Firebase Realtime Database endpoint reachable (HTTP {status})")
            try:
                keys = list(json.loads(body).keys()) if body and body != "null" else []
                print(f"  [OK] Available root collections: {', '.join(keys) if keys else '(empty)'}")
            except Exception:
                pass
            return True
    except HTTPError as e:
        if e.code == 401 or e.code == 403:
            print(f"  [OK] Database endpoint reachable. (Protected by Security Rules: HTTP {e.code})")
            return True
        print(f"  [FAIL] HTTP Error reaching database: {e.code} {e.reason}")
        return False
    except URLError as e:
        print(f"  [FAIL] Network error connecting to Firebase URL: {e.reason}")
        return False
    except Exception as e:
        print(f"  [FAIL] Connection error: {e}")
        return False


def test_admin_connection(sdk, sa_type, sa_data):
    print(f"\n[4/4] Testing Admin SDK authentication with Firebase...")
    if not sa_type:
        print("  [INFO] Skipping Admin SDK test (no service account configured).")
        return

    firebase_admin, credentials, db = sdk
    try:
        if not firebase_admin._apps:
            if sa_type == "json_env":
                cred = credentials.Certificate(sa_data)
            else:
                cred = credentials.Certificate(str(sa_data))
            firebase_admin.initialize_app(cred, {"databaseURL": FIREBASE_DATABASE_URL})

        app = firebase_admin.get_app()
        print(f"  [OK] Firebase Admin App initialized successfully: {app.name}")

        # Test read
        users_ref = db.reference("users")
        users = users_ref.get()
        count = len(users) if isinstance(users, dict) else (len(users) if isinstance(users, list) else 0)
        print(f"  [OK] Successfully queried 'users' node: {count} accounts found.")
        return True
    except Exception as e:
        print(f"  [FAIL] Admin SDK operation failed: {e}")
        return False


def sync_local_to_firebase(sdk, sa_type, sa_data):
    print("\n--- SYNCING LOCAL saptha_db.json TO FIREBASE ---")
    local_db_path = BASE_DIR / "saptha_db.json"
    if not local_db_path.exists():
        print(f"Local database {local_db_path} not found.")
        return

    if not sa_type:
        print("A service account is required to sync data to Firebase.")
        return

    firebase_admin, credentials, db = sdk
    data = json.loads(local_db_path.read_text(encoding="utf-8-sig"))

    print("Uploading users...")
    if "users" in data:
        db.reference("users").set(data["users"])
        print(f"  [OK] {len(data['users'])} users synced.")

    collections = [
        "announcements", "activity_announcements", "events", "placements",
        "sports", "hrd_programs", "hostel_announcements", "hostel_info",
        "canteen_info", "library", "subjects", "modules", "pending_admins",
        "contacts_list"
    ]

    for col in collections:
        items = data.get("content", {}).get(col, data.get(col))
        if items:
            print(f"Uploading {col}...")
            db.reference(col).set(items)
            count = len(items) if isinstance(items, (list, dict)) else 1
            print(f"  [OK] {col}: {count} records synced.")

    print("\n[OK] Full sync completed successfully!")


def main():
    print("=" * 60)
    print(" SAPTHA SNPSU Portal — Firebase Connection Diagnostic")
    print("=" * 60)

    has_sdk, sdk = check_firebase_admin_sdk()
    sa_type, sa_data = check_service_account()
    rtdb_ok = test_rtdb_rest()

    if has_sdk and sa_type:
        test_admin_connection(sdk, sa_type, sa_data)

    if "--sync" in sys.argv and has_sdk and sa_type:
        sync_local_to_firebase(sdk, sa_type, sa_data)

    print("\n" + "=" * 60)
    print(" Diagnostic Complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
