import json
from pathlib import Path
from datetime import datetime, timezone

DB_FILE = Path("c:/Users/kisho/Downloads/Saptha-portal/Saptha-portal-main/saptha_db.json")

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def update_db():
    if not DB_FILE.exists():
        print("DB file not found.")
        return

    data = json.loads(DB_FILE.read_text(encoding="utf-8-sig"))
    
    # 1. Add admin user
    if "users" not in data:
        data["users"] = {}
        
    data["users"]["24SUUBECS0952"] = {
        "srn": "24SUUBECS0952",
        "password": "admin@5185",
        "role": "admin",
        "name": "Super Admin",
        "created_at": now_iso()
    }
    
    # 2. Add missing collections
    if "content" not in data:
        data["content"] = {}
        
    for col in ["contacts_list", "pending_admins"]:
        if col not in data["content"]:
            data["content"][col] = []
            
    DB_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print("Database updated successfully.")

if __name__ == "__main__":
    update_db()
