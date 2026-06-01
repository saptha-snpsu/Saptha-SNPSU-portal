var API = location.port === "8000" ? "/api" : "http://127.0.0.1:8000/api";

var LS = {
    get:(k,d=null)=>{try{return JSON.parse(localStorage.getItem(k))??d}catch{return d}},
    set:(k,v)=>localStorage.setItem(k,JSON.stringify(v)),
    del:k=>localStorage.removeItem(k)
};

function requireAuth(){
    const u = LS.get("snps_user");
    if(!u){ location.href="index.html"; return null; }
    return u;
}

function logout(){
    LS.del("snps_user");
    LS.del("viewing_batch");
    location.href="index.html";
}

function getBatchFromSRN(srn){
    const m = String(srn||"").match(/^(\d{2})/);
    return m ? `20${m[1]}` : "2024";
}

function getEffectiveBatch(){
    const u = LS.get("snps_user");
    if(!u) return "2024";
    const defaultBatch = u.batch || getBatchFromSRN(u.srn) || "2024";
    if(u.role !== "student"){
        return LS.get("viewing_batch") || defaultBatch;
    }
    return defaultBatch;
}

var ROLE_LABELS = {
    student: "Student",
    course_coordinator: "Course Coordinator",
    director: "Director",
    hrd_coordinator: "HRD Coordinator",
    hostel_coordinator: "Hostel Coordinator",
    canteen_coordinator: "Canteen Coordinator",
    library_coordinator: "Library Coordinator",
    dsa_coordinator: "DSA Member",
    placement_coordinator: "Placement Coordinator",
    sports_coordinator: "Sports Coordinator",
    events_coordinator: "Events Coordinator"
};

var EDIT_PERMISSIONS = {
    departments: ["course_coordinator"],
    announcements: ["director"],
    hrd: ["hrd_coordinator"],
    hostel: ["hostel_coordinator"],
    canteen: ["canteen_coordinator"],
    library: ["library_coordinator"],
    dsa: ["dsa_coordinator"],
    placements: ["placement_coordinator"],
    sports: ["sports_coordinator"],
    events: ["events_coordinator"]
};

function roleLabel(role){
    return ROLE_LABELS[role] || role || "Student";
}

function canEdit(area){
    const u = LS.get("snps_user");
    return !!u && (EDIT_PERMISSIONS[area] || []).includes(u.role);
}


const firebaseConfig = {
  apiKey: "AIzaSyBYnklU-sN7tSmT20xxhHjhe2f7S4bZGqE",
  authDomain: "saptha-college.firebaseapp.com",
  projectId: "saptha-college",
  storageBucket: "saptha-college.firebasestorage.app",
  messagingSenderId: "654209557619",
  appId: "1:654209557619:web:434a43aa2a49e9d0ceb606",
  databaseURL: "https://saptha-college-default-rtdb.firebaseio.com"
};

if (!window.firebase.apps.length) {
    window.firebase.initializeApp(firebaseConfig);
}
const db = window.firebase.database();

async function apiList(collectionName, scope=""){
    const batch = getEffectiveBatch();
    const snapshot = await db.ref(collectionName).once('value');
    let docs = [];
    snapshot.forEach(child => {
        docs.push({id: child.key, ...child.val()});
    });
    
    // Strict batch filtering: only show items that match the current batch or are explicitly set to 'All'
    docs = docs.filter(d => {
        let b = (d.data && d.data.batch) || d.batch;
        return b === 'All' || b === batch;
    });
    
    if(scope) {
        docs = docs.filter(d => {
            let s = (d.data && d.data.scope) || d.scope;
            return s === scope;
        });
    }
    return docs;
}

async function apiCreate(collectionName, payload){
    const batch = getEffectiveBatch();
    payload.batch = payload.batch || batch;
    
    const newRef = db.ref(collectionName).push();
    const item = {
        id: newRef.key,
        data: payload,
        created_at: new Date().toISOString()
    };
    
    await newRef.set(item);
    return item;
}

async function apiDelete(collectionName, id){
    await db.ref(collectionName).child(id).remove();
    return {deleted: id};
}

var NAV_ITEMS = [
["home.html","Home"],["aboutus.html","About Us"],["departments.html","Departments"],
["resources.html","Resources"],["announcements.html","Announcements"],["hrd.html","HRD"],
["hostel.html","Hostel"],["canteen.html","Canteen"],["library.html","Library"],
["dsa.html","DSA"],["placements.html","Placements"],["sports.html","Sports"],
["events.html","Events"],["contactus.html","Contact Us"]
];

function renderHeader(active){
    const u = LS.get("snps_user");
    const initials = u ? (u.name || u.srn).substring(0,2).toUpperCase() : "";
    const photo = u?.photo
        ? `<img src="${u.photo}" style="width:32px;height:32px;border-radius:50%">`
        : `<div class="avatar">${initials}</div>`;

    const isCoordinator = u?.role && u.role !== "student";
    const selectedBatch = getEffectiveBatch();

    const batchSelector = isCoordinator ? `
      <select id="globalBatchSelect" onchange="LS.set('viewing_batch', this.value); location.reload();"
              style="padding:4px 8px;border-radius:6px;border:1px solid #ccc;font-weight:600;font-size:13px;color:#0b3d91;margin-left:10px;background:#fff;">
        <option value="2024" ${selectedBatch==="2024"?"selected":""}>2024 Batch</option>
        <option value="2025" ${selectedBatch==="2025"?"selected":""}>2025 Batch</option>
        <option value="2026" ${selectedBatch==="2026"?"selected":""}>2026 Batch</option>
        <option value="2027" ${selectedBatch==="2027"?"selected":""}>2027 Batch</option>
      </select>` : "";

    const roleBadge = isCoordinator
        ? `<span class="badge-role">${roleLabel(u.role)}</span>` : "";

    const nav = NAV_ITEMS.map(([h,l]) =>
        `<li><a href="${h}" class="${h===active?'active':''}">${l}</a></li>`
    ).join("");

    document.body.insertAdjacentHTML("afterbegin", `
    <style>
        .nav-logo{ width:32px !important; height:32px !important; object-fit:contain; flex-shrink:0; }
        .brand{ display:flex; align-items:center; gap:8px; }
    </style>
    <div class="topbar">
        <div class="container">
            <span>Sapthagiri NPS University — Student Portal</span>
            <span>${u ? `Welcome, ${u.name||u.srn} · <a href="#" onclick="logout();return false;">Logout</a>` : ""}</span>
        </div>
    </div>
    <div class="nav-overlay" onclick="toggleNav()"></div>
    <header class="site">
        <div class="container site-inner">
            <div style="display:flex;align-items:center;gap:12px">
                <button class="hamburger" onclick="toggleNav()">☰</button>
                <div class="brand">
                    <img src="logo.jpg" class="nav-logo">
                    <div>
                        <h1>SAPTHA</h1>
                        <small>Smart Campus · CSE ${selectedBatch} Batch</small>
                    </div>
                </div>
            </div>
            <nav class="main"><ul>${nav}</ul></nav>
            ${u ? `
            <div class="user-chip">
                ${photo}
                <span style="font-size:13px;font-weight:600">${u.srn}</span>
                ${roleBadge}
                ${batchSelector}
            </div>` : ""}
        </div>
    </header>
    `);
}

function toggleNav() {
    const nav = document.querySelector('nav.main');
    const overlay = document.querySelector('.nav-overlay');
    if(nav) nav.classList.toggle('open');
    if(overlay) overlay.classList.toggle('open');
}

function renderFooter(){
    document.body.insertAdjacentHTML("beforeend", `
    <footer class="site">
        <div class="container">
            <div class="grid cols-4">
                <div>
                    <h5>SAPTHA</h5>
                    <p>Your smart campus companion — centralized resources, instant updates and seamless access.</p>
                </div>
                <div>
                    <h5>Quick Access</h5>
                    <p>
                        <a href="aboutus.html">About Us</a><br>
                        <a href="departments.html">Departments</a><br>
                        <a href="hrd.html">HRD</a><br>
                        <a href="placements.html">Placements</a><br>
                        <a href="announcements.html">Announcements</a><br>
                        <a href="dsa.html">DSA</a>
                    </p>
                </div>
                <div>
                    <h5>Follow Us</h5>
                    <p>
                        <a href="https://www.instagram.com/saptha_snpsu/" target="_blank">Instagram</a><br>
                        <a href="https://snpsu.edu.in" target="_blank">Main Portal</a>
                    </p>
                </div>
                <div>
                    <h5>Contact the Developers</h5>
                    <p>
                        Saptha.snpsu@gmail.com<br>
                        <a href="https://www.instagram.com/saptha_snpsu/" target="_blank">Instagram</a>
                    </p>
                </div>
            </div>
            <div class="copy">Designed & developed by CSE Department · 2024 Batch — SAPTHA</div>
        </div>
    </footer>
    `);
}
(function initNotifications() {
    const u = LS.get("snps_user");
    if (!u) return;
    
    let knownIds = new Set();
    let isInitial = true;
    
    setInterval(async () => {
        try {
            const raw = await apiList("announcements");
            
            if (isInitial) {
                raw.forEach(a => knownIds.add(a.id));
                isInitial = false;
                return;
            }
            
            raw.forEach(a => {
                if (!knownIds.has(a.id)) {
                    knownIds.add(a.id);
                    if (a.data.by !== u.name && a.data.by !== u.role) {
                        alert(`📢 New Announcement: ${a.data.title}\nBy ${a.data.by}`);
                    }
                }
            });
        } catch (e) {}
    }, 5000);
})();
