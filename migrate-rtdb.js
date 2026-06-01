const fs = require('fs');
const firebase = require('firebase/compat/app');
require('firebase/compat/database');

const firebaseConfig = {
  apiKey: "AIzaSyBYnklU-sN7tSmT20xxhHjhe2f7S4bZGqE",
  authDomain: "saptha-college.firebaseapp.com",
  projectId: "saptha-college",
  storageBucket: "saptha-college.firebasestorage.app",
  messagingSenderId: "654209557619",
  appId: "1:654209557619:web:434a43aa2a49e9d0ceb606",
  databaseURL: "https://saptha-college-default-rtdb.firebaseio.com"
};

firebase.initializeApp(firebaseConfig);
const db = firebase.database();

async function migrate() {
    console.log("Reading saptha_db.json...");
    const data = JSON.parse(fs.readFileSync('saptha_db.json', 'utf8'));

    // Migrate users (convert dict to list or keep as dict? RTDB can handle dicts natively!)
    // In index.html we query `users` by `orderByChild('srn')`. That requires `users` to be a collection of nodes.
    // The keys in saptha_db.json are SRNs. So `usersRef.child(srn).set(userData)` works perfectly.
    console.log("Migrating users...");
    if (data.users) {
        await db.ref('users').set(data.users);
    }
    
    // Migrate everything else
    const collections = [
        'announcements', 'activity_announcements', 'events', 'placements',
        'sports', 'hrd_programs', 'hostel_announcements', 'hostel_info',
        'canteen_info', 'library', 'subjects', 'modules', 'module_files'
    ];
    
    for (const col of collections) {
        if (data[col]) {
            console.log(`Migrating ${col}...`);
            await db.ref(col).set(data[col]);
        }
    }
    
    console.log("Done!");
    process.exit(0);
}

migrate().catch(e => {
    console.error(e);
    process.exit(1);
});
