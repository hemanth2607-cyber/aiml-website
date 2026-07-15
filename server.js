const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Setup Database Connections
const db = new sqlite3.Database('./vsb_galaxy_dept.db', (err) => {
    if (err) {
        console.error('Database instantiation failure:', err.message);
    } else {
        console.log('Connected to VSB Department SQLite database.');
        verifyDatabaseTables();
    }
});

function verifyDatabaseTables() {
    // Users Table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'student',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Create Initial Admin Account
    const defaultAdmin = 'admin@vsb.edu';
    db.get('SELECT * FROM users WHERE email = ?', [defaultAdmin], (err, row) => {
        if (!row) {
            const adminHash = bcrypt.hashSync('VSBAdminGalaxy2025', 10);
            db.run('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', [defaultAdmin, adminHash, 'admin']);
        }
    });

    // Dynamic Blog / Department Updates Table
    db.run(`CREATE TABLE IF NOT EXISTS blogs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        summary TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT NOT NULL,
        date TEXT NOT NULL
    )`);

    // Add VSB Departmental Default Content
    db.get('SELECT COUNT(*) as count FROM blogs', (err, row) => {
        if (row && row.count === 0) {
            db.run(`INSERT INTO blogs (title, summary, content, category, date) VALUES 
                ('VSB AI & ML Research Lab Setup', 'Our division has established a new high-performance computing interface for deep learning analysis.', 'Detailed lab contents...', 'Lab Updates', 'Oct 29, 2025'),
                ('Neural Networks Semester Syllabus', 'Curriculum specifications and training patterns for third-year analytics courses.', 'Detailed syllabus documentation...', 'Academic', 'Nov 02, 2025')
            `);
        }
    });
}

// Config Modules
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session Engine Configuration
app.use(session({
    secret: 'vsb_cosmic_security_hashkey',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to true if running over HTTPS
        maxAge: 1000 * 60 * 60 * 3 
    }
}));

// Route global context processor
app.use((req, res, next) => {
    res.locals.user = req.session.userId ? { email: req.session.userEmail, role: req.session.userRole } : null;
    next();
});

// Admin Route Guards
function checkAdmin(req, res, next) {
    if (req.session.userId && req.session.userRole === 'admin') {
        next();
    } else {
        res.status(403).send('Access denied. Administrator privileges required.');
    }
}

// --- PORTAL ENDPOINTS ---

// Home Page
app.get('/', (req, res) => {
    db.all('SELECT * FROM blogs ORDER BY id DESC', [], (err, blogs) => {
        if (err) blogs = [];
        res.render('index', { blogs });
    });
});

// Login Page
app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    res.render('login', { error: null, success: null });
});

// Student Sign-Up Routing
app.post('/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.render('login', { error: 'Please populate all parameters.', success: null });
    }

    const secureHash = bcrypt.hashSync(password, 10);
    db.run('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', [email, secureHash, 'student'], (err) => {
        if (err) {
            const warning = err.message.includes('UNIQUE') ? 'Email structure already registered.' : 'Registration failed.';
            return res.render('login', { error: warning, success: null });
        }
        res.render('login', { error: null, success: 'VSB Student account created. Proceed to authentication.' });
    });
});

// Login Handlers
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err || !user) {
            return res.render('login', { error: 'Invalid authentication credentials.', success: null });
        }

        const validPassword = bcrypt.compareSync(password, user.password);
        if (!validPassword) {
            return res.render('login', { error: 'Invalid authentication credentials.', success: null });
        }

        req.session.userId = user.id;
        req.session.userEmail = user.email;
        req.session.userRole = user.role;

        if (user.role === 'admin') {
            res.redirect('/admin');
        } else {
            res.redirect('/');
        }
    });
});

// Terminate Session
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

// Secure Administrator Control Board
app.get('/admin', checkAdmin, (req, res) => {
    db.all('SELECT id, email, role, created_at FROM users WHERE role = ? ORDER BY id DESC', ['student'], (err, students) => {
        if (err) students = [];
        
        db.all('SELECT * FROM blogs ORDER BY id DESC', [], (err, blogs) => {
            if (err) blogs = [];
            res.render('admin', { students, blogs, editBlog: null });
        });
    });
});

// Pull individual post for inline update rendering
app.get('/admin/edit/:id', checkAdmin, (req, res) => {
    const blogId = req.params.id;
    db.all('SELECT id, email, role, created_at FROM users WHERE role = ? ORDER BY id DESC', ['student'], (err, students) => {
        if (err) students = [];
        
        db.all('SELECT * FROM blogs ORDER BY id DESC', [], (err, blogs) => {
            if (err) blogs = [];
            
            db.get('SELECT * FROM blogs WHERE id = ?', [blogId], (err, editBlog) => {
                res.render('admin', { students, blogs, editBlog: editBlog || null });
            });
        });
    });
});

// CREATE: Write new departmental update
app.post('/admin/blogs/add', checkAdmin, (req, res) => {
    const { title, summary, content, category } = req.body;
    const dateFormatted = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    
    db.run('INSERT INTO blogs (title, summary, content, category, date) VALUES (?, ?, ?, ?, ?)', 
        [title, summary, content, category, dateFormatted], (err) => {
            if (err) console.error(err.message);
            res.redirect('/admin');
        }
    );
});

// UPDATE: Modify departmental updates
app.post('/admin/blogs/update/:id', checkAdmin, (req, res) => {
    const { title, summary, content, category } = req.body;
    const blogId = req.params.id;

    db.run('UPDATE blogs SET title = ?, summary = ?, content = ?, category = ? WHERE id = ?', 
        [title, summary, content, category, blogId], (err) => {
            if (err) console.error(err.message);
            res.redirect('/admin');
        }
    );
});

// DELETE: Remove updates from system indexes
app.get('/admin/blogs/delete/:id', checkAdmin, (req, res) => {
    const blogId = req.params.id;
    db.run('DELETE FROM blogs WHERE id = ?', [blogId], (err) => {
        if (err) console.error(err.message);
        res.redirect('/admin');
    });
});

app.listen(PORT, () => {
    console.log(`VSB Portal is running on http://localhost:${PORT}`);
});