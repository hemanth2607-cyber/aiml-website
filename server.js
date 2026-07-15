const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg'); // Changed from sqlite3 to pg
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Setup PostgreSQL Connection Pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL, // Injected via environment variables
    ssl: {
        rejectUnauthorized: false // Required for serverless hosting providers like Neon/Supabase
    }
});

// Test connection and initialize tables
pool.connect((err, client, release) => {
    if (err) {
        return console.error('Error acquiring client', err.stack);
    }
    console.log('Successfully connected to PostgreSQL database.');
    verifyDatabaseTables();
    release();
});

function verifyDatabaseTables() {
    // Users Table (Changed INTEGER PRIMARY KEY AUTOINCREMENT to SERIAL PRIMARY KEY)
    pool.query(`CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'student',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) console.error('Error creating users table:', err.message);
        
        // Create Initial Admin Account
        const defaultAdmin = 'admin@vsb.edu';
        pool.query('SELECT * FROM users WHERE email = $1', [defaultAdmin], (err, result) => {
            if (err) return console.error(err.message);
            if (result.rows.length === 0) {
                const adminHash = bcrypt.hashSync('VSBAdminGalaxy2025', 10);
                pool.query('INSERT INTO users (email, password, role) VALUES ($1, $2, $3)', [defaultAdmin, adminHash, 'admin']);
            }
        });
    });

    // Dynamic Blog / Department Updates Table
    pool.query(`CREATE TABLE IF NOT EXISTS blogs (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        summary TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT NOT NULL,
        date TEXT NOT NULL
    )`, (err) => {
        if (err) console.error('Error creating blogs table:', err.message);

        // Add VSB Departmental Default Content
        pool.query('SELECT COUNT(*) as count FROM blogs', (err, result) => {
            if (err) return console.error(err.message);
            const count = parseInt(result.rows[0].count);
            if (count === 0) {
                pool.query(`INSERT INTO blogs (title, summary, content, category, date) VALUES 
                    ('VSB AI & ML Research Lab Setup', 'Our division has established a new high-performance computing interface for deep learning analysis.', 'Detailed lab contents...', 'Lab Updates', 'Oct 29, 2025'),
                    ('Neural Networks Semester Syllabus', 'Curriculum specifications and training patterns for third-year analytics courses.', 'Detailed syllabus documentation...', 'Academic', 'Nov 02, 2025')
                `);
            }
        });
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
    pool.query('SELECT * FROM blogs ORDER BY id DESC', (err, result) => {
        const blogs = result ? result.rows : [];
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
    pool.query('INSERT INTO users (email, password, role) VALUES ($1, $2, $3)', [email, secureHash, 'student'], (err) => {
        if (err) {
            const warning = err.message.includes('unique') || err.message.includes('duplicate') ? 'Email structure already registered.' : 'Registration failed.';
            return res.render('login', { error: warning, success: null });
        }
        res.render('login', { error: null, success: 'VSB Student account created. Proceed to authentication.' });
    });
});

// Login Handlers
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    pool.query('SELECT * FROM users WHERE email = $1', [email], (err, result) => {
        const user = result && result.rows.length > 0 ? result.rows[0] : null;
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
    pool.query('SELECT id, email, role, created_at FROM users WHERE role = $1 ORDER BY id DESC', ['student'], (err, sResult) => {
        const students = sResult ? sResult.rows : [];
        
        pool.query('SELECT * FROM blogs ORDER BY id DESC', (err, bResult) => {
            const blogs = bResult ? bResult.rows : [];
            res.render('admin', { students, blogs, editBlog: null });
        });
    });
});

// Pull individual post for inline update rendering
app.get('/admin/edit/:id', checkAdmin, (req, res) => {
    const blogId = req.params.id;
    pool.query('SELECT id, email, role, created_at FROM users WHERE role = $1 ORDER BY id DESC', ['student'], (err, sResult) => {
        const students = sResult ? sResult.rows : [];
        
        pool.query('SELECT * FROM blogs ORDER BY id DESC', (err, bResult) => {
            const blogs = bResult ? bResult.rows : [];
            
            pool.query('SELECT * FROM blogs WHERE id = $1', [blogId], (err, editResult) => {
                const editBlog = editResult && editResult.rows.length > 0 ? editResult.rows[0] : null;
                res.render('admin', { students, blogs, editBlog });
            });
        });
    });
});

// CREATE: Write new departmental update
app.post('/admin/blogs/add', checkAdmin, (req, res) => {
    const { title, summary, content, category } = req.body;
    const dateFormatted = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    
    pool.query('INSERT INTO blogs (title, summary, content, category, date) VALUES ($1, $2, $3, $4, $5)', 
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

    pool.query('UPDATE blogs SET title = $1, summary = $2, content = $3, category = $4 WHERE id = $5', 
        [title, summary, content, category, blogId], (err) => {
            if (err) console.error(err.message);
            res.redirect('/admin');
        }
    );
});

// DELETE: Remove updates from system indexes
app.get('/admin/blogs/delete/:id', checkAdmin, (req, res) => {
    const blogId = req.params.id;
    pool.query('DELETE FROM blogs WHERE id = $1', [blogId], (err) => {
        if (err) console.error(err.message);
        res.redirect('/admin');
    });
});

app.listen(PORT, () => {
    console.log(`VSB Portal is running on port ${PORT}`);
});