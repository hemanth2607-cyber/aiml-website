const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ========================================================================
// 1. SET EXPRESS CONFIGURATIONS IMMEDIATELY (Before database & routes)
// ========================================================================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
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

// ========================================================================
// 2. SETUP DATABASE CONNECTION POOL
// ========================================================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
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
    // Users Table
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

// Admin Route Guards
function checkAdmin(req, res, next) {
    if (req.session.userId && req.session.userRole === 'admin') {
        next();
    } else {
        res.status(403).send('Access denied. Administrator privileges required.');
    }
}

// Setup Nodemailer SMTP Transporter
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_PORT === '465', // true for 465, false for 587
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// ========================================================================
// 3. PORTAL ENDPOINTS
// ========================================================================

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
    const queryError = req.query.error || null;
    res.render('login', { error: queryError, success: null });
});

// Student Sign-Up Routing (With Lowercase Normalization)
app.post('/register', (req, res) => {
    const { password } = req.body;
    const email = req.body.email ? req.body.email.trim().toLowerCase() : null;

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

// Login Handlers (With Lowercase Normalization and Auto-Seed Admin Fallback)
app.post('/login', (req, res) => {
    const { password } = req.body;
    const email = req.body.email ? req.body.email.trim().toLowerCase() : null;

    if (!email || !password) {
        return res.render('login', { error: 'Please enter all credentials.', success: null });
    }

    pool.query('SELECT * FROM users WHERE email = $1', [email], (err, result) => {
        let user = result && result.rows.length > 0 ? result.rows[0] : null;

        // Auto-Seed Admin Fallback: If admin is missing, generate it immediately
        if (!user && email === 'admin@vsb.edu' && password === 'VSBAdminGalaxy2025') {
            const adminHash = bcrypt.hashSync('VSBAdminGalaxy2025', 10);
            pool.query('INSERT INTO users (email, password, role) VALUES ($1, $2, $3) RETURNING *', 
                [email, adminHash, 'admin'], (err, insertResult) => {
                    if (err || !insertResult || insertResult.rows.length === 0) {
                        return res.render('login', { error: 'Failed to auto-seed admin account.', success: null });
                    }
                    const newAdmin = insertResult.rows[0];
                    req.session.userId = newAdmin.id;
                    req.session.userEmail = newAdmin.email;
                    req.session.userRole = newAdmin.role;
                    return res.redirect('/admin');
                }
            );
            return;
        }

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

// ========================================================================
// 4. GOOGLE OAUTH 2.0 CHANNELS (Nodemailer and Fetch compatible)
// ========================================================================

// Redirect to Google Authentication Screen
app.get('/auth/google', (req, res) => {
    const rootUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
    const options = {
        redirect_uri: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/auth/google/callback',
        client_id: process.env.GOOGLE_CLIENT_ID,
        access_type: 'offline',
        response_type: 'code',
        prompt: 'consent',
        scope: [
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email'
        ].join(' ')
    };
    const queryString = new URLSearchParams(options).toString();
    res.redirect(`${rootUrl}?${queryString}`);
});

// Capture Callback Code and Authenticate User (With Casing Normalization & Logging)
app.get('/auth/google/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.redirect('/login?error=Google authentication aborted.');

    try {
        // Exchange Code for Access Token
        const tokenUrl = 'https://oauth2.googleapis.com/token';
        const values = {
            code,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            redirect_uri: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/auth/google/callback',
            grant_type: 'authorization_code'
        };

        const response = await fetch(tokenUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams(values).toString()
        });
        
        const tokenData = await response.json();
        if (!tokenData.access_token) {
            return res.redirect('/login?error=Google security token rejected.');
        }

        // Fetch User profile metadata
        const userResponse = await fetch(`https://www.googleapis.com/oauth2/v3/userinfo?access_token=${tokenData.access_token}`);
        const googleUser = await userResponse.json();

        if (!googleUser.email) {
            return res.redirect('/login?error=Email address missing from Google profile.');
        }

        // Normalize email to lowercase
        const email = googleUser.email.trim().toLowerCase();

        // Check if student identity exists
        pool.query('SELECT * FROM users WHERE email = $1', [email], (err, result) => {
            if (err) {
                console.error('Google Callback SQL Lookup Error:', err); // Logs exact error details to Vercel Console
                return res.redirect('/login?error=System database error.');
            }

            let user = result && result.rows.length > 0 ? result.rows[0] : null;

            if (!user) {
                // If first time logging in, register them automatically
                const dummyPassword = bcrypt.hashSync(Math.random().toString(36), 10);
                pool.query('INSERT INTO users (email, password, role) VALUES ($1, $2, $3) RETURNING *', 
                    [email, dummyPassword, 'student'], (err, insertResult) => {
                        if (err) {
                            console.error('Google Callback SQL Insert Error:', err);
                            return res.redirect('/login?error=Registration failed.');
                        }
                        const newUser = insertResult.rows[0];
                        req.session.userId = newUser.id;
                        req.session.userEmail = newUser.email;
                        req.session.userRole = newUser.role;
                        return res.redirect('/');
                    }
                );
            } else {
                // Account exists, establish session
                req.session.userId = user.id;
                req.session.userEmail = user.email;
                req.session.userRole = user.role;
                return res.redirect('/');
            }
        });

    } catch (err) {
        console.error('Google Auth Handshake Error:', err);
        res.redirect('/login?error=Security handshake crash.');
    }
});

// Terminate Session
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

// Secure Administrator Control Board
app.get('/admin', checkAdmin, (req, res) => {
    const emailSuccess = req.query.notified === 'true' ? 'Notification email dispatched to all students.' : null;
    const emailError = req.query.notified === 'error' ? 'Failed to dispatch email. Check SMTP settings.' : null;

    pool.query('SELECT id, email, role, created_at FROM users WHERE role = $1 ORDER BY id DESC', ['student'], (err, sResult) => {
        const students = sResult ? sResult.rows : [];
        
        pool.query('SELECT * FROM blogs ORDER BY id DESC', (err, bResult) => {
            const blogs = bResult ? bResult.rows : [];
            res.render('admin', { students, blogs, editBlog: null, success: emailSuccess, error: emailError });
        });
    });
});

// Send Email Announcements to All Registered Students (BCC protected)
app.post('/admin/notify', checkAdmin, (req, res) => {
    const { subject, message } = req.body;

    // Fetch all registered student emails
    pool.query('SELECT email FROM users WHERE role = $1', ['student'], (err, result) => {
        if (err || result.rows.length === 0) {
            return res.redirect('/admin?notified=error');
        }

        const studentEmails = result.rows.map(row => row.email);

        const mailOptions = {
            from: `"VSB AI & ML Department" <${process.env.SMTP_USER}>`,
            bcc: studentEmails.join(','), // Send in BCC field to secure student privacy
            subject: subject,
            text: message,
            html: `<div style="font-family: Arial, sans-serif; padding: 20px; background-color: #0d081c; color: #f3f4f6; border-radius: 12px;">
                     <h2 style="color: #06b6d4; font-family: 'Orbitron', sans-serif;">VSB Department Announcement</h2>
                     <p style="font-size: 14px; line-height: 1.6; color: #d1d5db;">${message.replace(/\n/g, '<br>')}</p>
                     <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.1); margin-top: 20px;">
                     <p style="font-size: 11px; color: #9ca3af;">This is an automated notification from the V.S.B. AI &amp; ML Academic Portal.</p>
                   </div>`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('SMTP Error:', error);
                return res.redirect('/admin?notified=error');
            }
            res.redirect('/admin?notified=true');
        });
    });
});

// Pull individual post for inline update rendering
app.get('/admin/edit/:id', checkAdmin, (req, res) => {
    pool.query('SELECT id, email, role, created_at FROM users WHERE role = $1 ORDER BY id DESC', ['student'], (err, sResult) => {
        const students = sResult ? sResult.rows : [];
        
        pool.query('SELECT * FROM blogs ORDER BY id DESC', (err, bResult) => {
            const blogs = bResult ? bResult.rows : [];
            
            pool.query('SELECT * FROM blogs WHERE id = $1', [req.params.id], (err, editResult) => {
                const editBlog = editResult && editResult.rows.length > 0 ? editResult.rows[0] : null;
                res.render('admin', { students, blogs, editBlog, success: null, error: null });
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