const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
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

// Route global context processor (Injected role metadata into global locals)
app.use((req, res, next) => {
    res.locals.user = req.session.userId ? { 
        email: req.session.userEmail, 
        role: req.session.userRole, // 'student', 'staff', 'admin'
        department: req.session.userDepartment
    } : null;
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
        
        // Dynamic Column Alterations
        pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT', (err) => {
            if (err) console.error('Error adding reset_token column:', err.message);
        });
        pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires TIMESTAMP', (err) => {
            if (err) console.error('Error adding reset_token_expires column:', err.message);
        });
        pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS year TEXT', (err) => {
            if (err) console.error('Error adding year column:', err.message);
        });
        pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS department TEXT', (err) => {
            if (err) console.error('Error adding department column:', err.message);
        });

        // Create Initial Admin Account
        const defaultAdmin = 'admin@vsb.edu';
        pool.query('SELECT * FROM users WHERE email = $1', [defaultAdmin], (err, result) => {
            if (err) return console.error(err.message);
            if (result.rows.length === 0) {
                const adminHash = bcrypt.hashSync('VSBAdminGalaxy2025', 10);
                pool.query('INSERT INTO users (email, password, role, year, department) VALUES ($1, $2, $3, $4, $5)', 
                    [defaultAdmin, adminHash, 'admin', 'N/A', 'CSE(AIML)']);
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
                    ('VSB AI & ML Research Lab Setup', 'Our division has established a new high-performance computing interface for deep learning analysis.', 'Detailed lab contents...', 'Lab Updates', 'Oct 29, 2025')`);
            }
        });
    });

    // Academic Updates Table
    pool.query(`CREATE TABLE IF NOT EXISTS academics (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        summary TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT NOT NULL,
        date TEXT NOT NULL
    )`, (err) => {
        if (err) console.error('Error creating academics table:', err.message);
        pool.query('SELECT COUNT(*) as count FROM academics', (err, result) => {
            if (err) return console.error(err.message);
            if (parseInt(result.rows[0].count) === 0) {
                pool.query(`INSERT INTO academics (title, summary, content, category, date) VALUES 
                    ('Neural Networks Semester Syllabus', 'Curriculum specifications and training patterns for third-year analytics courses.', 'Detailed syllabus documentation...', 'Academic', 'Nov 02, 2025')`);
            }
        });
    });

    // Events Table
    pool.query(`CREATE TABLE IF NOT EXISTS events (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        summary TEXT NOT NULL,
        date TEXT NOT NULL,
        location TEXT NOT NULL,
        registration_link TEXT DEFAULT '#'
    )`, (err) => {
        if (err) console.error('Error creating events table:', err.message);
        pool.query('SELECT COUNT(*) as count FROM events', (err, result) => {
            if (err) return console.error(err.message);
            if (parseInt(result.rows[0].count) === 0) {
                pool.query(`INSERT INTO events (title, summary, date, location) VALUES 
                    ('Symposium on Generative AI', 'A day-long technical workshop on LLMs and diffusion models.', 'Dec 12, 2025', 'Main Auditorium')`);
            }
        });
    });
}

// Route Protection Guards
function checkAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login?error=Access restricted. Please log in.');
    }
}

// Academics Protection Guard (Restricts to CSE(AIML) or Admin roles)
function checkAcademicAccess(req, res, next) {
    if (req.session.userId) {
        if (req.session.userRole === 'admin' || req.session.userDepartment === 'CSE(AIML)') {
            next();
        } else {
            res.status(403).send('Access denied. Academic Updates are restricted exclusively to CSE(AIML) students.');
        }
    } else {
        res.redirect('/login?error=Access restricted. Please log in.');
    }
}

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
    secure: process.env.SMTP_PORT === '465', 
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
    res.render('index');
});

// SUB-PORTAL: Events Page
app.get('/events', checkAuth, (req, res) => {
    pool.query('SELECT * FROM events ORDER BY id DESC', (err, result) => {
        const events = result ? result.rows : [];
        res.render('events', { events });
    });
});

// SUB-PORTAL: Academic Updates Page
app.get('/academics', checkAcademicAccess, (req, res) => {
    pool.query('SELECT * FROM academics ORDER BY id DESC', (err, result) => {
        const academics = result ? result.rows : [];
        res.render('academics', { academics });
    });
});

// SUB-PORTAL: Announcements Page
app.get('/announcements', checkAuth, (req, res) => {
    pool.query('SELECT * FROM blogs ORDER BY id DESC', (err, result) => {
        const announcements = result ? result.rows : [];
        res.render('announcements', { announcements });
    });
});

// Login Page
app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    const queryError = req.query.error || null;
    const querySuccess = req.query.success || null;
    res.render('login', { error: queryError, success: querySuccess });
});

// Student Sign-Up Routing (With Lowercase Normalization and Year/Dept insertions)
app.post('/register', (req, res) => {
    const { password, year, department } = req.body;
    const email = req.body.email ? req.body.email.trim().toLowerCase() : null;

    if (!email || !password || !year || !department) {
        return res.render('login', { error: 'Please populate all parameters.', success: null });
    }

    const secureHash = bcrypt.hashSync(password, 10);
    pool.query('INSERT INTO users (email, password, role, year, department) VALUES ($1, $2, $3, $4, $5)', 
        [email, secureHash, 'student', year, department], (err) => {
            if (err) {
                const warning = err.message.includes('unique') || err.message.includes('duplicate') ? 'Email structure already registered.' : 'Registration failed.';
                return res.render('login', { error: warning, success: null });
            }
            res.render('login', { error: null, success: 'VSB Student account created. Proceed to authentication.' });
        }
    );
});

// Login Handlers (With Session Mapping of role/department)
app.post('/login', (req, res) => {
    const { password } = req.body;
    const email = req.body.email ? req.body.email.trim().toLowerCase() : null;

    if (!email || !password) {
        return res.render('login', { error: 'Please enter all credentials.', success: null });
    }

    pool.query('SELECT * FROM users WHERE email = $1', [email], (err, result) => {
        let user = result && result.rows.length > 0 ? result.rows[0] : null;

        // Auto-Seed Admin Fallback
        if (!user && email === 'admin@vsb.edu' && password === 'VSBAdminGalaxy2025') {
            const adminHash = bcrypt.hashSync('VSBAdminGalaxy2025', 10);
            pool.query('INSERT INTO users (email, password, role, year, department) VALUES ($1, $2, $3, $4, $5) RETURNING *', 
                [email, adminHash, 'admin', 'N/A', 'CSE(AIML)'], (err, insertResult) => {
                    if (err || !insertResult || insertResult.rows.length === 0) {
                        return res.render('login', { error: 'Failed to auto-seed admin account.', success: null });
                    }
                    const newAdmin = insertResult.rows[0];
                    req.session.userId = newAdmin.id;
                    req.session.userEmail = newAdmin.email;
                    req.session.userRole = newAdmin.role;
                    req.session.userDepartment = newAdmin.department;
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
        req.session.userRole = user.role; // Stores 'student', 'staff', or 'admin'
        req.session.userDepartment = user.department; 

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
                console.error('Google Callback SQL Lookup Error:', err); 
                return res.redirect('/login?error=System database error.');
            }

            let user = result && result.rows.length > 0 ? result.rows[0] : null;

            if (!user) {
                // NEW USER DETECTED: Redirect them to the set-password page instead of auto-logging in
                req.session.tempGoogleEmail = email; // Store email temporarily in session
                return res.redirect('/register/google-setup');
            } else {
                // Account exists, establish session
                req.session.userId = user.id;
                req.session.userEmail = user.email;
                req.session.userRole = user.role;
                req.session.userDepartment = user.department;
                return res.redirect('/');
            }
        });

    } catch (err) {
        console.error('Google Auth Handshake Error:', err);
        res.redirect('/login?error=Security handshake crash.');
    }
});

// GET: Render the Password Setup Page for New Google Users (Pulls Year and Dept too)
app.get('/register/google-setup', (req, res) => {
    if (!req.session.tempGoogleEmail) {
        return res.redirect('/login?error=Google authentication session expired.');
    }
    res.render('google-setup', { email: req.session.tempGoogleEmail, error: null });
});

// POST: Save New Google User with Custom Password, Year and Department
app.post('/register/google-complete', (req, res) => {
    const email = req.session.tempGoogleEmail;
    const { password, year, department } = req.body;

    if (!email) {
        return res.redirect('/login?error=Google authentication session expired.');
    }
    if (!password || !year || !department) {
        return res.render('google-setup', { email, error: 'Please populate all setup parameters.' });
    }

    const secureHash = bcrypt.hashSync(password, 10);
    pool.query('INSERT INTO users (email, password, role, year, department) VALUES ($1, $2, $3, $4, $5) RETURNING *', 
        [email, secureHash, 'student', year, department], (err, result) => {
            if (err) {
                console.error('Google Complete SQL Insert Error:', err);
                return res.render('google-setup', { email, error: 'Failed to register account.' });
            }

            // Registration successful: Clear temp variable and establish login session
            delete req.session.tempGoogleEmail;
            
            const newUser = result.rows[0];
            req.session.userId = newUser.id;
            req.session.userEmail = newUser.email;
            req.session.userRole = newUser.role;
            req.session.userDepartment = newUser.department;
            return res.redirect('/');
        }
    );
});

// GET: Render the Password Recovery request page
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { error: null, success: null });
});

// POST: Generate random secure token and email the recovery link
app.post('/forgot-password', (req, res) => {
    const email = req.body.email ? req.body.email.trim().toLowerCase() : null;

    if (!email) {
        return res.render('forgot-password', { error: 'Please populate your email field.', success: null });
    }

    // Verify if email is actually registered
    pool.query('SELECT * FROM users WHERE email = $1', [email], (err, result) => {
        if (err || result.rows.length === 0) {
            return res.render('forgot-password', { error: null, success: 'If that email is registered, a password recovery link has been dispatched.' });
        }

        const resetToken = crypto.randomBytes(20).toString('hex');
        
        // Store Token & Expiration inside database (1 hour duration)
        pool.query(`UPDATE users 
                    SET reset_token = $1, reset_token_expires = NOW() + INTERVAL '1 hour' 
                    WHERE email = $2`, [resetToken, email], (err) => {
            if (err) {
                console.error('Password Reset Token Save Error:', err);
                return res.render('forgot-password', { error: 'System database error.', success: null });
            }

            // Construct Host URL depending on development vs production
            const hostUrl = req.headers.host.includes('localhost') ? `http://${req.headers.host}` : `https://${req.headers.host}`;
            const recoveryLink = `${hostUrl}/reset-password/${resetToken}`;

            const mailOptions = {
                from: `"VSB AI & ML Department" <${process.env.SMTP_USER}>`,
                to: email,
                subject: 'Secure Password Reset Link | VSB AI&ML',
                html: `<div style="font-family: Arial, sans-serif; padding: 20px; background-color: #0d081c; color: #f3f4f6; border-radius: 12px; max-w: 500px; margin: auto;">
                         <h2 style="color: #06b6d4; font-family: 'Orbitron', sans-serif; text-align: center;">Password Recovery</h2>
                         <p style="font-size: 14px; line-height: 1.6; color: #d1d5db;">You are receiving this email because you (or someone else) requested a password recovery setup for your VSB AI &amp; ML student account.</p>
                         <div style="text-align: center; margin: 30px 0;">
                           <a href="${recoveryLink}" style="background-color: #a855f7; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 14px; box-shadow: 0 0 15px rgba(168,85,247,0.4);">Reset Account Password</a>
                         </div>
                         <p style="font-size: 12px; color: #9ca3af;">If you did not request this, please ignore this email. This link will expire in 1 hour.</p>
                         <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.1); margin-top: 20px;">
                         <p style="font-size: 10px; color: #6b7280; text-align: center;">This is an automated notification from the V.S.B. AI &amp; ML Academic Portal.</p>
                       </div>`
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('SMTP Reset Send Error:', error);
                    return res.render('forgot-password', { error: 'Failed to send recovery email. Contact admin.', success: null });
                }
                res.render('forgot-password', { error: null, success: 'If that email is registered, a password recovery link has been dispatched.' });
            });
        });
    });
});

// GET: Validate token from URL and render the password replacement form
app.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;

    // Verify token exists and hasn't expired
    pool.query(`SELECT * FROM users 
                WHERE reset_token = $1 AND reset_token_expires > NOW()`, [token], (err, result) => {
        if (err || !result || result.rows.length === 0) {
            return res.redirect('/login?error=Password reset link is invalid or has expired.');
        }
        res.render('reset-password', { token, error: null });
    });
});

// POST: Execute the password override and secure the new password
app.post('/reset-password', (req, res) => {
    const { token, password } = req.body;

    if (!token || !password) {
        return res.redirect('/login?error=Password reset session expired.');
    }

    // Double check token validity
    pool.query(`SELECT * FROM users 
                WHERE reset_token = $1 AND reset_token_expires > NOW()`, [token], (err, result) => {
        if (err || !result || result.rows.length === 0) {
            return res.redirect('/login?error=Password reset link is invalid or has expired.');
        }

        const secureHash = bcrypt.hashSync(password, 10);

        // Update password and clear token
        pool.query(`UPDATE users 
                    SET password = $1, reset_token = NULL, reset_token_expires = NULL 
                    WHERE reset_token = $2`, [secureHash, token], (err) => {
            if (err) {
                console.error('Password Reset Execute Error:', err);
                return res.render('reset-password', { token, error: 'Database update failed.' });
            }
            res.redirect('/login?success=Password updated successfully. You can now login.');
        });
    });
});

// Secure Administrator Control Board
app.get('/admin', checkAdmin, (req, res) => {
    const emailSuccess = req.query.notified === 'true' ? 'Notification email dispatched to all students.' : null;
    const emailError = req.query.notified === 'error' ? 'Failed to dispatch email. Check SMTP settings.' : null;

    // Query students
    pool.query('SELECT id, email, role, year, department, created_at FROM users WHERE role = $1 ORDER BY id DESC', ['student'], (err, sResult) => {
        const students = sResult ? sResult.rows : [];
        
        // Query staff/teachers (New Query)
        pool.query('SELECT id, email, role, department, created_at FROM users WHERE role = $1 ORDER BY id DESC', ['staff'], (err, stResult) => {
            const staff = stResult ? stResult.rows : [];

            pool.query('SELECT * FROM blogs ORDER BY id DESC', (err, bResult) => {
                const blogs = bResult ? bResult.rows : [];
                
                pool.query('SELECT * FROM academics ORDER BY id DESC', (err, aResult) => {
                    const academics = aResult ? aResult.rows : [];
                    
                    pool.query('SELECT * FROM events ORDER BY id DESC', (err, eResult) => {
                        const events = eResult ? eResult.rows : [];
                        res.render('admin', { students, staff, blogs, academics, events, editBlog: null, editAcademic: null, editEvent: null, success: emailSuccess, error: emailError });
                    });
                });
            });
        });
    });
});

// CREATE STAFF: Securely register a new Staff account (Admin Protected)
app.post('/admin/staff/add', checkAdmin, (req, res) => {
    const { password, department } = req.body;
    const email = req.body.email ? req.body.email.trim().toLowerCase() : null;

    if (!email || !password || !department) {
        return res.redirect('/admin?notified=error');
    }

    const secureHash = bcrypt.hashSync(password, 10);
    // Insert into users with 'staff' role
    pool.query('INSERT INTO users (email, password, role, year, department) VALUES ($1, $2, $3, $4, $5)', 
        [email, secureHash, 'staff', 'N/A', department], (err) => {
            if (err) {
                console.error('Error creating Staff:', err.message);
                return res.redirect('/admin?notified=error');
            }
            res.redirect('/admin');
        }
    );
});

// DELETE STAFF: Securely remove staff credentials from Database (Admin Protected)
app.get('/admin/staff/delete/:id', checkAdmin, (req, res) => {
    const staffId = req.params.id;

    // Guard: Ensure we only delete staff accounts
    pool.query('DELETE FROM users WHERE id = $1 AND role = $2', [staffId, 'staff'], (err) => {
        if (err) {
            console.error('Error deleting staff:', err.message);
            return res.redirect('/admin?notified=error');
        }
        res.redirect('/admin');
    });
});

// DELETE STUDENT: Securely remove student credentials from Database (Admin Protected)
app.get('/admin/students/delete/:id', checkAdmin, (req, res) => {
    const studentId = req.params.id;

    // Guard: Ensure we only delete student accounts, not administrative accounts
    pool.query('DELETE FROM users WHERE id = $1 AND role = $2', [studentId, 'student'], (err) => {
        if (err) {
            console.error('Error deleting student:', err.message);
            return res.redirect('/admin?notified=error');
        }
        res.redirect('/admin');
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
            bcc: studentEmails.join(','), 
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

// --- ADMIN MULTI-TABLE CRUD HANDLERS ---

// CREATE Announcements
app.post('/admin/blogs/add', checkAdmin, (req, res) => {
    const { title, summary, content, category } = req.body;
    const dateFormatted = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    pool.query('INSERT INTO blogs (title, summary, content, category, date) VALUES ($1, $2, $3, $4, $5)', [title, summary, content, category, dateFormatted], () => res.redirect('/admin'));
});

// UPDATE Announcements
app.post('/admin/blogs/update/:id', checkAdmin, (req, res) => {
    const { title, summary, content, category } = req.body;
    pool.query('UPDATE blogs SET title = $1, summary = $2, content = $3, category = $4 WHERE id = $5', [title, summary, content, category, req.params.id], () => res.redirect('/admin'));
});

// DELETE Announcements
app.get('/admin/blogs/delete/:id', checkAdmin, (req, res) => {
    pool.query('DELETE FROM blogs WHERE id = $1', [req.params.id], () => res.redirect('/admin'));
});

// CREATE Academics
app.post('/admin/academics/add', checkAdmin, (req, res) => {
    const { title, summary, content, category } = req.body;
    const dateFormatted = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    pool.query('INSERT INTO academics (title, summary, content, category, date) VALUES ($1, $2, $3, $4, $5)', [title, summary, content, category, dateFormatted], () => res.redirect('/admin'));
});

// UPDATE Academics
app.post('/admin/academics/update/:id', checkAdmin, (req, res) => {
    const { title, summary, content, category } = req.body;
    pool.query('UPDATE academics SET title = $1, summary = $2, content = $3, category = $4 WHERE id = $5', [title, summary, content, category, req.params.id], () => res.redirect('/admin'));
});

// DELETE Academics
app.get('/admin/academics/delete/:id', checkAdmin, (req, res) => {
    pool.query('DELETE FROM academics WHERE id = $1', [req.params.id], () => res.redirect('/admin'));
});

// CREATE Events
app.post('/admin/events/add', checkAdmin, (req, res) => {
    const { title, summary, date, location, registration_link } = req.body;
    pool.query('INSERT INTO events (title, summary, date, location, registration_link) VALUES ($1, $2, $3, $4, $5)', [title, summary, date, location, registration_link || '#'], () => res.redirect('/admin'));
});

// UPDATE Events
app.post('/admin/events/update/:id', checkAdmin, (req, res) => {
    const { title, summary, date, location, registration_link } = req.body;
    pool.query('UPDATE events SET title = $1, summary = $2, date = $3, location = $4, registration_link = $5 WHERE id = $6', [title, summary, date, location, registration_link || '#', req.params.id], () => res.redirect('/admin'));
});

// DELETE Events
app.get('/admin/events/delete/:id', checkAdmin, (req, res) => {
    pool.query('DELETE FROM events WHERE id = $1', [req.params.id], () => res.redirect('/admin'));
});

app.listen(PORT, () => {
    console.log(`VSB Portal is running on port ${PORT}`);
});