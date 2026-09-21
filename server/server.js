// fs - let us read files, such as certificates, HTML, CSS..
// https - Node.js module used to create the HTTPS server.

const https = require('https');
const fs = require('fs');
const path = require('path');
const {ASSESSMENT} = require('./questions');

const PORT = 8443;
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// key - server private key
// cert - server certificate
// CA certificate
// requestCert makes the server ask the browser for a client certificate
// rejectUnauthorized - don't automatically reject the connection
const options = {
    key: fs.readFileSync(path.join(__dirname, '..', 'pki', 'server', 'server.key')),
    cert: fs.readFileSync(path.join(__dirname, '..', 'pki', 'server', 'server.crt')),
    ca: fs.readFileSync(path.join(__dirname, '..', 'pki', 'ca', 'ca.crt')),
    requestCert: true,
    rejectUnauthorized: false,
};

const CONTENT_TYPES = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
};

// Security headers:
// X-Frame-Options -> Prevents your pages from being displayed inside an iframe (against clickjacking)
// X-Content-Type-Options -> Tells the browser to do not try to guess a different file type.
// Strict-Transport-Security -> Tells the browser to use HTTPS for future requests to this site.
// CSP -> Only load resources from this application itself unless explicitly allowed.
// Referrer Policy -> Prevents the browser from sending the previous URL as a Referer header.
function setSecurityHeaders(res) {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('Referrer-Policy', 'no-referrer');
}

// Show a simple error message to the user, but keep the detailed
// error in the server console. This avoids exposing internal
// information such as file paths or other implementation details.
function safeError(res, statusCode, publicMessage, internalError) {
    if (internalError) {
        console.error(`[${new Date().toISOString()}] Internal error:`, internalError);
    }
    res.writeHead(statusCode, {'Content-Type': 'text/plain'});
    res.end(publicMessage + '\n');
}

// protection against path traversal
function resolveSafePath(requestedUrl) {
    const resolvedPath = path.normalize(path.join(PUBLIC_DIR, requestedUrl));
    if (!resolvedPath.startsWith(PUBLIC_DIR)) return null;
    return resolvedPath;
}

// We use the certificate subject to identify
// the user and determine whether they are a teacher or a student.
function getIdentity(req) {
    if (!req.socket.authorized) return null;
    const cert = req.socket.getPeerCertificate();
    if (!cert || !cert.subject) return null;

    const cn = cert.subject.CN || 'Unknown User';
    const ouRaw = cert.subject.OU || '';
    const issuer = (cert.issuer && cert.issuer.CN) || 'Unknown Issuer';
    const role = ouRaw.toLowerCase().includes('teacher') || cn.toLowerCase().includes('teacher')
        ? 'teacher'
        : 'student';

    return {cn, ou: ouRaw, role, issuer};
}

// XSS protection - escape special HTML characters before putting user or certificate
// data into generated HTML. This prevents the value from being
// interpreted as HTML or JavaScript by the browser
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// In-memory array for the Teacher "Review Results" view.
const submittedResults = [];

// Small set of SVG icons used by the pages.
// Keeping them here means we don't need an external icon library.
function icon(name) {
    const icons = {
        shieldCheck: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 9 8 11 4.6-2 8-6 8-11V5l-8-3Z"/><path d="m9 12 2 2 4-4"/></svg>`,
        graduationCap: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 10 12 5 2 10l10 5 10-5Z"/><path d="M6 12v5c0 1.7 2.7 3 6 3s6-1.3 6-3v-5"/></svg>`,
        briefcase: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>`,
        lock: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>`,
        clipboardList: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="12" height="16" rx="2"/><path d="M9 2h6v4H9z"/><path d="M9 11h6M9 15h4"/></svg>`,
        chevronRight: `<svg class="icon icon-inline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6 6 6-6 6"/></svg>`,
        info: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>`,
        trash: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6"/></svg>`,
    };
    return icons[name] || '';
}


// Shared page shell - wraps every page in the same navbar/footer.
function pageShell(title, identity, bodyHtml) {

    const roleClass = identity ? `role-${identity.role}` : 'role-none';
    const identityBadge = identity
        ? `<div class="nav-identity">
         <span class="nav-identity-name">${escapeHtml(identity.cn)}</span>
         <span class="role-pill role-pill--${identity.role}">${identity.role}</span>
       </div>`
        : `<div class="nav-identity nav-identity--none">${icon('lock')}<span>Not authenticated</span></div>`;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - Assessment System</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body class="${roleClass}">
  <nav class="navbar">
    <a class="navbar-brand" href="/">${icon('shieldCheck')} Assessment System</a>
    <div class="navbar-links">
      <a href="/about">${icon('info')} About &amp; Security</a>
      ${identityBadge}
    </div>
  </nav>
  <main class="page-body">
    ${bodyHtml}
  </main>
  <footer class="site-footer">
    <p>${icon('lock')} Authenticated via X.509 client certificate.</p>
  </footer>
</body>
</html>`;
}

// displays certificate status
function certPanel(identity) {
    if (!identity) {
        return `
    <div class="cert-panel cert-panel--error">
      <div class="cert-panel-icon">${icon('lock')}</div>
      <div>
        <h3>Certificate Authentication Failed</h3>
        <p>No valid client certificate was presented during the TLS handshake.</p>
      </div>
    </div>`;
    }
    return `
    <div class="cert-panel">
      <div class="cert-panel-icon">${icon('shieldCheck')}</div>
      <div>
        <h3>Certificate Verified</h3>
        <dl class="cert-detail-list">
          <dt>Identity</dt><dd>${escapeHtml(identity.cn)}</dd>
          <dt>Role</dt><dd><span class="role-pill role-pill--${identity.role}">${identity.role}</span></dd>
          <dt>Issued by</dt><dd>${escapeHtml(identity.issuer)}</dd>
          <dt>Status</dt><dd><span class="status-ok">Authenticated</span></dd>
        </dl>
      </div>
    </div>`;
}


function renderLoginPage(identity) {
    const body = `
    <section class="hero">
      <h1>Certificate-Based Login</h1>
      <p class="hero-subtitle">This system authenticates users with an X.509 client certificate instead of a username and password. Your identity is verified during the TLS handshake, before any page is even requested.</p>
    </section>
    ${certPanel(identity)}
    ${identity
        ? `<div><a class="btn btn-primary" href="/dashboard">Continue to Dashboard ${icon('chevronRight')}</a></div>`
        : `<div class="card login-help">
           <h3>No certificate detected</h3>
           <p>If your browser has a client certificate installed and trusted, it should be offered automatically. If not, install the provided <code>.pfx</code> file into your browser or OS certificate store, then reload this page.</p>
         </div>`}
  `;
    return pageShell('Login', identity, body);
}

function renderErrorPage(identity, code, message) {
    const body = `
    <section class="card error-card">
      <div class="alert alert-error"><strong>${code} - Access Denied</strong><p>${escapeHtml(message)}</p></div>
      <a class="btn btn-secondary" href="/">${icon('chevronRight')} Back to Login</a>
    </section>`;
    return pageShell('Access Denied', identity, body);
}

// the certificate role controls which dashboard is displayed
function renderDashboardPage(identity) {
    return identity.role === 'teacher' ? renderTeacherDashboard(identity) : renderStudentDashboard(identity);
}


function renderStudentDashboard(identity) {
    const body = `
    <section class="dashboard-header">
      <h1>${icon('graduationCap')} Student Dashboard</h1>
      <p>Welcome back, <strong>${escapeHtml(identity.cn)}</strong>.</p>
    </section>
    ${certPanel(identity)}
    <section class="section-block">
      <h2>Available Assessments</h2>
      <div class="assessment-grid">
        <div class="assessment-card">
          <div class="assessment-card-header">
            <h3>${escapeHtml(ASSESSMENT.title)}</h3>
            <span class="badge badge-available">Available</span>
          </div>
          <p class="assessment-meta">${icon('clipboardList')} ${ASSESSMENT.questions.length} questions &middot; Multiple choice</p>
          <a class="btn btn-primary btn-block" href="/assessment">Start Assessment ${icon('chevronRight')}</a>
        </div>
      </div>
    </section>`;
    return pageShell('Dashboard', identity, body);
}

function renderTeacherDashboard(identity) {
    const recent = submittedResults.slice(-5).reverse();
    const rows = recent.length
        ? recent.map(r => `
        <tr>
          <td>${escapeHtml(r.studentName)}</td>
          <td>${r.score}/${r.total}</td>
          <td>${new Date(r.timestamp).toLocaleString()}</td>
        </tr>`).join('')
        : `<tr><td colspan="3" class="empty-row">No submissions yet in this session.</td></tr>`;

    const body = `
    <section class="dashboard-header">
      <h1>${icon('briefcase')} Teacher Dashboard</h1>
      <p>Welcome, <strong>${escapeHtml(identity.cn)}</strong>.</p>
    </section>
    ${certPanel(identity)}
    <section class="section-block">
      <h2>Manage Assessments</h2>
      <div class="assessment-grid">
        <div class="assessment-card">
          <div class="assessment-card-header">
            <h3>${escapeHtml(ASSESSMENT.title)}</h3>
            <span class="badge badge-manage">${ASSESSMENT.questions.length} questions</span>
          </div>
          <p class="assessment-meta">${icon('clipboardList')} Add, edit, or remove questions</p>
          <a class="btn btn-primary btn-block" href="/manage">Manage Questions ${icon('chevronRight')}</a>
        </div>
      </div>
    </section>
    <section class="section-block">
      <h2>Review Results</h2>
      <table class="results-table">
        <thead><tr><th>Student</th><th>Score</th><th>Submitted</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </section>`;
    return pageShell('Dashboard', identity, body);
}

function renderAssessmentPage(identity) {
    const questionsHtml = ASSESSMENT.questions.map((q, i) => `
    <fieldset class="question-block">
      <legend><span class="question-number">Q${i + 1}</span> ${escapeHtml(q.prompt)}</legend>
      <div class="choice-list">
        ${q.choices.map((choice, ci) => `
          <label class="choice-label">
            <input type="radio" name="${q.id}" value="${ci}" required>
            <span>${escapeHtml(choice)}</span>
          </label>`).join('')}
      </div>
    </fieldset>`).join('');

    const body = `
    <section class="dashboard-header">
      <h1>${icon('clipboardList')} ${escapeHtml(ASSESSMENT.title)}</h1>
      <p>${escapeHtml(ASSESSMENT.instructions)}</p>
    </section>
    <form method="POST" action="/assessment/submit" class="assessment-form">
      ${questionsHtml}
      <button type="submit" class="btn btn-primary btn-block">Submit Assessment ${icon('chevronRight')}</button>
    </form>`;
    return pageShell('Assessment', identity, body);
}

function renderResultsPage(identity, score, total) {
    const percent = Math.round((score / total) * 100);
    const passed = percent >= 70;
    const body = `
    <section class="results-card">
      <div class="results-icon ${passed ? 'results-icon--pass' : 'results-icon--fail'}">${icon(passed ? 'shieldCheck' : 'lock')}</div>
      <h1>Assessment Results</h1>
      <p class="results-score">${score} / ${total} correct</p>
      <p class="results-percent">${percent}%</p>
      <div class="alert ${passed ? 'alert-success' : 'alert-error'}">
        ${passed ? 'Well done - you passed this assessment.' : 'You did not reach the passing threshold this time.'}
      </div>
      <a class="btn btn-primary" href="/dashboard">${icon('chevronRight')} Return to Dashboard</a>
    </section>`;
    return pageShell('Results', identity, body);
}


function renderManagePage(identity, errorMessage) {
    const errorHtml = errorMessage
        ? `<div class="alert alert-error"><strong>Could not save:</strong> ${escapeHtml(errorMessage)}</div>`
        : '';

    const questionCards = ASSESSMENT.questions.map((q, idx) => `
    <div class="manage-question-card">
      <form method="POST" action="/manage/save-question" class="manage-form">
        <input type="hidden" name="qid" value="${escapeHtml(q.id)}">
        <label>Question ${idx + 1} text
          <input type="text" name="prompt" value="${escapeHtml(q.prompt)}" required>
        </label>
        <div class="manage-choices">
          ${q.choices.map((c, ci) => `
            <label class="manage-choice-row">
              <input type="radio" name="correct" value="${ci}" ${ci === q.correctIndex ? 'checked' : ''} required>
              <input type="text" name="choice${ci}" value="${escapeHtml(c)}" required>
            </label>`).join('')}
        </div>
        <p class="manage-hint">Select the radio button next to the correct answer.</p>
        <div class="manage-actions">
          <button type="submit" class="btn btn-primary btn-small">Save Changes</button>
        </div>
      </form>
      <form method="POST" action="/manage/delete-question" class="manage-delete-form"
            onsubmit="return confirm('Delete this question? This cannot be undone.');">
        <input type="hidden" name="qid" value="${escapeHtml(q.id)}">
        <button type="submit" class="btn btn-danger btn-small">${icon('trash')} Delete</button>
      </form>
    </div>`).join('');

    const addForm = `
    <div class="manage-question-card manage-question-card--new">
      <h3>Add New Question</h3>
      <form method="POST" action="/manage/add-question" class="manage-form">
        <label>Question text
          <input type="text" name="prompt" placeholder="Enter the question text" required>
        </label>
        <div class="manage-choices">
          ${[0, 1, 2, 3].map(ci => `
            <label class="manage-choice-row">
              <input type="radio" name="correct" value="${ci}" ${ci === 0 ? 'checked' : ''} required>
              <input type="text" name="choice${ci}" placeholder="Choice ${ci + 1}" required>
            </label>`).join('')}
        </div>
        <p class="manage-hint">Select the radio button next to the correct answer.</p>
        <div class="manage-actions">
          <button type="submit" class="btn btn-primary btn-small">Add Question</button>
        </div>
      </form>
    </div>`;

    const body = `
    <section class="dashboard-header">
      <h1>${icon('clipboardList')} Manage Assessment Questions</h1>
      <p>Editing: <strong>${escapeHtml(ASSESSMENT.title)}</strong></p>
    </section>
    ${errorHtml}
    <div class="manage-list">
      ${questionCards}
    </div>
    ${addForm}
    <a class="btn btn-secondary" href="/dashboard">${icon('chevronRight')} Back to Dashboard</a>
  `;
    return pageShell('Manage Assessment', identity, body);
}


function validateQuestionInput(fields) {
    const prompt = (fields.prompt || '').trim();
    const choices = [0, 1, 2, 3].map(i => (fields['choice' + i] || '').trim());
    const correctIndex = parseInt(fields.correct, 10);

    if (!prompt) {
        return {valid: false, error: 'Question text cannot be empty.'};
    }
    if (choices.some(c => c.length === 0)) {
        return {valid: false, error: 'All four answer choices must be filled in.'};
    }
    if (isNaN(correctIndex) || correctIndex < 0 || correctIndex > 3) {
        return {valid: false, error: 'You must select which choice is correct.'};
    }
    return {valid: true, prompt, choices, correctIndex};
}


// Read the submitted form data and turn it into a simple JavaScript object.
// The size limit prevents someone from sending an unnecessarily large request.
function parseFormBody(req, callback) {
    let body = '';
    req.on('data', chunk => {
        body += chunk;
        if (body.length > 1e6) req.destroy();
    });
    req.on('end', () => {
        const params = new URLSearchParams(body);
        const result = {};
        for (const [key, value] of params) result[key] = value;
        callback(result);
    });
}

// All question-management routes use this check.
// The user must have a valid client certificate and must be a teacher.
function rejectIfNotTeacher(identity, res) {
    if (!identity) {
        res.writeHead(401, {'Content-Type': 'text/html'});
        res.end(renderErrorPage(null, 401, 'Certificate authentication required.'));
        return true;
    }
    if (identity.role !== 'teacher') {
        res.writeHead(403, {'Content-Type': 'text/html'});
        res.end(renderErrorPage(identity, 403, 'Only teacher accounts may manage assessments.'));
        return true;
    }
    return false;
}


const server = https.createServer(options, (req, res) => {
    setSecurityHeaders(res);
    const identity = getIdentity(req);
    const urlPath = req.url.split('?')[0];

    if (urlPath === '/secure-area') {
        if (identity) {
            res.writeHead(200, {'Content-Type': 'text/plain'});
            res.end(`Access granted.\nClient certificate verified for: ${identity.cn}\n`);
        } else {
            console.warn(`[${new Date().toISOString()}] Client cert rejected: ${req.socket.authorizationError}`);
            res.writeHead(401, {'Content-Type': 'text/plain'});
            res.end('Access denied: valid client certificate required.\n');
        }
        return;
    }

    if (urlPath === '/' && req.method === 'GET') {
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.end(renderLoginPage(identity));
        return;
    }

    if (urlPath === '/dashboard' && req.method === 'GET') {
        if (!identity) {
            res.writeHead(401, {'Content-Type': 'text/html'});
            res.end(renderErrorPage(null, 401, 'Certificate authentication required.'));
            return;
        }
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.end(renderDashboardPage(identity));
        return;
    }

    if (urlPath === '/assessment' && req.method === 'GET') {
        if (!identity) {
            res.writeHead(401, {'Content-Type': 'text/html'});
            res.end(renderErrorPage(null, 401, 'Certificate authentication required.'));
            return;
        }
        if (identity.role !== 'student') {
            res.writeHead(403, {'Content-Type': 'text/html'});
            res.end(renderErrorPage(identity, 403, 'Only student accounts may take assessments.'));
            return;
        }
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.end(renderAssessmentPage(identity));
        return;
    }

    if (urlPath === '/assessment/submit' && req.method === 'POST') {
        if (!identity) {
            res.writeHead(401, {'Content-Type': 'text/html'});
            res.end(renderErrorPage(null, 401, 'Certificate authentication required.'));
            return;
        }
        if (identity.role !== 'student') {
            res.writeHead(403, {'Content-Type': 'text/html'});
            res.end(renderErrorPage(identity, 403, 'Only student accounts may submit assessments.'));
            return;
        }
        parseFormBody(req, (answers) => {
            let score = 0;
            ASSESSMENT.questions.forEach(q => {
                const submitted = answers[q.id];
                if (submitted !== undefined && parseInt(submitted, 10) === q.correctIndex) score++;
            });
            submittedResults.push({
                studentName: identity.cn,
                score,
                total: ASSESSMENT.questions.length,
                timestamp: Date.now()
            });
            res.writeHead(200, {'Content-Type': 'text/html'});
            res.end(renderResultsPage(identity, score, ASSESSMENT.questions.length));
        });
        return;
    }


    if (urlPath === '/manage' && req.method === 'GET') {
        if (rejectIfNotTeacher(identity, res)) return;
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.end(renderManagePage(identity));
        return;
    }

    // Save edits to one existing question.
    if (urlPath === '/manage/save-question' && req.method === 'POST') {
        if (rejectIfNotTeacher(identity, res)) return;
        parseFormBody(req, (fields) => {
            const question = ASSESSMENT.questions.find(q => q.id === fields.qid);
            if (!question) {
                safeError(res, 404, 'Question not found.');
                return;
            }

            const result = validateQuestionInput(fields);
            if (!result.valid) {
                // Re-show the management page with the current (unsaved) data plus
                // an inline error, rather than a generic error page - keeps the
                // teacher on the same screen with their other edits still visible.
                res.writeHead(200, {'Content-Type': 'text/html'});
                res.end(renderManagePage(identity, result.error));
                return;
            }

            question.prompt = result.prompt;
            question.choices = result.choices;
            question.correctIndex = result.correctIndex;

            res.writeHead(302, {Location: '/manage'});
            res.end();
        });
        return;
    }

    // Add a new question.
    if (urlPath === '/manage/add-question' && req.method === 'POST') {
        if (rejectIfNotTeacher(identity, res)) return;
        parseFormBody(req, (fields) => {
            const result = validateQuestionInput(fields);
            if (!result.valid) {
                res.writeHead(200, {'Content-Type': 'text/html'});
                res.end(renderManagePage(identity, result.error));
                return;
            }

            // Demo-only unique id - fine for an in-memory, single-session list.
            const newId = 'q' + Date.now();
            ASSESSMENT.questions.push({
                id: newId,
                prompt: result.prompt,
                choices: result.choices,
                correctIndex: result.correctIndex,
            });

            res.writeHead(302, {Location: '/manage'});
            res.end();
        });
        return;
    }

    // Delete a question. Refuses to delete the last remaining question,
    // since an assessment with zero questions would break the student view.
    if (urlPath === '/manage/delete-question' && req.method === 'POST') {
        if (rejectIfNotTeacher(identity, res)) return;
        parseFormBody(req, (fields) => {
            if (ASSESSMENT.questions.length <= 1) {
                res.writeHead(200, {'Content-Type': 'text/html'});
                res.end(renderManagePage(identity, 'At least one question must remain in the assessment.'));
                return;
            }
            const idx = ASSESSMENT.questions.findIndex(q => q.id === fields.qid);
            if (idx !== -1) ASSESSMENT.questions.splice(idx, 1);

            res.writeHead(302, {Location: '/manage'});
            res.end();
        });
        return;
    }

    if (urlPath === '/about' && req.method === 'GET') {
        const filePath = path.join(PUBLIC_DIR, 'about.html');
        fs.readFile(filePath, (err, data) => {
            if (err) {
                safeError(res, 404, 'Not found', err);
                return;
            }
            res.writeHead(200, {'Content-Type': 'text/html'});
            res.end(data);
        });
        return;
    }

    const filePath = resolveSafePath(urlPath);

    // important security check is,
    //someone cannot use the static-file mechanism to escape the public folder.
    if (!filePath) {
        safeError(res, 403, 'Forbidden');
        return;
    }

    fs.readFile(filePath, (err, data) => {
        if (err) {
            safeError(res, 404, 'Not found', err);
            return;
        }
        const ext = path.extname(filePath);
        const contentType = CONTENT_TYPES[ext] || 'application/octet-stream';
        res.writeHead(200, {'Content-Type': contentType});
        res.end(data);
    });
});

server.listen(PORT, () => {
    console.log(`The application runs locally over HTTPS on port ${PORT}`);
    console.log(`https://localhost:${PORT}`);
});