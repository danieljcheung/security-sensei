/**
 * Intentionally vulnerable Express server for security testing.
 * DO NOT use in production!
 */

const express = require('express');
const mysql = require('mysql');
const app = express();

app.use(express.json());

// VULNERABLE: Eval with user input
app.post('/calculate', (req, res) => {
    const userInput = req.body.expression;
    // DANGEROUS: Arbitrary code execution
    const result = eval(userInput);
    res.json({ result });
});

// VULNERABLE: SQL Injection
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password123',
        database: 'users'
    });

    // DANGEROUS: SQL string concatenation
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    connection.query(query, (error, results) => {
        res.json(results);
    });
});

// VULNERABLE: Another SQL injection variant
app.get('/search', (req, res) => {
    const searchTerm = req.query.q;
    const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
    // Execute query...
    res.json({ query });
});

// VULNERABLE: innerHTML with user content (XSS)
app.get('/preview', (req, res) => {
    const content = req.query.content;
    // Sending back HTML that will use innerHTML
    res.send(`
        <html>
        <body>
            <div id="preview"></div>
            <script>
                document.getElementById('preview').innerHTML = '${content}';
            </script>
        </body>
        </html>
    `);
});

// VULNERABLE: Command injection
app.get('/ping', (req, res) => {
    const host = req.query.host;
    const { exec } = require('child_process');
    // DANGEROUS: Command injection
    exec('ping -c 4 ' + host, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

// VULNERABLE: Insecure token storage recommendation
app.get('/login-page', (req, res) => {
    res.send(`
        <html>
        <script>
            // VULNERABLE: Storing JWT in localStorage
            function handleLogin(token) {
                localStorage.setItem('authToken', token);
                localStorage.setItem('user_session', token);
            }

            // VULNERABLE: Storing sensitive data in sessionStorage
            function storeUserData(data) {
                sessionStorage.setItem('userPassword', data.password);
            }
        </script>
        </html>
    `);
});

// VULNERABLE: Insecure cookie settings
app.get('/set-cookie', (req, res) => {
    // Missing httpOnly, secure, sameSite
    res.cookie('session', 'abc123');
    res.cookie('authToken', req.query.token);
    res.send('Cookie set');
});

// VULNERABLE: Path traversal
app.get('/file', (req, res) => {
    const filename = req.query.name;
    const fs = require('fs');
    // DANGEROUS: No path sanitization
    const content = fs.readFileSync('./uploads/' + filename, 'utf8');
    res.send(content);
});

// VULNERABLE: SSRF
app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    const response = await fetch(url);
    const data = await response.text();
    res.send(data);
});

// VULNERABLE: Hardcoded credentials
const DB_PASSWORD = 'supersecret123';
const API_KEY = 'FAKE_API_KEY_FOR_DEMO';

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
