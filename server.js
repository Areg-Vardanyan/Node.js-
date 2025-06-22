let express = require('express');
let bcrypt = require('bcrypt');
let jwt = require('jsonwebtoken');
let { body, validationResult } = require('express-validator');

let app = express();
let PORT = process.env.PORT || 3000;
let SECRET_KEY = 'your_secret_key'; // Use a strong secret key

app.use(express.json());
let users = [];
app.post('/register', [
    body('username').isString().notEmpty(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    let errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    let { username, password } = req.body;
    let hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.status(201).send('User registered successfully');
});

app.post('/login', [
    body('username').isString().notEmpty(),
    body('password').notEmpty()
], async (req, res) => {
    let errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    let { username, password } = req.body;
    let user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).send('Invalid credentials');
    }

    let token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});

// Middleware to authenticate JWT
let authenticateJWT = (req, res, next) => {
    let token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.sendStatus(403);
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

// Protected route
app.get('/protected', authenticateJWT, (req, res) => {
    res.send(`Hello ${req.user.username}, you have access to this protected route!`);
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`); // you can add here port u want 
});

