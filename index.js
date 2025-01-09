// SERVER EXPRESSJS
const express = require('express');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
// const { sequelize, User } = require('./models/user');

const app = express();
app.use(express.json());

// Sinkronisasi Database
// sequelize.sync().then(() => {
//     console.log('Database synced!');
// });

const PORT = 3000;
const SECRET_KEY = 'mysecretkey';

const getUsers = () => JSON.parse(fs.readFileSync('users.json', 'utf-8'));
const saveUsers = (users) => fs.writeFileSync('users.json', JSON.stringify(users, null, 2));

// ENDPOINT REGISTER
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required!' });
    }

    const users = getUsers();
    const userExists = users.find(user => user.username === username);

    if (userExists) {
        return res.status(400).json({ message: 'User already exists! '});
    }

    const hasehedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hasehedPassword});
    fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
    saveUsers(users);

    res.status(201).json({ message: 'User registred successfully!' });
});

// ENDPOINT LOGIN
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const users = getUsers();

    const user = users.find(user => user.username === username);

    if (!user) {
        res.status(400).json({ message: 'Invalid username or password!' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!password) {
        return res.status(400).json({ message: 'Invalid username or password!' });
    }

    // Membuat JWT
    const token = jwt.sign({username}, SECRET_KEY, { expiresIn: '1h'});
    res.status(200).json({ message: 'Login successful', token});
});

// Middleware untuk memverifikasi JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Access Denied' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid Token!'});

        req.user = user;
        next();
    });
};

// Proteksi endpoint CRUD dengan JWT
app.get('/users', authenticateToken, (req, res) => {
    const users = getUsers();
    res.status(200).json(users);
});

// Menjalankan PORT
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

// Create User
app.post('/users', async (req, res) => {
    const { username, password } = req.body;
  
    const users = getUsers();
    const userExists = users.find(user => user.username === username);

    if (userExists) {
        return res.status(400).json({ message: 'User already exists! '});
    }

    const hasehedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hasehedPassword});
    fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
    saveUsers(users);
  
    res.status(201).json({ message: 'User created!' });
});

// UPDATE USER
app.put('/users/:username', (req, res) => {
    const { username } = req.params;
    const { password } = req.body;
  
    const users = getUsers();
  
    const userIndex = users.findIndex(user => user.username === username);
    if (userIndex === -1) {
      return res.status(404).json({ message: 'User not found!' });
    }
  
    users[userIndex].password = password;
    fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
  
    res.status(200).json({ message: 'User updated!' });
});

// DELETE USER
app.delete('/users/:username', authenticateToken, (req, res) => {
    const { username } = req.params;
    let users = getUsers();
  
    const userIndex = users.findIndex(user => user.username === username);
    if (userIndex === -1) {
      return res.status(404).json({ message: 'User not found!' });
    }
  
    users.splice(userIndex, 1);
    saveUsers(users);
  
    res.status(200).json({ message: 'User deleted successfully!' });
  });
  
  