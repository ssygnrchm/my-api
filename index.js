// SERVER EXPRESSJS
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { sequelize, User } = require('./models/user');

const app = express();
app.use(express.json());

// Sinkronisasi Database
sequelize.sync().then(() => {
    console.log('Database synced!');
});

// ENDPOINT REGISTER
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Hash password sebelum menyimpan ke database
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ username, password: hashedPassword });

        res.status(201).json({ message: 'User registered!', user });
    } catch (error) {
        res.status(500).json({ message: 'Error registering user', error });
    }
});

// ENDPOINT LOGIN
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Cari user berdasarkan username
        const user = await User.findOne({ where: { username } });

        if (!user) {
            res.status(400).json({ message: 'Invalid username or password!' });
        }

        // Bandingkan password yang diinput dengan password yang di-hash
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Buat token JWT
        const token = jwt.sign({ id: user.id, username: user.username }, 'secret_key', { expiresIn: '1hr'});
        
        res.status(200).json({ message: 'Login successful', token});
    } catch (error) {
        res.status(500).json({ message: 'Error logging in', error});
    }
});

// Endpoint Read - Protected Route
app.get('/users', verifyToken, async (req, res) => {
    try{
        const users = await User.findAll();
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: 'Error fecthing users', error });
    } 
});

// Endpoint Update User
app.put('/users/:id', verifyToken, async (req, res) => {
    const { id } = req.params;
    const { username, password} = req.body;

    try {
        const user = await User.findByPk(id);

        if (!user) {
            return res.status(404).json({ message: 'User not found!' });
        }

       const hashedPassword = await bcrypt.hash(password, 10);
       user.username = username;
       user.password = hashedPassword;

       await user.save();
       res.status(200).json({ message: 'User updated!', user });
    } catch (error) {
        res.status(500).json({ message: 'Error updating user', error });
    }
});

// Endpoint Delete User
app.delete('/users/:id', verifyToken, async (req, res) => {
    const { id } = req.params;

    try {
        const user = await User.findByPk(id);

        if (!user) {
            return res.status(404).json({ message: 'User not found!' });
        }

        await user.destroy();
        res.status(200).json({ message: 'User deleted!' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting user', error });
    }
});

// Middleware untuk verifikasi Token
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];

    // Periksa apakah header Authorization ada dan dalam format "Bearer token"
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(403).json({ message: 'No token provided!' });
    }
    
    // Ekstrak token dari header Authorization
    const token = authHeader.split(' ')[1];

    jwt.verify(token, 'secret_key', (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Unauthorized!' });
      }
      
      // Simpan informasi user dari token ke dalam request
      req.userId = decoded.id;
      next();
    });
}

// Jalankan Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});