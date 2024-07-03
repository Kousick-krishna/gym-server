const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const cors = require('cors');
const AdminReg = require('./models/AdminReg');
const UserReg = require('./models/UserReg');

// Load environment variables
dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const mongoDBURL = process.env.MONGODB_URL;

if (!mongoDBURL) {
    console.error('Error: MONGODB_URL is not defined in .env file');
    process.exit(1); // Exit the application
}

mongoose.connect(mongoDBURL, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch(err => {
        console.error('Error connecting to MongoDB:', err);
    });

app.post('/AdminReg', async (req, res) => {
    const { AdminId, password } = req.body;
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newAdmin = new AdminReg({ AdminId, password: hashedPassword });
        await newAdmin.save();
        res.status(201).json({ message: 'Admin registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error registering admin', error });
    }
});

app.post('/AdminLogin', async (req, res) => {
    const { AdminId, password } = req.body;
    try {
        const admin = await AdminReg.findOne({ AdminId });
        if (!admin) {
            return res.status(400).json({ message: 'Invalid AdminId or password' });
        }
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid AdminId or password' });
        }

        res.status(200).json({ message: 'Login successful' });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in', error });
    }
});

app.post('/UserReg', async (req, res) => {
    const { UserId, password } = req.body;
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new UserReg({ UserId, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error registering user', error });
    }
});

app.post('/UserLogin', async (req, res) => {
    const { UserId, password } = req.body;
    try {
        const user = await UserReg.findOne({ UserId });
        if (!user) {
            return res.status(400).json({ message: 'Invalid UserId or password' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid UserId or password' });
        }

        res.status(200).json({ message: 'Login successful' });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in', error });
    }
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
