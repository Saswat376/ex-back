require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');


const app = express();


// Connect to MongoDB
connectDB();


// Middleware
app.use(cors());
app.use(express.json());


// Routes
app.use('/api/auth', authRoutes);


// Test route
app.get('/', (req, res) => {
 res.json({ message: 'Auth API is running' });
});


const PORT = process.env.PORT || 3000;


app.listen(PORT, () => {
 console.log(`Server running on port ${PORT}`);
});
