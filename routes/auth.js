const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');


// @route   POST /api/auth/register
// @desc    Register a new user
// @access  Public
router.post('/register', async (req, res) => {
 try {
   const { name, email, password } = req.body;


   // Validation
   if (!name || !email || !password) {
     return res.status(400).json({
       message: 'Please provide all required fields'
     });
   }


   if (password.length < 6) {
     return res.status(400).json({
       message: 'Password must be at least 6 characters'
     });
   }


   // Check if user exists
   const existingUser = await User.findOne({ email });
   if (existingUser) {
     return res.status(400).json({
       message: 'User already exists with this email'
     });
   }


   // Hash password
   const salt = await bcrypt.genSalt(10);
   const hashedPassword = await bcrypt.hash(password, salt);


   // Create user
   const user = new User({
     name,
     email,
     password: hashedPassword
   });


   await user.save();


   // Create JWT token
   const token = jwt.sign(
     { userId: user._id },
     process.env.JWT_SECRET,
     { expiresIn: '7d' }
   );


   res.status(201).json({
     message: 'User registered successfully',
     token,
     user: {
       id: user._id,
       name: user.name,
       email: user.email
     }
   });


 } catch (error) {
   console.error(error);
   res.status(500).json({ message: 'Server error' });
 }
});


// @route   POST /api/auth/login
// @desc    Login user
// @access  Public
router.post('/login', async (req, res) => {
 try {
   const { email, password } = req.body;


   // Validation
   if (!email || !password) {
     return res.status(400).json({
       message: 'Please provide email and password'
     });
   }


   // Check if user exists
   const user = await User.findOne({ email });
   if (!user) {
     return res.status(400).json({
       message: 'Invalid credentials'
     });
   }


   // Verify password
   const isMatch = await bcrypt.compare(password, user.password);
   if (!isMatch) {
     return res.status(400).json({
       message: 'Invalid credentials'
     });
   }


   // Create JWT token
   const token = jwt.sign(
     { userId: user._id },
     process.env.JWT_SECRET,
     { expiresIn: '7d' }
   );


   res.json({
     message: 'Login successful',
     token,
     user: {
       id: user._id,
       name: user.name,
       email: user.email
     }
   });


 } catch (error) {
   console.error(error);
   res.status(500).json({ message: 'Server error' });
 }
});




module.exports = router;