const jwt = require('jsonwebtoken');
const User = require('../models/User');


const authMiddleware = async (req, res, next) => {
 try {
   // Get token from header
   const token = req.header('Authorization')?.replace('Bearer ', '');


   if (!token) {
     return res.status(401).json({
       message: 'No token, authorization denied'
     });
   }


   // Verify token
   const decoded = jwt.verify(token, process.env.JWT_SECRET);
  
   // Get user from database
   const user = await User.findById(decoded.userId).select('-password');
  
   if (!user) {
     return res.status(401).json({
       message: 'Token is not valid'
     });
   }


   // Attach user to request
   req.user = user;
   next();


 } catch (error) {
   res.status(401).json({
     message: 'Token is not valid'
   });   
 }

 router.get('/me', authMiddleware, async (req, res) => {
 try {
   res.json({
     user: {
       id: req.user._id,
       name: req.user.name,
       email: req.user.email
     }
   });
 } catch (error) {
   res.status(500).json({ message: 'Server error' });
 
 }
});

module.exports = authMiddleware;
}