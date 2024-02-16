// routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const usermodel = require('../Model/usermodel');

const router = express.Router();

// User Registration
app.post('/register', async (req, res) => {
    try {
      const { username, password, role } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({ username, password: hashedPassword, role });
      await user.save();
      res.status(201).send('User registered successfully');
    } catch (error) {
      console.error(error);
      res.status(500).send('Error registering user');
    }
  });
  
  // User Login
  app.post('/login', async (req, res) => {
    try {
      const { username, password } = req.body;
      const user = await User.findOne({ username });
      if (!user) {
        return res.status(404).send('User not found');
      }
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        return res.status(401).send('Invalid password');
      }
      const token = jwt.sign({ username: user.username, role: user.role }, 'secret');
      res.status(200).json({ token });
    } catch (error) {
      console.error(error);
      res.status(500).send('Error logging in');
    }
  });
  
  // Protect routes with JWT
  function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).send('Unauthorized');
    jwt.verify(token, 'secret', (err, user) => {
      if (err) return res.status(403).send('Forbidden');
      req.user = user;
      next();
    });
  }
  
  // Admin Routes
  app.post('/admin/create', authenticateToken, async (req, res) => {
    try {
      if (req.user.role !== 'Admin') {
        return res.status(403).send('Forbidden');
      }
      const { username, password, role } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({ username, password: hashedPassword, role });
      await user.save();
      res.status(201).send('User created successfully');
    } catch (error) {
      console.error(error);
      res.status(500).send('Error creating user');
    }
  });
  app.post('/admin/create', authenticateToken, async (req, res) => {
    try {
      if (req.user.role !== 'Admin') {
        return res.status(403).send('Forbidden');
      }
      const { username, password, role } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({ username, password: hashedPassword, role, adminProvidedPassword: true });
      await user.save();
      res.status(201).send('User created successfully');
    } catch (error) {
      console.error(error);
      res.status(500).send('Error creating user');
    }
  });
  
  // Update User (Admin Only)
  app.put('/admin/update/:id', authenticateToken, async (req, res) => {
    try {
      if (req.user.role !== 'Admin') {
        return res.status(403).send('Forbidden');
      }
      const { username, password, role } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
      await User.findByIdAndUpdate(req.params.id, { username, password: hashedPassword, role });
      res.status(200).send('User updated successfully');
    } catch (error) {
      console.error(error);
      res.status(500).send('Error updating user');
    }
  });
  
  // Delete User (Admin Only)
  app.delete('/admin/delete/:id', authenticateToken, async (req, res) => {
    try {
      if (req.user.role !== 'Admin') {
        return res.status(403).send('Forbidden');
      }
      await User.findByIdAndDelete(req.params.id);
      res.status(200).send('User deleted successfully');
    } catch (error) {
      console.error(error);
      res.status(500).send('Error deleting user');
    }
  });  

module.exports = router;
