const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();
const axios = require('axios');
const app = express();
const PORT = process.env.PORT || 5000;
const mongoURI = process.env.mongoURI;

mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  playlists: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Playlist' }],
  verificationToken: { type: String },
  tokenExpiration: { type: Date },
  resetToken: String, // Add this field
  resetTokenExpiration: Date, // Add this field
});

const User = mongoose.model('User', userSchema);

const playlistSchema = new mongoose.Schema({
  name: { type: String, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  isPublic: { type: Boolean, default: false },
  movies: [{ type: String }]
});

const Playlist = mongoose.model('Playlist', playlistSchema);

app.use(bodyParser.json());
app.use(cors());

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET || 'rohanth12', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Sign Up
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }
    if (password.length < 12) {
      return res.status(400).json({ message: 'Password must be at least 12 characters long' });
    }
    if (!/[A-Z]/.test(password)) {
      return res.status(400).json({ message: 'Password must contain at least one uppercase letter' });
    }
    if (!/[a-z]/.test(password)) {
      return res.status(400).json({ message: 'Password must contain at least one lowercase letter' });
    }
    if (!/\d/.test(password)) {
      return res.status(400).json({ message: 'Password must contain at least one number' });
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+/.test(password)) {
      return res.status(400).json({ message: 'Password must contain at least one special character' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    const verificationToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiration = Date.now() + 3600000; // 1 hour

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      verificationToken,
      tokenExpiration
    });

    await newUser.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: newUser.email,
      subject: 'Email Verification',
      text: `Please verify your email by clicking the link: \nhttps://movie-hunters-wolkus.vercel.app/verify-email?token=${verificationToken}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return console.error('Error sending email:', error);
      }
      console.log('Email sent:', info.response);
    });

    res.status(201).json({ message: 'User created successfully. Please verify your email.' });
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ message: 'Error creating user' });
  }
});


// Reset Password
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    const user = await User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } });
    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    if (newPassword.length < 12) {
      return res.status(400).json({ message: 'Password must be at least 12 characters long' });
    }
    if (!/[A-Z]/.test(newPassword)) {
      return res.status(400).json({ message: 'Password must contain at least one uppercase letter' });
    }
    if (!/[a-z]/.test(newPassword)) {
      return res.status(400).json({ message: 'Password must contain at least one lowercase letter' });
    }
    if (!/\d/.test(newPassword)) {
      return res.status(400).json({ message: 'Password must contain at least one number' });
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+/.test(newPassword)) {
      return res.status(400).json({ message: 'Password must contain at least one special character' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;
    await user.save();

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error('Error resetting password:', err);
    res.status(500).json({ message: 'Error resetting password' });
  }
});



// Password Reset Request
app.post('/request-reset-password', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Email not found' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiration = Date.now() + 3600000; // 1 hour

    user.resetToken = resetToken;
    user.resetTokenExpiration = resetTokenExpiration;
    await user.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Password Reset',
      text: `Please reset your password by clicking the link: \nhttps://movie-hunters-wolkus.vercel.app/reset-password?token=${resetToken}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return console.error('Error sending email:', error);
      }
      console.log('Email sent:', info.response);
    });

    res.status(200).json({ message: 'Password reset email sent' });
  } catch (err) {
    console.error('Error requesting password reset:', err);
    res.status(500).json({ message: 'Error requesting password reset' });
  }
});


// Verify Email
app.get('/verify-email', async (req, res) => {
  const { token } = req.query;

  try {
    const user = await User.findOne({ verificationToken: token, tokenExpiration: { $gt: Date.now() } });
    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.tokenExpiration = undefined;
    await user.save();

    res.status(200).json({ message: 'Email verified successfully' });
  } catch (err) {
    console.error('Error verifying email:', err);
    res.status(500).json({ message: 'Error verifying email' });
  }
});

// Sign In
app.post('/signin', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email }).populate('playlists');
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    if (!user.isVerified) {
      return res.json({ message: 'Please verify your email before signing in', isVerified : false });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET || 'rohanth12');
    const username = user.username;

    res.json({ message: "Login Successful", token, username, playlists: user.playlists , isVerified : true });
  } catch (err) {
    console.error('Error signing in:', err);
    res.status(500).json({ message: 'Error signing in' });
  }
});

// Update User Details
app.put('/user', authenticateToken, async (req, res) => {
  const { username, email } = req.body;
  const userId = req.user.email;

  try {
    const user = await User.findOne({ email: userId });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.username = username;
    user.email = email;
    await user.save();

    res.status(200).json({ message: 'User details updated successfully', username: user.username, email: user.email });
  } catch (err) {
    console.error('Error updating user details:', err);
    res.status(500).json({ message: 'Error updating user details' });
  }
});

// Create Playlist
app.post('/playlists', authenticateToken, async (req, res) => {
  const { name } = req.body;
  const userId = req.user.email;
  const isPublic = false;

  try {
    const user = await User.findOne({ email: userId });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const newPlaylist = new Playlist({ name, user: user._id, isPublic });
    await newPlaylist.save();

    user.playlists.push(newPlaylist);
    await user.save();

    res.status(201).json({ message: 'Playlist created successfully', playlist: newPlaylist });
  } catch (err) {
    console.error('Error creating playlist:', err);
    res.status(500).json({ message: 'Error creating playlist' });
  }
});

// Update Playlist to Public
app.put('/playlists/:playlistId/public', authenticateToken, async (req, res) => {
  const playlistId = req.params.playlistId;
  const userId = req.user.email;

  try {
    const user = await User.findOne({ email: userId });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const playlist = await Playlist.findOneAndUpdate(
      { _id: playlistId, user: user._id },
      { isPublic: true },
      { new: true }
    );

    if (!playlist) {
      return res.status(404).json({ message: 'Playlist not found or you do not have permission to update it' });
    }

    res.status(200).json({ message: 'Playlist updated to public successfully', playlist });
  } catch (err) {
    console.error('Error updating playlist to public:', err);
    res.status(500).json({ message: 'Error updating playlist to public' });
  }
});

// Update Playlist to Private
app.put('/playlists/:playlistId/private', authenticateToken, async (req, res) => {
  const playlistId = req.params.playlistId;
  const userId = req.user.email;

  try {
    const user = await User.findOne({ email: userId });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const playlist = await Playlist.findOneAndUpdate(
      { _id: playlistId, user: user._id },
      { isPublic: false },
      { new: true }
    );

    if (!playlist) {
      return res.status(404).json({ message: 'Playlist not found or you do not have permission to update it' });
    }

    res.status(200).json({ message: 'Playlist updated to private successfully', playlist });
  } catch (err) {
    console.error('Error updating playlist to private:', err);
    res.status(500).json({ message: 'Error updating playlist to private' });
  }
});

// Fetch Public Playlist
app.get('/public/playlists/:playlistId', async (req, res) => {
  const playlistId = req.params.playlistId;

  try {
    const playlist = await Playlist.findById(playlistId).populate('user');
    if (!playlist) {
      return res.status(404).json({ message: 'Playlist not found' });
    }
    if (!playlist.isPublic) {
      return res.status(200).json({ message: 'Playlist is not public', isPublic: false });
    }

    res.status(200).json({ playlist, isPublic: true });
  } catch (err) {
    console.error('Error fetching public playlist:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add Movie to Playlist
app.post('/playlists/:playlistId/movies', authenticateToken, async (req, res) => {
  const { movieName } = req.body;
  const { playlistId } = req.params;

  try {
    const playlist = await Playlist.findById(playlistId);
    if (!playlist) {
      return res.status(404).json({ message: 'Playlist not found' });
    }

    playlist.movies.push(movieName);
    await playlist.save();

    res.status(200).json({ message: 'Movie added to playlist successfully', playlist });
  } catch (err) {
    console.error('Error adding movie to playlist:', err);
    res.status(500).json({ message: 'Error adding movie to playlist' });
  }
});

// Delete Movie from Playlist
app.delete('/playlists/:playlistId/movies/:movieName', authenticateToken, async (req, res) => {
  const { playlistId, movieName } = req.params;

  try {
    const playlist = await Playlist.findById(playlistId);
    if (!playlist) {
      return res.status(404).json({ message: 'Playlist not found' });
    }

    const index = playlist.movies.indexOf(movieName);
    if (index === -1) {
      return res.status(404).json({ message: 'Movie not found in playlist' });
    }

    playlist.movies.splice(index, 1);
    await playlist.save();

    res.status(200).json({ message: 'Movie deleted from playlist successfully', playlist });
  } catch (err) {
    console.error('Error deleting movie from playlist:', err);
    res.status(500).json({ message: 'Error deleting movie from playlist' });
  }
});

// Search Movies
// const axios = require('axios');
const apiKey = process.env.apikey;

app.get('/search/:q', async (req, res) => {
  const query = req.params.q;
  const page = req.query.page || 1;

  try {
    const response = await axios.get(`http://www.omdbapi.com/?s=${query}&apikey=${apiKey}&page=${page}`);
    if (response.data.Response === 'True') {
      res.json(response.data);
    } else {
      res.status(404).json({ error: 'Movies not found' });
    }
  } catch (error) {
    console.error(`Error fetching movies for query ${query}:`, error);
    res.status(500).json({ error: 'An error occurred while fetching data from OMDB API' });
  }
});

// Fetch Movie Details
app.get('/movie/:imdbID', async (req, res) => {
  const imdbID = req.params.imdbID;

  try {
    const response = await axios.get(`http://www.omdbapi.com/?i=${imdbID}&apikey=${apiKey}`);
    if (response.data.Response === 'True') {
      res.json(response.data);
    } else {
      res.status(404).json({ error: 'Movie not found' });
    }
  } catch (error) {
    console.error(`Error fetching movie details for imdbID ${imdbID}:`, error);
    res.status(500).json({ error: 'An error occurred while fetching data from OMDB API' });
  }
});

// Get User's Playlists
app.get('/playlists', authenticateToken, async (req, res) => {
  const userId = req.user.email;

  try {
    const user = await User.findOne({ email: userId }).populate('playlists');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json(user.playlists);
  } catch (err) {
    console.error('Error fetching playlists:', err);
    res.status(500).json({ message: 'Error fetching playlists' });
  }
});

// Delete Playlist
app.delete('/playlists/:playlistId', authenticateToken, async (req, res) => {
  const { playlistId } = req.params;
  const userId = req.user.email;

  try {
    const user = await User.findOne({ email: userId });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const playlist = await Playlist.findById(playlistId);
    if (!playlist) {
      return res.status(404).json({ message: 'Playlist not found' });
    }

    if (!playlist.user.equals(user._id)) {
      return res.status(403).json({ message: 'You are not authorized to delete this playlist' });
    }

    await Playlist.deleteOne({ _id: playlistId });

    user.playlists.pull(playlistId);
    await user.save();

    res.status(200).json({ message: 'Playlist deleted successfully' });
  } catch (err) {
    console.error('Error deleting playlist:', err);
    res.status(500).json({ message: 'Error deleting playlist' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
