// api/server.js

const express = require('express');
const mongoose = require('mongoose');

const app = express();
const port = process.env.PORT || 3000;

// MongoDB connection
const mongoURI = 'your_mongo_database_uri';
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.use(express.json());

// Sample route
app.get('/', (req, res) => {
  res.send('Hello, World!');
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
