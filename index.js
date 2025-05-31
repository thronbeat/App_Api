// index.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();

const pool = require('./db'); // <-- Import pool from db.js
app.locals.pool = pool;

app.use(cors());
app.use(bodyParser.json());

const userRoutes = require('./routes/users');
app.use('/', userRoutes);

app.listen(5000, () => {
  console.log('Server is running on port 5000');
});
