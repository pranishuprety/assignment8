const express = require('express');
const nedb = require("nedb-promises");
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
const db = nedb.create('users.jsonl');

// Middleware
app.use(express.static('public'));
app.use(express.json()); // ✅ Automatically decode JSON bodies

// Helper function to generate authentication token
function generateAuthToken() {
  return crypto.randomBytes(64).toString('hex');
}

// ✅ GET /users - return all user records (passwords NOT included)
app.get('/users', (req, res) => {
  db.find({})
    .then(users => {
      users = users.map(user => {
        // Remove password from user data
        delete user.password;
        return user;
      });
      res.send(users);
    })
    .catch(error => res.send({ error }));
});

// ✅ POST /users - register a new user (with password hashing)
app.post('/users', async (req, res) => {
  const { username, password, name, email } = req.body;

  if (!username || !password || !name || !email) {
    return res.send({ error: 'Missing fields.' });
  }

  const existingUser = await db.findOne({ username });
  if (existingUser) {
    return res.send({ error: 'Username already exists.' });
  }

  // Hash the password before storing
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { username, password: hashedPassword, name, email, authenticationToken: null };

  try {
    const user = await db.insert(newUser);
    // Do NOT send the password in the response
    delete user.password;
    res.send(user);
  } catch (error) {
    res.send({ error });
  }
});

// ✅ POST /users/auth - authenticate a user (login)
app.post('/users/auth', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.send({ error: 'Missing username or password.' });
  }

  const user = await db.findOne({ username });
  if (!user) {
    return res.status(401).send({ error: 'Invalid username or password.' });
  }

  // Check if the provided password matches the hashed password in the database
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).send({ error: 'Invalid username or password.' });
  }

  // Generate authentication token and update user record
  const authToken = generateAuthToken();
  user.authenticationToken = authToken;
  await db.update({ username: user.username }, { $set: { authenticationToken: authToken } });

  // Send back user info with the authentication token (but not the password)
  delete user.password;
  res.send({
    username: user.username,
    authenticationToken: user.authenticationToken,
    name: user.name,
    email: user.email
  });
});

// ✅ PATCH /users/:username/:authenticationToken - update name/email (secured)
app.patch('/users/:username/:authenticationToken', async (req, res) => {
  const { username, authenticationToken } = req.params;
  const { name, email } = req.body;

  const user = await db.findOne({ username });

  if (!user || user.authenticationToken !== authenticationToken) {
    return res.status(401).send({ error: 'Unauthorized.' });
  }

  try {
    const result = await db.update({ username: user.username }, { $set: { name, email } });
    if (result === 0) return res.send({ error: 'Something went wrong.' });
    res.send({ ok: true });
  } catch (error) {
    res.send({ error });
  }
});

// ✅ DELETE /users/:username/:authenticationToken - delete user (secured)
app.delete('/users/:username/:authenticationToken', async (req, res) => {
  const { username, authenticationToken } = req.params;

  const user = await db.findOne({ username });

  if (!user || user.authenticationToken !== authenticationToken) {
    return res.status(401).send({ error: 'Unauthorized.' });
  }

  try {
    const result = await db.delete({ username: user.username });
    if (result === 0) return res.send({ error: 'Something went wrong.' });
    res.send({ ok: true });
  } catch (error) {
    res.send({ error });
  }
});

// Default route for any other path
app.all('*', (req, res) => res.status(404).send('Invalid URL.'));

// Start server
app.listen(3000, () => console.log("Server started on http://localhost:3000"));
