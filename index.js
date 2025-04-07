const express = require('express');
const nedb = require("nedb-promises");

const app = express();
const db = nedb.create('users.jsonl');

// Middleware
app.use(express.static('public'));
app.use(express.json()); // ✅ Automatically decode JSON bodies

// ✅ GET /users - return all user records
app.get('/users', (req, res) => {
  db.find({})
    .then(users => res.send(users))
    .catch(error => res.send({ error }));
});

// ✅ GET /users/:username - return specific user
app.get('/users/:username', (req, res) => {
  db.findOne({ username: req.params.username })
    .then(user => {
      if (!user) res.send({ error: 'Username not found.' });
      else res.send(user);
    })
    .catch(error => res.send({ error }));
});

// ✅ POST /users - register a new user
app.post('/users', (req, res) => {
  const { username, password, name, email } = req.body;

  if (!username || !password || !name || !email) {
    return res.send({ error: 'Missing fields.' });
  }

  db.findOne({ username })
    .then(existing => {
      if (existing) return res.send({ error: 'Username already exists.' });

      return db.insert({ username, password, name, email })
        .then(doc => res.send(doc));
    })
    .catch(error => res.send({ error }));
});

// ✅ PATCH /users/:username - update name/email
app.patch('/users/:username', (req, res) => {
  const { name, email } = req.body;

  db.update({ username: req.params.username }, { $set: { name, email } })
    .then(result => {
      if (result === 0) res.send({ error: 'Something went wrong.' });
      else res.send({ ok: true });
    })
    .catch(error => res.send({ error }));
});

// ✅ DELETE /users/:username - delete user
app.delete('/users/:username', (req, res) => {
  db.delete({ username: req.params.username })
    .then(result => {
      if (result === 0) res.send({ error: 'Something went wrong.' });
      else res.send({ ok: true });
    })
    .catch(error => res.send({ error }));
});

// Default route for any other path
app.all('*', (req, res) => res.status(404).send('Invalid URL.'));

// Start server
app.listen(3000, () => console.log("Server started on http://localhost:3000"));
