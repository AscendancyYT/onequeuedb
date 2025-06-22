const jsonServer = require('json-server');
const bcrypt = require('bcrypt');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();

server.use(middlewares);
server.use(jsonServer.bodyParser);

// CORS configuration
server.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'http://127.0.0.1:5500');
  res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

// Basic authentication middleware
const authUser = process.env.AUTH_USER || 'admin';
const authPass = process.env.AUTH_PASS || 'secret';
server.use((req, res, next) => {
  const auth = req.headers.authorization;
  if (auth === 'Basic ' + Buffer.from(`${authUser}:${authPass}`).toString('base64')) {
    next();
  } else {
    res.status(401).send('Unauthorized');
  }
});

// Password hashing for POST requests
server.use(async (req, res, next) => {
  if (req.method === 'POST' && (req.path === '/companies' || req.path === '/users')) {
    if (req.body.password) {
      try {
        req.body.password = await bcrypt.hash(req.body.password, 10);
      } catch (error) {
        return res.status(500).send('Error hashing password');
      }
    }
  }
  next();
});

// Custom login endpoints
server.post('/companies/login', async (req, res) => {
  const { username, password } = req.body;
  const companies = router.db.get('companies').value();
  const company = companies.find(c => c.username === username);
  if (company && await bcrypt.compare(password, company.password)) {
    res.json({ id: company.id });
  } else {
    res.status(401).send('Invalid credentials');
  }
});

server.post('/users/login', async (req, res) => {
  const { username, password } = req.body;
  const users = router.db.get('users').value();
  const user = users.find(u => u.username === username);
  if (user && await bcrypt.compare(password, user.password)) {
    res.json({ id: user.id });
  } else {
    res.status(401).send('Invalid credentials');
  }
});

server.use(router);

const port = process.env.PORT || 3000;
server.listen(port, '0.0.0.0', () => {
  console.log(`JSON Server running on port ${port}`);
});
