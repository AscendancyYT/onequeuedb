const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();

server.use(middlewares);
server.use((req, res, next) => {
  const auth = req.headers.authorization;
  if (auth === 'Basic ' + Buffer.from('admin:secret').toString('base64')) {
    next();
  } else {
    res.status(401).send('Unauthorized');
  }
});
server.use(router);
server.listen(3000);
