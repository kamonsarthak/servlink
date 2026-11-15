// Simulates a sleeping service: records each wake, starts listening after a short boot delay.
// Usage: node wake-server.mjs <port> <counterFile>
import { appendFileSync } from 'node:fs';
import http from 'node:http';

const [port, counter] = process.argv.slice(2);
appendFileSync(counter, `${process.pid}\n`);
setTimeout(() => {
  http
    .createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(`woken ${req.url}`);
    })
    .listen(Number(port), '127.0.0.1');
}, 600);
