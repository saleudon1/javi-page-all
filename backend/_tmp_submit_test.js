const http = require('http');
const data = JSON.stringify({ email: 'test@example.com', password: 'secret123', captcha: 'dummy-token' });
const options = {
  hostname: 'localhost', port: 3000, path: '/api/submit', method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
};
const req = http.request(options, (res)=>{
  let body = '';
  res.on('data', (c)=> body += c);
  res.on('end', ()=>{
    console.log('status', res.statusCode);
    try{ console.log('body', JSON.parse(body)); }catch(e){ console.log('body', body); }
  });
});
req.on('error', (e)=> console.error('request error', e.stack || e.message));
req.write(data);
req.end();
