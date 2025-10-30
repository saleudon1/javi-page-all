const http = require('http');
const domains = ['aol.com','126.com','163.com','gmail.com','yahoo.com'];
(async ()=>{
  for(const d of domains){
    const url = `http://localhost:3000/api/detect-platform?domain=${encodeURIComponent(d)}`;
    http.get(url, (res)=>{
      let body='';
      res.on('data', c=> body+=c);
      res.on('end', ()=> {
        console.log(`${d} -> status=${res.statusCode}`);
        console.log('headers:', JSON.stringify(res.headers));
        console.log('body:', body);
      });
    }).on('error',(e)=> console.error(d,'error',e.stack || e.message));
    await new Promise(r=>setTimeout(r,400));
  }
})();
