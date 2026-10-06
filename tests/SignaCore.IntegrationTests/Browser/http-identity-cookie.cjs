// Real Chromium transport acceptance. Never print URLs, payloads, cookies, credentials or tokens.
const {chromium} = require(process.env.SIGNACORE_PLAYWRIGHT_MODULE || 'playwright');
const http = require('http');
const https = require('https');
const net = require('net');
const assert = require('node:assert/strict');
const readline = require('readline');
const origin = 'http://10.20.30.40:5002';
let targetPort = Number(process.env.SIGNACORE_BROWSER_PORT);
const input = readline.createInterface({input:process.stdin});
async function restart() {
  const port = new Promise(resolve => input.once('line',resolve));
  process.stdout.write('RESTART\n'); targetPort = Number(await port);
}
const proxy = http.createServer((req,res)=>{
  const url = new URL(req.url);
  if (url.origin !== origin) {res.writeHead(400);res.end();return;}
  const upstream = http.request({hostname:'127.0.0.1',port:targetPort,path:url.pathname+url.search,method:req.method,headers:req.headers},r=>{
    res.writeHead(r.statusCode,r.headers);r.pipe(res);
  }); upstream.on('error',()=>{res.writeHead(502);res.end();}); req.pipe(upstream);
});
const callbackServer=https.createServer({pfx:Buffer.from(process.env.SIGNACORE_BROWSER_CALLBACK_PFX,'base64')},(_req,res)=>{res.writeHead(200,{'Content-Type':'text/html'});res.end('<!doctype html><title>Application callback</title>');});
proxy.on('connect',(req,socket,head)=>{
 if(req.url!=='bff.success.test:443'){socket.destroy();return;}
 const upstream=net.connect(callbackServer.address().port,'127.0.0.1',()=>{socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');if(head.length)upstream.write(head);socket.pipe(upstream);upstream.pipe(socket);});
 upstream.on('error',()=>socket.destroy());socket.on('error',()=>upstream.destroy());
});
const callback='https://bff.success.test/callback?canary=success-redirect';
const challenge='E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const verifier='dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
let serial=0;
function authorize(overrides={}) {
 const n=++serial;
 return origin+'/oauth2/authorize?'+new URLSearchParams({client_id:'login-success-app',redirect_uri:callback,response_type:'code',scope:'openid profile',state:'browser-state-'+n+'-0123456789abcdef',nonce:'browser-nonce-'+n+'-0123456789abcdef',code_challenge:challenge,code_challenge_method:'S256',...overrides});
}
function backchannel(path,fields) {
 return new Promise((resolve,reject)=>{
  const body=new URLSearchParams(fields).toString();
  const req=http.request({hostname:'127.0.0.1',port:targetPort,path,method:'POST',headers:{'Host':'10.20.30.40:5002','Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body),'Authorization':'Basic '+Buffer.from('login-success-app:login-success-secret').toString('base64')}},res=>{
   let data='';res.on('data',chunk=>data+=chunk);res.on('end',()=>resolve({status:res.statusCode,body:JSON.parse(data)}));
  }); req.on('error',reject);req.end(body);
 });
}
(async()=>{
 await new Promise(resolve=>callbackServer.listen(0,'127.0.0.1',resolve));
 await new Promise(resolve=>proxy.listen(0,'127.0.0.1',resolve));
 const browser=await chromium.launch({headless:true,proxy:{server:'http://127.0.0.1:'+proxy.address().port}});
 try {
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  await context.route('https://bff.success.test/**',route=>route.fulfill({status:200,contentType:'text/html',body:'<!doctype html><title>Application callback</title>'}));
  const page=await context.newPage();
  page.on('console',message=>{if(message.text().includes('Content Security Policy'))process.stdout.write('STEP_CSP_REJECTION\n');});
  page.on('requestfailed',request=>{const error=request.failure()?.errorText;process.stdout.write((/^net::ERR_[A-Z_]+$/.test(error||'')?'STEP_'+error.slice(5):'STEP_REQUEST_FAILURE')+'\n');});
  const form=async()=>{const response=await page.goto(authorize());process.stdout.write('STEP_FORM_STATUS_'+response.status()+'\n');assert.equal(response.status(),200);const content=await page.content();process.stdout.write(content.includes('id="username"')?'STEP_BODY_LOGIN\n':content.includes('Setup')?'STEP_BODY_SETUP\n':'STEP_BODY_OTHER\n');await page.locator('#username').waitFor();};
  process.stdout.write('STEP_FORM\n'); await form();
  let cookies=await context.cookies(origin);
  const csrf=cookies.find(c=>c.name==='signacore_http_test_login_csrf');
  assert.ok(csrf && csrf.httpOnly && !csrf.secure && csrf.sameSite==='Strict' && csrf.path==='/');
  assert.ok(!cookies.some(c=>c.name.startsWith('__Host-')));
  process.stdout.write('STEP_SMS\n');
  await page.locator('#phone').fill('13912345678');
  await page.locator('button[formaction="/oauth2/login/sms-code"]').click();
  await page.locator('#sms-notice').waitFor();
  const otpPromise=new Promise(resolve=>input.once('line',resolve));process.stdout.write('GET_SMS\n');
  await page.locator('#otp').fill(await otpPromise);
  await page.locator('button[value="sms_login"]').click();await page.waitForURL('https://bff.success.test/**',{timeout:5000});
  const smsCode=new URL(page.url()).searchParams.get('code');assert.ok(smsCode);
  const sms=await backchannel('/oauth2/token',{grant_type:'authorization_code',code:smsCode,redirect_uri:callback,code_verifier:verifier});assert.equal(sms.status,200);
  const smsClaims=JSON.parse(Buffer.from(sms.body.id_token.split('.')[1],'base64url').toString());assert.deepEqual(smsClaims.amr,['sms']);assert.ok(smsClaims.nonce);
  const invalidHint=await backchannel('/oauth2/logout/requests',{id_token_hint:'invalid-id-token'});assert.equal(invalidHint.status,400);assert.ok((await context.cookies(origin)).some(c=>c.name==='signacore_http_test_identity'));
  const smsLogout=await backchannel('/oauth2/logout/requests',{id_token_hint:sms.body.id_token});assert.equal(smsLogout.status,200);
  assert.equal((await page.goto(origin+smsLogout.body.logout_uri)).status(),200);
  await form();
  await page.locator('#username').fill(process.env.SIGNACORE_BROWSER_USERNAME);
  await page.locator('#password').fill(process.env.SIGNACORE_BROWSER_PASSWORD);
  await page.locator('button[value="login"]').click(); await page.waitForURL('https://bff.success.test/**',{timeout:5000});
  process.stdout.write('STEP_LOGIN\n'); let code=new URL(page.url()).searchParams.get('code'); assert.ok(code);
  const wrongVerifier=await backchannel('/oauth2/token',{grant_type:'authorization_code',code,redirect_uri:callback,code_verifier:'E'+verifier.slice(1)});assert.equal(wrongVerifier.status,400);assert.equal(wrongVerifier.body.error,'invalid_grant');
  const login=await backchannel('/oauth2/token',{grant_type:'authorization_code',code,redirect_uri:callback,code_verifier:verifier}); assert.equal(login.status,200); assert.ok(login.body.id_token);
  process.stdout.write('STEP_REPLAY\n'); const replay=await backchannel('/oauth2/token',{grant_type:'authorization_code',code,redirect_uri:callback,code_verifier:verifier}); assert.equal(replay.status,400);
  // Bound replay revokes the first session; establish a second one for reuse/logout checks.
  process.stdout.write('STEP_SECOND_LOGIN\n'); await form(); await page.locator('#username').fill(process.env.SIGNACORE_BROWSER_USERNAME); await page.locator('#password').fill(process.env.SIGNACORE_BROWSER_PASSWORD);
  await page.locator('button[value="login"]').click(); await page.waitForURL('https://bff.success.test/**',{timeout:5000});
  code=new URL(page.url()).searchParams.get('code');
  const second=await backchannel('/oauth2/token',{grant_type:'authorization_code',code,redirect_uri:callback,code_verifier:verifier});assert.equal(second.status,200);
  cookies=await context.cookies(origin);const identity=cookies.find(c=>c.name==='signacore_http_test_identity');
  assert.ok(identity && identity.httpOnly && !identity.secure && identity.sameSite==='Lax' && identity.path==='/');
  await page.goto(authorize());await page.waitForURL('https://bff.success.test/**',{timeout:5000}); assert.ok(new URL(page.url()).searchParams.get('code'));
  process.stdout.write('STEP_RESTART\n'); await restart(); await page.goto(authorize());await page.waitForURL('https://bff.success.test/**',{timeout:5000});assert.ok(new URL(page.url()).searchParams.get('code'));
  process.stdout.write('STEP_LOGOUT\n'); const logout=await backchannel('/oauth2/logout/requests',{id_token_hint:second.body.id_token});assert.equal(logout.status,200);
  const response=await page.goto(origin+logout.body.logout_uri);assert.equal(response.status(),200);
  cookies=await context.cookies(origin);assert.ok(!cookies.some(c=>['signacore_http_test_identity','signacore_http_test_login_csrf'].includes(c.name)));
  const repeated=await page.goto(origin+logout.body.logout_uri);assert.equal(repeated.status(),400);
  await form();
  process.stdout.write('STEP_CSRF\n');
  // Wrong CSRF fails locally with no session; start a fresh continuation for cancel.
  await page.locator('input[name="__RequestVerificationToken"]').evaluateAll(nodes=>nodes.forEach(n=>n.value='invalid-csrf-value'));
  await page.locator('#username').fill(process.env.SIGNACORE_BROWSER_USERNAME);await page.locator('#password').fill(process.env.SIGNACORE_BROWSER_PASSWORD);
  const rejected=page.waitForResponse(r=>r.url()===origin+'/oauth2/login');await page.locator('button[value="login"]').click();assert.equal((await rejected).status(),400);
  assert.ok(!(await context.cookies(origin)).some(c=>c.name==='signacore_http_test_identity'));
  await form(); await page.locator('button[value="cancel"]').click();await page.waitForURL('https://bff.success.test/**',{timeout:5000});assert.equal(new URL(page.url()).searchParams.get('error'),'access_denied');
  process.stdout.write('STEP_INVALID_INPUTS\n'); for(const fields of [{state:'bad'},{nonce:'bad'},{code_challenge:'bad'}]){const r=await page.goto(authorize(fields));assert.equal(r.status(),200);const error=new URL(page.url());assert.equal(error.searchParams.get('error'),'invalid_request');assert.equal(error.searchParams.get('code'),null);}
  process.stdout.write('PASS_BROWSER_COOKIE_TRANSPORT\n');
 } finally {await browser.close();proxy.close();callbackServer.close();input.close();}
})().catch(()=>{process.stderr.write('Browser cookie transport acceptance failed.\n');proxy.close();callbackServer.close();input.close();process.exitCode=1;});
