const { createClient } = require('@supabase/supabase-js');
function send(res, status, body){res.status(status).setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');return res.end(JSON.stringify(body));}
function authorized(req,res){const expected=process.env.CASE_MEMORY_ACCESS_KEY;if(!expected)return send(res,503,{error:'CASE_MEMORY_ACCESS_KEY is not configured'}),false;const supplied=req.headers['x-app-key'];if(!supplied||supplied!==expected){send(res,401,{error:'Invalid app access key'});return false;}return true;}
function supabase(){if(!process.env.SUPABASE_URL||!process.env.SUPABASE_SERVICE_ROLE_KEY)throw new Error('Supabase environment variables are not configured');return createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false,autoRefreshToken:false}})}
module.exports={send,authorized,supabase};
