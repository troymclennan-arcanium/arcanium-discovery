'use strict';
// Static GitHub Pages cannot authenticate a person. All sensitive catalog fields and
// asset bytes are encrypted. Never store the passcode or key in browser storage.
const $ = (id) => document.getElementById(id);
const dec = new TextDecoder();
let passcode = null;
let pub = null;
let unlocked = null;
const MAGIC = [65, 82, 67, 54, 1];
const encode = (text) => new TextEncoder().encode(text);
const hex = (bytes) => [...new Uint8Array(bytes)].map(x=>x.toString(16).padStart(2,'0')).join('');
async function digest(bytes){return hex(await crypto.subtle.digest('SHA-256',bytes));}
async function get(url){const r=await fetch(url,{cache:'no-store',credentials:'omit'});if(!r.ok)throw Error('Cannot retrieve encrypted file');return new Uint8Array(await r.arrayBuffer());}
async function decrypt(buf, secret, aad){
  if(buf.length<49 || MAGIC.some((v,i)=>buf[i]!==v))throw Error('Invalid encrypted file');
  const salt=buf.slice(5,21),nonce=buf.slice(21,33),ct=buf.slice(33);
  const k=await crypto.subtle.importKey('raw',encode(secret),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:pub.iterations,hash:'SHA-256'},k,{name:'AES-GCM',length:256},false,['decrypt']);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:nonce,additionalData:encode(aad)},key,ct);
  return new Uint8Array(pt);
}
function status(t,error){$('status').textContent=t;$('status').className=error?'status-error':'';}
function render(search=''){
  const target=$('list');target.replaceChildren();
  const list=unlocked.assets.filter(a=>(a.filename+' '+a.family+' '+a.format).toLowerCase().includes(search.toLowerCase()));
  $('count').textContent=list.length+' downloadable items';
  for(const a of list){
    const item=document.createElement('div');item.className='item';
    const details=document.createElement('div');const name=document.createElement('strong');name.textContent=a.filename;
    const meta=document.createElement('p');meta.textContent=a.family+' · '+a.format.toUpperCase()+' · '+Math.ceil(a.bytes/1024)+' KB · SHA-256 '+a.sha256.slice(0,12);
    const button=document.createElement('button');button.type='button';button.textContent='Download';button.setAttribute('aria-label','Download '+a.filename);
    button.addEventListener('click',()=>download(a,button));details.append(name,meta);item.append(details,button);target.append(item);
  }
}
async function download(a,button){
  button.disabled=true;button.textContent='Decrypting…';
  try{
    if(!passcode||!unlocked)throw Error('Session is locked');
    const enc=await get(a.path);
    if(await digest(enc)!==a.cipher_sha256)throw Error('Encrypted file checksum mismatch');
    const pt=await decrypt(enc,passcode,'ARC6:v1:'+pub.release+':'+a.id);
    if(pt.length!==a.bytes||await digest(pt)!==a.sha256)throw Error('Decrypted file checksum mismatch');
    const url=URL.createObjectURL(new Blob([pt],{type:a.type||'application/octet-stream'}));
    const link=document.createElement('a');link.href=url;link.download=a.filename;document.body.append(link);link.click();link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),5000);
  }catch(e){status('Download failed: '+e.message,true);}
  finally{button.disabled=false;button.textContent='Download';}
}
function lock(){passcode=null;unlocked=null;$('passcode').value='';$('heading').textContent='Brand files';$('gate').hidden=false;$('catalog').hidden=true;$('list').replaceChildren();$('search').value='';status('Locked');}
async function unlock(){
  const attempted=$('passcode').value;
  if(attempted.length<24){status('Enter the complete project passcode',true);return;}
  $('unlock').disabled=true;status('Opening encrypted catalog…');
  try{
    const enc=await get(pub.catalog);
    if(await digest(enc)!==pub.catalog_sha256)throw Error('Catalog integrity error');
    const plain=await decrypt(enc,attempted,'ARC6:v1:'+pub.release+':catalog');
    const catalog=JSON.parse(dec.decode(plain));
    if(catalog.release_id!==pub.release||!Array.isArray(catalog.assets)||catalog.assets.length!==pub.encrypted_objects)throw Error('Inconsistent release manifest');
    passcode=attempted;unlocked=catalog;$('passcode').value='';
    $('heading').textContent=catalog.brand+' — brand files';$('gate').hidden=true;$('catalog').hidden=false;
    $('notice').textContent=(catalog.notice||'Encrypted brand assets')+' · This is a public site carrying encrypted files.';
    render();status('');
  }catch(e){passcode=null;unlocked=null;status('Unable to unlock: wrong passcode or corrupted catalog',true);}
  finally{$('unlock').disabled=false;}
}
async function init(){try{const response=await fetch('current.json',{cache:'no-store'});if(!response.ok)throw Error('Release unavailable');pub=await response.json();if(pub.format!=='arcanium-pages-ciphertext-v1'||pub.iterations!==600000)throw Error('Unsupported encrypted release');}catch(e){status('The encrypted release is not available',true);$('unlock').disabled=true;}}
$('unlock').addEventListener('click',unlock);$('passcode').addEventListener('keydown',e=>{if(e.key==='Enter')unlock();});$('lock').addEventListener('click',lock);$('search').addEventListener('input',e=>render(e.target.value));init();
