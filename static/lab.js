'use strict';
const $ = id => document.getElementById(id);
const enc = new TextEncoder();
let sample, plaintext;
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
function unhex(s) {
  if (typeof s !== 'string' || !/^(?:[0-9a-f]{2})+$/i.test(s)) throw Error('Invalid hex');
  return Uint8Array.from(s.match(/../g), pair => parseInt(pair, 16));
}
async function seal(label, raw) {
  const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode(label)}, key, enc.encode('Fictional project file: '+label));
  return {format:'keyguard-lab-v1',label,nonce:hex(iv),ciphertext:hex(new Uint8Array(cipher))};
}
async function open(raw, record) {
  if (raw.length!==32 || record.format!=='keyguard-lab-v1' || typeof record.label!=='string') throw Error('Invalid lab artifact');
  const iv=unhex(record.nonce);
  if (iv.length!==12) throw Error('Invalid nonce');
  const key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);
  return crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:enc.encode(record.label)},key,unhex(record.ciphertext));
}
function download(bytes,name) {
  const url=URL.createObjectURL(new Blob([bytes],{type:'application/octet-stream'}));
  const a=document.createElement('a'); a.href=url; a.download=name; a.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function rows(items) {
  $('results').replaceChildren();
  for (const item of items) {
    const tr=$('results').insertRow();
    tr.insertCell().textContent=item[0];
    const result=tr.insertCell();
    result.textContent=item[1]?'Authenticates · readable':'Authentication failed';
    result.setAttribute('data-result',item[1]?'pass':'fail');
  }
}
function resetSample() {
  sample=null;
  ['steal','save','compare','tamper'].forEach(id=>$(id).disabled=true);
  $('status').textContent='';
  rows([]);
}
$('target').onchange=resetSample;
$('generate').onclick=async () => {
  resetSample();
  const selector=$('target');
  const option=selector.selectedOptions[0];
  const target={name:option.value,domain:option.dataset.domain,token:option.dataset.token};
  $('generate').disabled=selector.disabled=true;
  try {
    const random=()=>crypto.getRandomValues(new Uint8Array(32));
    const leaked=random();
    const other=Array.from(selector.options).filter(o=>o.value!==target.name);
    const label=target.domain+' · '+target.name;
    const records=await Promise.all([
      seal(label+' · original v1',leaked),
      seal(label+' · rotated v2',random()),
      ...other.map(o=>seal(o.dataset.domain+' · '+o.value+' · v1',random()))
    ]);
    sample={leaked,records,target};
    $('status').textContent='Four ciphertext samples ready for '+target.name+
      (target.token ? '. Simulate key theft to notify Admin and '+target.name+'.'
                    : '. An active workspace key is required to send an incident alert.');
    $('steal').disabled=!target.token;
    ['compare','tamper'].forEach(id=>$(id).disabled=false);
  } catch (_) { $('status').textContent='Could not generate samples. Open the lab from localhost in a browser with Web Crypto.'; }
  finally { $('generate').disabled=selector.disabled=false; }
};
$('steal').onclick=async ()=>{
  const button=$('steal');
  button.disabled=true;
  $('generate').disabled=$('target').disabled=true;
  try {
    const body=new URLSearchParams({csrf:button.dataset.csrf,target:sample.target.token});
    const response=await fetch(button.dataset.url,{method:'POST',body});
    const result=await response.json();
    $('status').textContent=result.message;
    if(response.ok) $('save').disabled=false;
    else button.disabled=false;
  } catch (_) {
    $('status').textContent='Could not send the incident alert. Try again.';
    button.disabled=false;
  } finally { $('generate').disabled=$('target').disabled=false; }
};
$('save').onclick=()=>{
  const name=sample.target.name.toLowerCase();
  download(hex(sample.leaked),'leaked-'+name+'-v1.txt');
  download(JSON.stringify(sample.records[0]),name+'-original.encrypted.json');
};
async function check(record,raw) {
  try { await open(raw,record); return true; } catch (_) { return false; }
}
$('compare').onclick=async ()=>{
  const {records,leaked}=sample;
  rows(await Promise.all(records.map(async r=>[r.label,await check(r,leaked)])));
};
$('tamper').onclick=async ()=>{
  const {records,leaked}=sample;
  const original=records[0], bytes=unhex(original.ciphertext);
  bytes[0]^=1;
  rows([[original.label,await check(original,leaked)],['Same ciphertext with one byte changed',await check({...original,ciphertext:hex(bytes)},leaked)]]);
};
$('manual').onsubmit=async e=>{
  e.preventDefault();
  plaintext=null; $('plain').hidden=true;
  try {
    const data=new FormData(e.target);
    const key=data.get('key'), cipher=data.get('cipher');
    if (key.size>1024 || cipher.size>1024*1024) throw Error('File too large');
    plaintext=await open(unhex((await key.text()).trim()),JSON.parse(await cipher.text()));
    $('manual-result').textContent='Authentication passed. The decrypted sample is ready.';
    $('plain').hidden=false;
  } catch (_) { $('manual-result').textContent='Decryption failed: wrong key, damaged ciphertext, or invalid lab artifact.'; }
};
$('plain').onclick=()=>{ if(plaintext) download(plaintext,'decrypted-lab-sample.txt'); };
