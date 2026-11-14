const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const {webcrypto} = require('node:crypto');
const elements = new Map();
const get = id => {
  if (!elements.has(id)) elements.set(id,{rows:[],replaceChildren(){this.rows=[];},
    insertRow(){const row=[];this.rows.push(row);return {insertCell(){const cell={setAttribute(){}};row.push(cell);return cell;}}}});
  return elements.get(id);
};
const box = vm.createContext({document:{getElementById:get},crypto:webcrypto,TextEncoder,Uint8Array});
vm.runInContext(fs.readFileSync(__dirname+'/static/lab.js','utf8'),box);
(async()=>{
  const options=['Alice','Ben','Cara'].map((value,i)=>({value,dataset:{domain:i===2?'south.example':'north.example',token:'test'}}));
  get('target').options=options;
  for (const selected of options) {
  get('target').selectedOptions=[selected];
  await get('generate').onclick();
  assert.match(get('status').textContent,/Four ciphertext/);
  await get('compare').onclick();
  const results=()=>get('results').rows.map(row=>row[1].textContent);
  assert.deepEqual(results(),['Authenticates · readable','Authentication failed','Authentication failed','Authentication failed']);
  await get('tamper').onclick();
  assert.deepEqual(results(),['Authenticates · readable','Authentication failed']);
  assert.match(get('results').rows[0][0].textContent,new RegExp(selected.value));
  }
  console.log('Incident Lab: real Web Crypto isolation and tamper checks passed.');
})().catch(e=>{console.error(e);process.exitCode=1;});
