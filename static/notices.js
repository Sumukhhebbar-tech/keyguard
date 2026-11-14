'use strict';
const notice = document.getElementById('incident-notice');
const message = document.getElementById('incident-message');
let busy = false;
async function refreshNotice() {
  if (busy) return;
  busy = true;
  try {
    const response = await fetch(notice.dataset.url);
    if (!response.ok) return;
    const state = await response.json();
    if (message.textContent !== state.message) message.textContent = state.message;
    notice.hidden = !state.message;
  } catch (_) { /* Keep the last displayed notice during a temporary outage. */ }
  finally { busy = false; }
}
setInterval(refreshNotice, 5000);
window.addEventListener('focus', refreshNotice);
