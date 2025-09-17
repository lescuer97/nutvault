// App JS: login support, certificate copy, and simplified save-button behavior for editable card name

// ----------------------
// Helper: find cert content in DOM by account and which
function getCertContentFromDOM(accountId, which) {
  const preId = `${which}-content-${accountId}`;
  const pre = document.getElementById(preId);
  if (pre && pre.textContent && pre.textContent.trim().length > 0) {
    return pre.textContent;
  }
  const row = document.getElementById(`${which}-row-${accountId}`);
  if (row) {
    const preInRow = row.querySelector('pre');
    if (preInRow && preInRow.textContent && preInRow.textContent.trim().length > 0) {
      return preInRow.textContent;
    }
  }
  return null;
}

// ----------------------
// Login (Nostr sign and submit)
async function sign_nostr_event(event) {
  if (!window.nostr) {
    throw Error("window nostr is not set. You need a NIP-07 extension");
  }
  let signedEvent = await window.nostr.signEvent(event);
  return signedEvent;
}

function initLogin() {
  const loginContainer = document.getElementById("loginContainer");
  if (!loginContainer) return;

  loginContainer.addEventListener("submit", async (e) => {
    e.preventDefault();

    const eventToSign = {
      created_at: Math.floor(Date.now() / 1000),
      kind: 27235,
      tags: [],
      content: loginContainer.nonce,
    };

    try {
      const signedEvent = await sign_nostr_event(eventToSign);
      const loginRequest = new Request("/login", {
        method: "POST",
        body: JSON.stringify(signedEvent),
      });

      const res = await fetch(loginRequest);
      if (res.ok) {
        window.location.href = "/";
      } else {
        const targetHeader = res.headers.get("HX-RETARGET");
        if (window.htmx && targetHeader) {
          const text = await res.text();
          window.htmx.swap(`#${targetHeader}`, text, { swapStyle: "innerHTML" });
        }
      }
    } catch (err) {
      console.log("Login error", err);
    }
  });
}

// ----------------------
// Copy certificate content to clipboard
function initCertCopy() {
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.cert-copy-btn');
    if (!btn) return;

    const accountId = btn.getAttribute('data-account');
    const which = btn.getAttribute('data-which');
    if (!accountId || !which) return;

    try {
      let text = getCertContentFromDOM(accountId, which);
      if (!text) {
        const res = await fetch(`/cert/${accountId}/${which}`);
        if (!res.ok) {
          console.error('failed to fetch cert fragment', res.status);
          return;
        }
        const html = await res.text();
        const tmp = document.createElement('div');
        tmp.innerHTML = html;
        const pre = tmp.querySelector(`#${which}-content-${accountId}`) || tmp.querySelector('pre');
        text = pre ? pre.textContent : null;
      }

      if (!text) {
        console.error('no cert content found to copy');
        return;
      }

      await navigator.clipboard.writeText(text);
      const original = btn.innerHTML;
      btn.innerHTML = '✅';
      setTimeout(() => btn.innerHTML = original, 1500);
    } catch (err) {
      console.error('copy failed', err);
    }
  });
}

// ----------------------
// Simplified: show Save button only when input.value !== input.defaultValue
function initCardInputs(root = document) {
  root.querySelectorAll('.card-name-input').forEach((input) => {
    const form = input.closest('form');
    if (!form) return;
    const saveBtn = form.querySelector('.card-save-btn');
    if (!saveBtn) return;

    const update = () => {
      if (input.value !== input.defaultValue) {
        saveBtn.classList.remove('hidden');
      } else {
        saveBtn.classList.add('hidden');
      }
    };

    input.addEventListener('input', update);
    input.addEventListener('change', update);

    // initialize
    update();

    form.addEventListener('submit', () => {
      saveBtn.classList.add('hidden');
      saveBtn.setAttribute('aria-busy', 'true');
    });
  });
}

// ----------------------
// Boot
document.addEventListener('DOMContentLoaded', () => {
  initLogin();
  initCertCopy();
  initCardInputs();
});

// Re-init card inputs after HTMX swaps (new fragments)
if (typeof document !== 'undefined') {
  document.body.addEventListener('htmx:afterSwap', (e) => {
    const root = e && e.target ? e.target : document;
    initCardInputs(root);
  });
}
