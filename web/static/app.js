// Utility functions and HTMX-compatible handlers for the UI

// Utility to find cert content in DOM by account and which
function getCertContentFromDOM(accountId, which) {
  // Prefer the pre we render with id="{which}-content-{accountId}"
  const preId = `${which}-content-${accountId}`;
  const pre = document.getElementById(preId);
  if (pre && pre.textContent && pre.textContent.trim().length > 0) {
    return pre.textContent;
  }
  // Fallback: look for the row and scan for a pre tag within it
  const row = document.getElementById(`${which}-row-${accountId}`);
  if (row) {
    const preInRow = row.querySelector('pre');
    if (preInRow && preInRow.textContent && preInRow.textContent.trim().length > 0) {
      return preInRow.textContent;
    }
  }
  return null;
}

/**
 * @typedef {Object}  UnsignedNostrEvent
 * @property {number} created_at  - should be a unix timestamp
 * @property {number} kind
 * @property {Array[][]} tags
 * @property {string} content
 */
/**
 * @typedef {Object}  SignedNostrEvent
 * @property {number} created_at  - should be a unix timestamp
 * @property {number} kind
 * @property {Array[][]} tags
 * @property {string} content
 * @property {string} id
 * @property {string} sig
 * @property {string} pubkey
 */


/** 
 *
 * @argument {UnsignedNostrEvent} event
 *
 * @returns {Promise<SignedNostrEvent>} 
 */
async function sign_nostr_event(event) {
    if (!window.nostr) {
        throw Error("window nostr is not set. You need to a nip-07 extension")

    }
    /**
    @type {SignedNostrEvent}
    */
    let signedEvent = await window.nostr.signEvent(event)

    return signedEvent
}


/** 
     *@type {HTMLDivElement}
     */
const loginContainer = document.getElementById("loginContainer")
console.log({ loginContainer })
if (loginContainer) {
    loginContainer.addEventListener("submit", async (e) => {
        e.preventDefault();

        /** @type {UnsignedNostrEvent}*/
        const eventToSign = {
            created_at: Math.floor(Date.now() / 1000),
            kind: 27235,
            tags: [],
            content: loginContainer.nonce,
        };

        const signedEvent =  await sign_nostr_event(eventToSign);

        const loginRequest = new Request("/login", {
          method: "POST",
          body: JSON.stringify(signedEvent),
        });

        fetch(loginRequest)
          .then((res) => {
            if (res.ok) {
              window.location.href = "/";
            } else {
              const targetHeader = res.headers.get("HX-RETARGET");

              if (window.htmx && targetHeader) {
                res
                  .text()
                  .then((text) => {
                    window.htmx.swap(`#${targetHeader}`, text, {
                      swapStyle: "innerHTML",
                    });
                  })
                  .catch((err) => {
                    console.log({ errText: err });
                  });
              }
            }
          })
          .catch((err) => {
            console.log("Error message");
            console.log({ err });
          });
    })
}

// Copy cert content to clipboard when clicking copy buttons
document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.cert-copy-btn');
    if (!btn) return;

    // Find account/which from data attributes
    const accountId = btn.getAttribute('data-account');
    const which = btn.getAttribute('data-which');
    if (!accountId || !which) return;

    try {
        // First try to copy from the DOM (preferred if already open)
        let text = getCertContentFromDOM(accountId, which);

        // If not found, also check for HTMX swapped content in the row
        if (!text) {
          const row = document.getElementById(`${which}-row-${accountId}`);
          if (row) {
            const preInRow = row.querySelector('pre');
            if (preInRow && preInRow.textContent && preInRow.textContent.trim().length > 0) {
              text = preInRow.textContent;
            }
          }
        }

        // If still not found, fetch the open fragment from server and parse
        if (!text) {
            const res = await fetch(`/cert/${accountId}/${which}`);
            if (!res.ok) {
                console.error('failed to fetch cert fragment', res.status);
                return;
            }
            const html = await res.text();

            // Create a temporary container to parse
            const tmp = document.createElement('div');
            tmp.innerHTML = html;
            // Prefer specifically id'ed pre if present
            const pre = tmp.querySelector(`#${which}-content-${accountId}`) || tmp.querySelector('pre');
            text = pre ? pre.textContent : null;
        }

        if (!text) {
            console.error('no cert content found to copy');
            return;
        }

        await navigator.clipboard.writeText(text);
        // give feedback by changing button text briefly
        const original = btn.innerHTML;
        btn.innerHTML = '✅';
        setTimeout(() => btn.innerHTML = original, 1500);
    } catch (err) {
        console.error('copy failed', err);
    }
});

// Setup name editing behavior for cards (toggle save button visibility)
function setupCardNameEditing() {
  document.querySelectorAll('.card-name-input').forEach((input) => {
    const form = input.closest('form');
    if (!form) return;
    const saveBtn = form.querySelector('.card-save-btn');
    if (!saveBtn) return;

    const getDefault = () => (input.getAttribute('data-default') || '').trim();

    const syncButton = () => {
      const changed = input.value.trim() !== getDefault();
      saveBtn.classList.toggle('hidden', !changed);
    };

    // Update visibility on input
    input.addEventListener('input', syncButton);

    // On form submit, hide save button and mark busy to avoid double submissions
    form.addEventListener('submit', () => {
      saveBtn.classList.add('hidden');
      saveBtn.setAttribute('aria-busy', 'true');
    });

    // Initialize
    syncButton();
  });
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  setupCardNameEditing();
});

// Re-initialize after HTMX swaps new content so new inputs get behavior attached
if (typeof document !== 'undefined') {
  document.body.addEventListener('htmx:afterSwap', (evt) => {
    setupCardNameEditing();
  });
}
