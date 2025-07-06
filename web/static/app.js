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
