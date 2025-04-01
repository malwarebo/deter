// Example Worker Script (worker.js)

// Configuration (Ensure these are set in wrangler.toml or Dashboard environment variables)
// - TARGET_ZONE_ID: Your Cloudflare Zone ID (used to construct KV key)
// - KV_NAMESPACE: Binding name for your KV Namespace (e.g., ATTACK_STATUS_KV)

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Avoid applying logic to non-page assets if desired (optional)
    // if (url.pathname.match(/\.(css|js|jpg|png|gif|ico)$/)) {
    //   return fetch(request);
    // }

    // --- Determine Attack Status ---
    let attackStatus = "inactive"; // Default: assume safe
    const zoneId = env.TARGET_ZONE_ID;
    const kvBinding = env.KV_NAMESPACE; // Use the binding name configured

    if (!zoneId) {
      console.error(
        "Worker ERROR: TARGET_ZONE_ID environment variable not set!"
      );
      // Fail open or closed? For security, might challenge/block if config missing
      // return new Response("Configuration Error", { status: 500 });
    }
    if (!kvBinding) {
      console.error("Worker ERROR: KV Namespace binding not configured!");
      // return new Response("Configuration Error", { status: 500 });
    }

    const kvKey = `attack_status_zone_${zoneId}`;
    let kvReadError = false;

    if (zoneId && kvBinding) {
      try {
        const status = await kvBinding.get(kvKey);
        if (status === "active") {
          attackStatus = "active";
          console.log(`Worker INFO: KV Status for ${kvKey} is 'active'.`);
        } else {
          console.log(
            `Worker INFO: KV Status for ${kvKey} is '${status}'. Treating as inactive.`
          );
        }
      } catch (e) {
        console.error(`Worker ERROR: KV GET failed for key ${kvKey}: ${e}`);
        kvReadError = true;
        // Decide how to handle KV errors: fail open (inactive) or fail closed (active)?
        // Failing open might be safer for user experience, but less secure during actual failure.
        // attackStatus = 'active'; // Example: Fail closed (treat as attack)
      }
    } else {
      attackStatus = "inactive"; // Cannot check status if config is missing
      console.error(
        "Worker WARN: Cannot check attack status due to missing config. Assuming inactive."
      );
    }

    // --- Apply Mitigation if Attack Active ---
    if (attackStatus === "active") {
      console.log(
        `Worker INFO: Attack ACTIVE for ${url.pathname}. Applying mitigation.`
      );

      // --- Mitigation Option: Simple Proof-of-Work (Conceptual Example) ---
      // This requires client-side JS to solve and resubmit. A library like 'hashcash-browser'
      // or a custom implementation would be needed for a real solution.
      // This example just shows the flow: Check for solution, if missing, send challenge.

      const powHeader = "X-Pow-Solution";
      const solution = request.headers.get(powHeader);

      // Basic check - Needs proper validation logic!
      if (solution && solution.startsWith("solved:")) {
        console.log(
          `Worker INFO: Received potential PoW solution. Allowing request (validation needed).`
        );
        // Allow request to proceed to origin/cache AFTER validation
        return fetch(request);
      } else {
        // Send PoW Challenge HTML/JS
        console.log(
          `Worker INFO: No valid PoW solution found. Sending challenge page.`
        );
        const difficulty = 20; // Example difficulty
        const challengeNonce = Math.random().toString(36).substring(2); // Unique nonce per challenge

        const challengeHtml = generatePowChallengeHtml(
          request.method,
          url.href,
          difficulty,
          challengeNonce,
          powHeader
        );
        return new Response(challengeHtml, {
          status: 403, // Forbidden - Requires action
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control":
              "no-store, no-cache, must-revalidate, proxy-revalidate", // Prevent caching of challenge
            Pragma: "no-cache",
            Expires: "0",
          },
        });
      }

      // --- Mitigation Option 2: Trigger Cloudflare Managed Challenge (Requires Enterprise Plan typically) ---
      /*
      console.log(`Worker INFO: Triggering Cloudflare Managed Challenge for ${url.pathname}`);
      // This often involves returning a specific response that CF interprets
      // It might be a 403 status with specific headers, or using Firewall Rules triggered by Go.
      // The simplest might be the Go app enabling a Firewall Rule with action "managed_challenge".
      // If you *can* trigger from Worker:
      return new Response('Managed Challenge Required', {
          status: 403, // Check CF docs for correct status/headers
          // headers: { 'X-CF-Enable-Managed-Challenge': 'true' } // Hypothetical header
      });
      */

      // --- Mitigation Option 3: Trigger Cloudflare Turnstile (Recommended over CAPTCHA) ---
      /*
      console.log(`Worker INFO: Presenting Cloudflare Turnstile challenge for ${url.pathname}`);
      // You'd typically embed the Turnstile widget JS/HTML snippet here.
      // The verification happens server-side (either in this worker on a subsequent request,
      // or passed to your origin). This is more complex than simple PoW.
      const turnstileSiteKey = env.TURNSTILE_SITE_KEY; // Needs env var
      if (!turnstileSiteKey) return new Response("Turnstile not configured", { status: 500 });

      const turnstileHtml = `... HTML with Turnstile widget using site key ${turnstileSiteKey} ...`;
      return new Response(turnstileHtml, { status: 403, headers: { 'Content-Type': 'text/html'} });
      */
    } else {
      // Attack status is inactive, proceed normally
      // console.log(`Worker INFO: Attack INACTIVE for ${url.pathname}. Proceeding.`);
      return fetch(request); // Forward request to origin or cache
    }
  },
};

// --- Helper Function for Conceptual PoW Challenge Page ---
function generatePowChallengeHtml(
  method,
  originalUrl,
  difficulty,
  nonce,
  solutionHeader
) {
  // IMPORTANT: This client-side PoW is basic and illustrative.
  // Use robust libraries for actual hashing and difficulty adjustment.
  // This example simulates work with setTimeout.
  return `
<!DOCTYPE html>
<html>
<head>
    <title>Verifying Connection</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>body{font-family: sans-serif; padding: 20px;}</style>
</head>
<body>
    <h1>Verifying your connection...</h1>
    <p>This page helps protect against automated attacks. Please wait.</p>
    <p id="status">Starting security check...</p>
    <progress id="progress" max="100" value="0"></progress>

    <script>
      const difficulty = ${difficulty}; // How many leading zeros (example)
      const nonce = "${nonce}";
      const originalUrl = "${originalUrl}";
      const solutionHeader = "${solutionHeader}";
      const method = "${method}"; // Original request method

      async function solveChallenge() {
        const statusEl = document.getElementById('status');
        const progressEl = document.getElementById('progress');
        statusEl.textContent = 'Performing security check... (Difficulty: ${difficulty})';

        console.log('Starting PoW calculation...');
        let counter = 0;
        let solution = '';
        const targetPrefix = '0'.repeat(difficulty); // Simplified target

        // Simulate finding a hash with leading zeros (replace with real crypto hash)
        const startTime = Date.now();
        while (true) {
            counter++;
            const dataToHash = nonce + ':' + counter;
            // In real PoW, hash dataToHash (e.g., SHA-256)
            // const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(dataToHash));
            // const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');

            // *** SIMULATION ***
            const simulatedHash = Math.random().toString(16).substring(2); // Fake hash
            if (counter % 1000 === 0) { // Update progress periodically
                 progressEl.value = (counter / (1000 * difficulty)) * 100 % 100; // Very rough progress
                 await new Promise(resolve => setTimeout(resolve, 1)); // Prevent blocking UI thread
            }

            // Replace with actual hash check: if (hashHex.startsWith(targetPrefix))
            if (Math.random() < 0.00001 * (15/difficulty) ) { // Simulate finding solution eventually
                solution = 'solved:' + nonce + ':' + counter; // Example solution format
                console.log('PoW solution found:', solution);
                break;
            }
             if (Date.now() - startTime > 20000) { // Timeout
                 statusEl.textContent = 'Verification timed out. Please reload.';
                 console.error('PoW timed out');
                 return; // Stop trying
             }
        }

        statusEl.textContent = 'Verification successful. Reloading page...';
        progressEl.value = 100;

        // Retry the original request with the solution header
        try {
            const headers = new Headers();
            headers.append(solutionHeader, solution);
            // Add other necessary headers? Be careful about passing all original headers.
             headers.append('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8');


            const response = await fetch(originalUrl, {
                method: method, // Use original method
                headers: headers,
                redirect: 'manual' // Handle redirects manually if needed based on response
                // Body handling for POST/PUT etc. is complex from client-side JS like this
            });

             // Check if the server accepted the solution (e.g., not another 403)
            if (response.ok || response.status === 302 || response.status === 301) { // Allow OK or redirects
                 // Replace current page content or redirect
                 window.location.replace(originalUrl); // Simplest is often to just reload
             } else {
                 statusEl.textContent = 'Verification rejected by server (' + response.status + '). Please try reloading.';
                 console.error('Server rejected PoW solution:', response.status);
             }

        } catch (err) {
            statusEl.textContent = 'Failed to submit verification. Please check your connection and reload.';
            console.error('Fetch error during PoW submission:', err);
        }
      }

      // Start the process after slight delay for rendering
      setTimeout(solveChallenge, 100);
    </script>
</body>
</html>
  `;
}
