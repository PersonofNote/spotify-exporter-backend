(() => {
    const pollInterval = 1000;
    let attempts = 0;
    const maxAttempts = 30;

    async function pollStatus() {
      try {
        const res = await fetch('/api/status', { credentials: 'include' });
        const data = await res.json();
        if (data.authenticated) {
          console.log("Auth complete. Closing popup.");
          window.close();
          return;
        }
      } catch (err) {
        console.error('Polling failed:', err);
      }

      attempts++;
      if (attempts < maxAttempts) {
        setTimeout(pollStatus, pollInterval);
      } else {
        alert("Login timed out. Please try again.");
        window.close();
      }
    }

    pollStatus();
})();
