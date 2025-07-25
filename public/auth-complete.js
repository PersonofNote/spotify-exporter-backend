(() => {
  const params = new URLSearchParams(window.location.search);
  const success = params.get('success') === 'true';
  const message = success
    ? { type: 'spotify-auth-success', userId: params.get('userId') }
    : { type: 'spotify-auth-failure', error: params.get('error') };

    console.log("✅ popup loaded");
    console.log("📤 posting message:", message);
    console.log("🪟 opener:", window.opener);
  
    if (window.opener) {
      window.opener.postMessage(message, "*");
    } else {
      console.warn("🚫 No opener found");
    }
  // window.opener?.postMessage(message, '*');
  window.close();
})();
