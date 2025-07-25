(() => {
  const params = new URLSearchParams(window.location.search);
  const success = params.get('success') === 'true';
  const message = success
    ? { type: 'spotify-auth-success', userId: params.get('userId') }
    : { type: 'spotify-auth-failure', error: params.get('error') };
  window.opener?.postMessage(message, '*');
  window.close();
})();
