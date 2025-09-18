(() => {
  const input = document.getElementById('input');
  const output = document.getElementById('output');

  const mirror = () => {
    if (!output) {
      return;
    }
    output.value = input?.value ?? '';
  };

  input?.addEventListener('input', mirror);
  mirror();
})();
