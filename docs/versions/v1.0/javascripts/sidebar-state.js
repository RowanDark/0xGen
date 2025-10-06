(function () {
  const STORAGE_KEY = 'glyph.docs.navigationState';

  function loadState() {
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      return stored ? JSON.parse(stored) : {};
    } catch (error) {
      console.warn('Unable to load navigation state', error); // eslint-disable-line no-console
      return {};
    }
  }

  function saveState(state) {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch (error) {
      console.warn('Unable to persist navigation state', error); // eslint-disable-line no-console
    }
  }

  function syncNavigation() {
    const state = loadState();
    const toggles = document.querySelectorAll('[data-md-toggle]');
    toggles.forEach((toggle) => {
      const id = toggle.getAttribute('data-md-toggle');
      if (!id) {
        return;
      }
      if (state[id] === true) {
        toggle.checked = true;
      }
      if (state[id] === false) {
        toggle.checked = false;
      }
      toggle.addEventListener('change', () => {
        state[id] = toggle.checked;
        saveState(state);
      });
    });
  }

  const init = () => window.requestAnimationFrame(syncNavigation);

  if (window.document$ && typeof window.document$.subscribe === 'function') {
    window.document$.subscribe(init);
  }

  if (document.readyState !== 'loading') {
    init();
  } else {
    document.addEventListener('DOMContentLoaded', init);
  }
})();
