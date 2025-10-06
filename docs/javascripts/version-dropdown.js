(function () {
  const initialise = () => {
    const header = document.querySelector('.md-header__inner');
    if (!header || header.querySelector('.doc-version-selector')) {
      return;
    }

    const docsRoot = resolveDocsRoot('version-dropdown.js');
    const dataUrl = new URL('data/doc-versions.json', docsRoot);

    fetch(dataUrl)
      .then((response) => {
        if (!response.ok) {
          throw new Error(`Failed to load version manifest: ${response.status}`);
        }
        return response.json();
      })
      .then((manifest) => {
        if (!manifest || !Array.isArray(manifest.versions) || manifest.versions.length === 0) {
          return;
        }
        const versions = manifest.versions.map((version) => {
          const absoluteUrl = new URL(version.url || './', docsRoot);
          return {
            ...version,
            absoluteUrl,
          };
        });

        const currentLocation = new URL(window.location.href);
        const current = versions.find((version) => currentLocation.href.startsWith(version.absoluteUrl.href))
          || versions.find((version) => version.id === manifest.default)
          || versions[0];

        const selector = buildSelector(versions, current);
        header.appendChild(selector);
      })
      .catch((error) => {
        console.warn('Unable to initialise version selector', error); // eslint-disable-line no-console
      });
  };

  const init = () => window.requestAnimationFrame(initialise);
  if (window.document$ && typeof window.document$.subscribe === 'function') {
    window.document$.subscribe(init);
  }

  if (document.readyState !== 'loading') {
    init();
  } else {
    document.addEventListener('DOMContentLoaded', init);
  }

  function buildSelector(versions, current) {
    const wrapper = document.createElement('div');
    wrapper.className = 'doc-version-selector md-header__option';

    const label = document.createElement('label');
    label.className = 'doc-version-selector__label';
    label.textContent = 'Version';
    label.setAttribute('for', 'doc-version-select');

    const select = document.createElement('select');
    select.id = 'doc-version-select';
    select.className = 'doc-version-selector__select';
    versions.forEach((version) => {
      const option = document.createElement('option');
      option.value = version.absoluteUrl.href;
      option.textContent = version.name || version.id;
      if (current && current.id === version.id) {
        option.selected = true;
      }
      select.appendChild(option);
    });
    select.addEventListener('change', (event) => {
      const target = event.target;
      if (target && target.value) {
        window.location.href = target.value;
      }
    });

    wrapper.appendChild(label);
    wrapper.appendChild(select);
    return wrapper;
  }

  function resolveDocsRoot(scriptName) {
    let script = document.currentScript;
    if (!script || !(script.src || '').includes(scriptName)) {
      script = Array.from(document.getElementsByTagName('script')).find((element) =>
        (element.src || '').includes(scriptName),
      );
    }
    if (!script) {
      return new URL('.', window.location.href);
    }
    const scriptUrl = new URL(script.src, window.location.href);
    return new URL('..', scriptUrl);
  }
})();
