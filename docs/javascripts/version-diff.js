(function () {
  const GITHUB_REPO = 'https://github.com/RowanDark/0xgen';
  const GITHUB_CHANGELOG = `${GITHUB_REPO}/blob/main/CHANGELOG.md`;

  function init() {
    const targets = Array.from(document.querySelectorAll('[data-version-diff]'));
    if (targets.length === 0) {
      return;
    }

    const docsRoot = resolveDocsRoot('version-diff.js');
    const manifestUrl = new URL('data/doc-versions.json', docsRoot);

    fetch(manifestUrl)
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
        const versions = manifest.versions.map((entry) => ({
          id: entry.id,
          name: entry.name || entry.id,
        }));
        targets.forEach((container) => render(container, versions));
      })
      .catch((error) => {
        console.warn('Unable to build version diff widget', error); // eslint-disable-line no-console
      });
  }

  function render(container, versions) {
    container.innerHTML = '';
    container.classList.add('doc-version-diff--ready');

    const heading = document.createElement('p');
    heading.className = 'doc-version-diff__intro';
    heading.textContent = 'Compare two published releases to review documentation updates.';
    container.appendChild(heading);

    const form = document.createElement('form');
    form.className = 'doc-version-diff__form';
    form.addEventListener('submit', (event) => {
      event.preventDefault();
    });

    const fromField = buildSelect('from', 'From version', versions);
    const toField = buildSelect('to', 'To version', versions);

    const compareButton = document.createElement('a');
    compareButton.className = 'md-button doc-version-diff__action';
    compareButton.target = '_blank';
    compareButton.rel = 'noopener';
    compareButton.textContent = 'Open documentation diff';

    const releaseLink = document.createElement('a');
    releaseLink.className = 'doc-version-diff__secondary';
    releaseLink.target = '_blank';
    releaseLink.rel = 'noopener';
    releaseLink.textContent = 'View release notes';

    const changelogLink = document.createElement('a');
    changelogLink.className = 'doc-version-diff__secondary';
    changelogLink.textContent = 'Open changelog';

    const updateLinks = () => {
      const fromVersion = fromField.select.value;
      const toVersion = toField.select.value;
      if (!fromVersion || !toVersion || fromVersion === toVersion) {
        compareButton.setAttribute('aria-disabled', 'true');
        compareButton.classList.add('doc-version-diff__action--disabled');
        compareButton.removeAttribute('href');
      } else {
        compareButton.removeAttribute('aria-disabled');
        compareButton.classList.remove('doc-version-diff__action--disabled');
        compareButton.href = `${GITHUB_REPO}/compare/${encodeURIComponent(fromVersion)}...${encodeURIComponent(toVersion)}?diff=split`;
      }
      if (toVersion) {
        releaseLink.href = `${GITHUB_REPO}/releases/tag/${encodeURIComponent(toVersion)}`;
      } else {
        releaseLink.removeAttribute('href');
      }
      changelogLink.href = `${GITHUB_CHANGELOG}#${encodeURIComponent(toVersion || fromVersion || '')}`;
    };

    fromField.select.addEventListener('change', updateLinks);
    toField.select.addEventListener('change', updateLinks);

    form.appendChild(fromField.wrapper);
    form.appendChild(toField.wrapper);
    form.appendChild(compareButton);

    container.appendChild(form);

    const secondary = document.createElement('div');
    secondary.className = 'doc-version-diff__secondary-links';
    secondary.appendChild(releaseLink);
    secondary.appendChild(changelogLink);
    container.appendChild(secondary);

    if (versions.length > 1) {
      fromField.select.value = versions[1].id;
      toField.select.value = versions[0].id;
    } else if (versions.length === 1) {
      fromField.select.value = versions[0].id;
      toField.select.value = versions[0].id;
    }
    updateLinks();
  }

  function buildSelect(name, labelText, versions) {
    const wrapper = document.createElement('label');
    wrapper.className = 'doc-version-diff__field';

    const label = document.createElement('span');
    label.className = 'doc-version-diff__label';
    label.textContent = labelText;
    wrapper.appendChild(label);

    const select = document.createElement('select');
    select.name = name;
    select.className = 'doc-version-diff__select';
    versions.forEach((version) => {
      const option = document.createElement('option');
      option.value = version.id;
      option.textContent = version.name;
      select.appendChild(option);
    });
    wrapper.appendChild(select);

    return { wrapper, select };
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

  const initOnce = () => window.requestAnimationFrame(init);
  if (window.document$ && typeof window.document$.subscribe === 'function') {
    window.document$.subscribe(initOnce);
  }

  if (document.readyState !== 'loading') {
    initOnce();
  } else {
    document.addEventListener('DOMContentLoaded', initOnce);
  }
})();
