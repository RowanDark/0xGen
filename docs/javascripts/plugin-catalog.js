(function () {
  const docsRoot = resolveDocsRoot('plugin-catalog.js');
  let cachedPlugins = null;

  const slugify = (value) =>
    (value || '')
      .toString()
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 50);

  const initialise = () => {
    const container = document.getElementById('plugin-catalog');
    if (!container || container.dataset.catalogInitialised) {
      return;
    }

    const searchField = document.getElementById('plugin-search');
    const languageFilter = document.getElementById('plugin-language');
    const categoryFilter = document.getElementById('plugin-category');
    if (!searchField || !languageFilter || !categoryFilter) {
      return;
    }

    container.dataset.catalogInitialised = 'true';
    container.setAttribute('role', 'list');
    container.setAttribute('aria-live', 'polite');
    container.setAttribute('aria-busy', 'true');

    const emptyState = document.createElement('p');
    emptyState.className = 'plugin-catalog__empty';
    emptyState.textContent = 'No plugins match the selected filters yet.';
    emptyState.setAttribute('role', 'status');
    emptyState.setAttribute('aria-live', 'polite');
    emptyState.tabIndex = -1;

    const dataUrl = new URL('data/plugin-catalog.json', docsRoot);

    const loadPlugins = cachedPlugins
      ? Promise.resolve(cachedPlugins)
      : fetch(dataUrl).then((response) => {
          if (!response.ok) {
            throw new Error(`Failed to load plugin catalogue: ${response.status}`);
          }
          return response.json();
        });

    loadPlugins
      .then((plugins) => {
        cachedPlugins = plugins;
        renderFilters(plugins, languageFilter, categoryFilter);
        renderCatalog(plugins, container, emptyState);

        const handleFilterChange = () => {
          const query = (searchField.value || '').trim().toLowerCase();
          const language = languageFilter.value;
          const category = categoryFilter.value;
          const filtered = plugins.filter((plugin) => {
            if (language && plugin.language !== language) {
              return false;
            }
            const pluginCategories = plugin.categories || [];
            if (category && !pluginCategories.includes(category)) {
              return false;
            }
            if (!query) {
              return true;
            }
            const haystack = [
              plugin.name,
              plugin.summary,
              plugin.author,
              plugin.language,
              ...(plugin.capabilities || []),
              ...pluginCategories,
            ]
              .join(' ')
              .toLowerCase();
            return haystack.includes(query);
          });
          renderCatalog(filtered, container, emptyState);
        };

        searchField.addEventListener('input', handleFilterChange);
        languageFilter.addEventListener('change', handleFilterChange);
        categoryFilter.addEventListener('change', handleFilterChange);
      })
      .catch((error) => {
        console.error(error); // eslint-disable-line no-console
        container.innerHTML = '';
        const failure = document.createElement('p');
        failure.className = 'plugin-catalog__empty';
        failure.textContent = 'Unable to load the plugin catalogue. Please try reloading the page.';
        failure.setAttribute('role', 'alert');
        failure.tabIndex = -1;
        container.appendChild(failure);
        container.setAttribute('aria-busy', 'false');
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

  function renderFilters(plugins, languageFilter, categoryFilter) {
    const languages = new Set();
    const categories = new Set();
    plugins.forEach((plugin) => {
      if (plugin.language) {
        languages.add(plugin.language);
      }
      (plugin.categories || []).forEach((category) => categories.add(category));
    });

    Array.from(languages)
      .sort((a, b) => a.localeCompare(b))
      .forEach((language) => {
        const option = document.createElement('option');
        option.value = language;
        option.textContent = language;
        languageFilter.appendChild(option);
      });

    Array.from(categories)
      .sort((a, b) => a.localeCompare(b))
      .forEach((category) => {
        const option = document.createElement('option');
        option.value = category;
        option.textContent = category;
        categoryFilter.appendChild(option);
      });
  }

  function renderCatalog(plugins, container, emptyState) {
    container.setAttribute('aria-busy', 'true');
    container.innerHTML = '';
    if (!plugins.length) {
      container.appendChild(emptyState);
      if (typeof emptyState.focus === 'function') {
        emptyState.focus({ preventScroll: true });
      }
      container.setAttribute('aria-busy', 'false');
      return;
    }

    plugins.forEach((plugin) => {
      container.appendChild(renderPlugin(plugin));
    });
    container.setAttribute('aria-busy', 'false');
  }

  function renderPlugin(plugin) {
    const card = document.createElement('article');
    card.className = 'plugin-card';
    card.setAttribute('role', 'listitem');
    card.tabIndex = 0;

    const cardIdentifier = slugify(plugin.id || plugin.name || 'plugin');
    if (cardIdentifier) {
      card.id = `plugin-${cardIdentifier}`;
    }

    const header = document.createElement('header');
    header.className = 'plugin-card__header';

    const title = document.createElement('h3');
    title.className = 'plugin-card__title';
    title.textContent = plugin.name || plugin.id;
    const titleId = card.id ? `${card.id}-title` : `plugin-title-${Math.random().toString(36).slice(2)}`;
    title.id = titleId;
    card.setAttribute('aria-labelledby', titleId);

    const version = document.createElement('span');
    version.className = 'plugin-card__version';
    version.textContent = plugin.version ? `v${plugin.version}` : 'Unversioned';

    header.appendChild(title);
    header.appendChild(version);

    const meta = document.createElement('p');
    meta.className = 'plugin-card__meta';
    meta.textContent = [plugin.language, plugin.author].filter(Boolean).join(' • ');

    const summary = document.createElement('p');
    summary.className = 'plugin-card__summary';
    summary.textContent = plugin.summary || 'No summary provided yet.';
    const summaryId = card.id ? `${card.id}-summary` : `${titleId}-summary`;
    summary.id = summaryId;
    card.setAttribute('aria-describedby', summaryId);

    const capabilities = document.createElement('ul');
    capabilities.className = 'plugin-card__capabilities';
    (plugin.capabilities || []).forEach((cap) => {
      const chip = document.createElement('li');
      chip.textContent = cap.replace(/^CAP_/, '').toLowerCase().replace(/_/g, ' ');
      capabilities.appendChild(chip);
    });

    const categories = document.createElement('ul');
    categories.className = 'plugin-card__categories';
    (plugin.categories || []).forEach((category) => {
      const chip = document.createElement('li');
      chip.textContent = category;
      categories.appendChild(chip);
    });

    const footer = document.createElement('footer');
    footer.className = 'plugin-card__footer';
    if (plugin.homepage) {
      const link = document.createElement('a');
      link.className = 'plugin-card__link';
      const resolved = new URL(plugin.homepage, docsRoot);
      link.href = resolved.href;
      link.textContent = 'View documentation';
      footer.appendChild(link);
    }

    card.appendChild(header);
    card.appendChild(meta);
    card.appendChild(summary);
    if (capabilities.childElementCount) {
      const capLabel = document.createElement('p');
      capLabel.className = 'plugin-card__label';
      capLabel.textContent = 'Capabilities';
      card.appendChild(capLabel);
      card.appendChild(capabilities);
    }
    if (categories.childElementCount) {
      const catLabel = document.createElement('p');
      catLabel.className = 'plugin-card__label';
      catLabel.textContent = 'Categories';
      card.appendChild(catLabel);
      card.appendChild(categories);
    }
    card.appendChild(footer);
    return card;
  }
})();
