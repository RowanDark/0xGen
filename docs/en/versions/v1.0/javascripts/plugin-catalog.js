(function () {
  let cachedPlugins = null;

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

    const emptyState = document.createElement('p');
    emptyState.className = 'plugin-catalog__empty';
    emptyState.textContent = 'No plugins match the selected filters yet.';

    const docsRoot = resolveDocsRoot('plugin-catalog.js');
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
        container.appendChild(failure);
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
    container.innerHTML = '';
    if (!plugins.length) {
      container.appendChild(emptyState);
      return;
    }

    plugins.forEach((plugin) => {
      container.appendChild(renderPlugin(plugin));
    });
  }

  function renderPlugin(plugin) {
    const card = document.createElement('article');
    card.className = 'plugin-card';

    const header = document.createElement('header');
    header.className = 'plugin-card__header';

    const title = document.createElement('h3');
    title.className = 'plugin-card__title';
    title.textContent = plugin.name || plugin.id;

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
      const resolved = new URL(plugin.homepage, new URL(baseUrl + '/', window.location.href));
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
