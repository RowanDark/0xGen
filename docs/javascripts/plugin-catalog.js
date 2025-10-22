(function () {
  const docsRoot = resolveDocsRoot('plugin-catalog.js');
  let cachedPlugins = null;
  let cachedRegistry = null;
  let catalogDataUrl = null;
  let cached0xgenVersions = [];
  const compatibilityStatuses = ['compatible', 'limited', 'unsupported'];

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
    const versionFilter = document.getElementById('plugin-oxg');
    const statusFilter = document.getElementById('plugin-compatibility-status');
    if (!searchField || !languageFilter || !categoryFilter || !versionFilter || !statusFilter) {
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

    catalogDataUrl = new URL('data/plugin-registry.json', docsRoot);
    const dataUrl = catalogDataUrl;

    const loadRegistry = cachedRegistry
      ? Promise.resolve(cachedRegistry)
      : fetch(dataUrl).then((response) => {
          if (!response.ok) {
            throw new Error(`Failed to load plugin catalogue: ${response.status}`);
          }
          return response.json();
        })
        .then((payload) => {
          if (Array.isArray(payload)) {
            return { plugins: payload, oxg_versions: [] };
          }
          return payload;
        });

    loadRegistry
      .then((registry) => {
        cachedRegistry = registry;
        const plugins = Array.isArray(registry.plugins) ? registry.plugins : [];
        const oxgVersions = Array.isArray(registry.oxg_versions)
          ? registry.oxg_versions
          : [];
        cachedPlugins = plugins;
        cached0xgenVersions = oxgVersions;
        renderFilters(plugins, languageFilter, categoryFilter, versionFilter, statusFilter, oxgVersions);
        renderCatalog(plugins, container, emptyState, oxgVersions);

        const handleFilterChange = () => {
          const query = (searchField.value || '').trim().toLowerCase();
          const language = languageFilter.value;
          const category = categoryFilter.value;
          const selectedVersion = versionFilter.value;
          const status = statusFilter.value;
          const filtered = plugins.filter((plugin) => {
            if (language && plugin.language !== language) {
              return false;
            }
            const pluginCategories = plugin.categories || [];
            if (category && !pluginCategories.includes(category)) {
              return false;
            }
            if (selectedVersion || status) {
              const compatibility = plugin.oxg_compat || plugin.compatibility || {};
              if (selectedVersion) {
                const versionEntry = compatibility[selectedVersion];
                if (!versionEntry) {
                  return false;
                }
                if (status && versionEntry.status !== status) {
                  return false;
                }
              } else if (status) {
                const matchesStatus = Object.values(compatibility).some(
                  (entry) => entry && entry.status === status,
                );
                if (!matchesStatus) {
                  return false;
                }
              }
            }
            if (!query) {
              return true;
            }
            const compatibilityValues = [];
            const pluginCompatibility = plugin.oxg_compat || plugin.compatibility;
            if (pluginCompatibility) {
              Object.entries(pluginCompatibility).forEach(([version, entry]) => {
                if (!entry) {
                  return;
                }
                compatibilityValues.push(`0xgen v${version}`);
                if (entry.status) {
                  compatibilityValues.push(entry.status);
                }
                if (entry.notes) {
                  compatibilityValues.push(entry.notes);
                }
              });
            }
            const haystack = [
              plugin.name,
              plugin.summary,
              plugin.author,
              plugin.language,
              ...(plugin.capabilities || []),
              ...pluginCategories,
              ...(selectedVersion ? [selectedVersion] : []),
              ...compatibilityValues,
            ]
              .join(' ')
              .toLowerCase();
            return haystack.includes(query);
          });
          renderCatalog(filtered, container, emptyState, oxgVersions);
        };

        searchField.addEventListener('input', handleFilterChange);
        languageFilter.addEventListener('change', handleFilterChange);
        categoryFilter.addEventListener('change', handleFilterChange);
        versionFilter.addEventListener('change', handleFilterChange);
        statusFilter.addEventListener('change', handleFilterChange);
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

  function renderFilters(
    plugins,
    languageFilter,
    categoryFilter,
    versionFilter,
    statusFilter,
    oxgVersions,
  ) {
    const languages = new Set();
    const categories = new Set();
    plugins.forEach((plugin) => {
      if (plugin.language) {
        languages.add(plugin.language);
      }
      (plugin.categories || []).forEach((category) => categories.add(category));
    });

    resetSelectOptions(languageFilter);
    Array.from(languages)
      .sort((a, b) => a.localeCompare(b))
      .forEach((language) => {
        const option = document.createElement('option');
        option.value = language;
        option.textContent = language;
        languageFilter.appendChild(option);
      });

    resetSelectOptions(categoryFilter);
    Array.from(categories)
      .sort((a, b) => a.localeCompare(b))
      .forEach((category) => {
        const option = document.createElement('option');
        option.value = category;
        option.textContent = category;
        categoryFilter.appendChild(option);
      });

    resetSelectOptions(versionFilter);
    oxgVersions
      .slice()
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
      .forEach((version) => {
        const option = document.createElement('option');
        option.value = version;
        option.textContent = `0xgen v${version}`;
        versionFilter.appendChild(option);
      });

    resetSelectOptions(statusFilter);
    compatibilityStatuses.forEach((status) => {
      const option = document.createElement('option');
      option.value = status;
      option.textContent = statusLabel(status);
      statusFilter.appendChild(option);
    });
  }

  function resetSelectOptions(select) {
    if (!select) {
      return;
    }
    while (select.options.length > 1) {
      select.remove(1);
    }
  }

  function statusLabel(status) {
    switch (status) {
      case 'compatible':
        return 'Compatible';
      case 'limited':
        return 'Limited';
      case 'unsupported':
        return 'Unsupported';
      default:
        return status || '';
    }
  }

  function statusIcon(status) {
    switch (status) {
      case 'compatible':
        return '✅';
      case 'limited':
        return '⚠️';
      case 'unsupported':
        return '❌';
      default:
        return '•';
    }
  }

  function renderCatalog(plugins, container, emptyState, oxgVersions) {
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
      container.appendChild(renderPlugin(plugin, oxgVersions));
    });
    container.setAttribute('aria-busy', 'false');
  }

  function renderPlugin(plugin, oxgVersions) {
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

    const details = document.createElement('dl');
    details.className = 'plugin-card__details';
    const addDetail = (label, value, options = {}) => {
      if (!value) {
        return;
      }
      const term = document.createElement('dt');
      term.textContent = label;
      const description = document.createElement('dd');
      if (options.code) {
        const code = document.createElement('code');
        code.textContent = value;
        description.appendChild(code);
      } else {
        description.textContent = value;
      }
      details.appendChild(term);
      details.appendChild(description);
    };

    addDetail('Version', plugin.version ? `v${plugin.version}` : 'Unversioned');
    addDetail('Last update', formatDate(plugin.last_updated));
    addDetail('Signature', plugin.signature_sha256, { code: true });

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
    const actions = document.createElement('div');
    actions.className = 'plugin-card__actions';

    const createAction = (href, label) => {
      if (!href) {
        return null;
      }
      const link = document.createElement('a');
      link.className = 'plugin-card__link';
      const base = catalogDataUrl || docsRoot;
      const resolved = new URL(href, base);
      link.href = resolved.href;
      link.textContent = label;
      return link;
    };

    const primaryActions = [
      createAction(plugin.links?.documentation || plugin.homepage, 'View documentation'),
      createAction(plugin.links?.installation, 'Installation guide'),
      createAction(plugin.links?.artifact, 'Download artefact'),
    ].filter(Boolean);

    const secondaryActions = [
      createAction(plugin.links?.manifest, 'Manifest'),
      createAction(plugin.links?.signature, 'Detached signature'),
    ].filter(Boolean);

    [...primaryActions, ...secondaryActions].forEach((link) => {
      if (link) {
        actions.appendChild(link);
      }
    });

    if (actions.childElementCount) {
      footer.appendChild(actions);
    }

    card.appendChild(header);
    card.appendChild(meta);
    card.appendChild(summary);
    if (details.childElementCount) {
      card.appendChild(details);
    }
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

    const compatibility = renderCompatibility(plugin, oxgVersions);
    if (compatibility) {
      const compatibilityLabel = document.createElement('p');
      compatibilityLabel.className = 'plugin-card__label';
      compatibilityLabel.textContent = 'Compatibility';
      card.appendChild(compatibilityLabel);
      card.appendChild(compatibility);
    }
    card.appendChild(footer);
    return card;
  }

  function renderCompatibility(plugin, oxgVersions) {
    const compat = plugin.oxg_compat || plugin.compatibility || {};
    const orderedVersions = [];
    const seen = new Set();
    oxgVersions.forEach((version) => {
      if (compat[version]) {
        orderedVersions.push(version);
        seen.add(version);
      }
    });
    Object.keys(compat)
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
      .forEach((version) => {
        if (!seen.has(version)) {
          orderedVersions.push(version);
          seen.add(version);
        }
      });
    if (!orderedVersions.length) {
      return null;
    }
    const container = document.createElement('div');
    container.className = 'plugin-card__compatibility';
    orderedVersions.forEach((version) => {
      const entry = compat[version];
      if (!entry || !entry.status) {
        return;
      }
      const badge = document.createElement('span');
      badge.className = `plugin-card__compatibility-badge plugin-card__compatibility-badge--${entry.status}`;
      badge.setAttribute('data-version', version);
      const icon = document.createElement('span');
      icon.setAttribute('aria-hidden', 'true');
      icon.textContent = statusIcon(entry.status);
      const text = document.createElement('span');
      text.textContent = `0xgen v${version}`;
      badge.appendChild(icon);
      badge.appendChild(text);
      const description = statusLabel(entry.status);
      const notes = entry.notes ? ` — ${entry.notes}` : '';
      badge.setAttribute('title', `${description}${notes}`.trim());
      badge.setAttribute('aria-label', `${description} on 0xgen v${version}${entry.notes ? `: ${entry.notes}` : ''}`);
      container.appendChild(badge);
    });
    if (!container.childElementCount) {
      return null;
    }
    return container;
  }

  function formatDate(value) {
    if (!value) {
      return null;
    }
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return value;
    }
    return parsed.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }
})();
