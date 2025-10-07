(function () {
  const docsRoot = resolveDocsRoot('plugin-compatibility.js');
  let cachedRegistry = null;

  const init = () => window.requestAnimationFrame(initialise);
  if (window.document$ && typeof window.document$.subscribe === 'function') {
    window.document$.subscribe(init);
  }

  if (document.readyState !== 'loading') {
    init();
  } else {
    document.addEventListener('DOMContentLoaded', init);
  }

  function initialise() {
    const container = document.getElementById('plugin-compatibility');
    if (!container || container.dataset.compatibilityInitialised) {
      return;
    }

    const searchField = document.getElementById('compatibility-search');
    const glyphFilter = document.getElementById('compatibility-glyph');
    const statusFilter = document.getElementById('compatibility-status');
    if (!searchField || !glyphFilter || !statusFilter) {
      return;
    }

    container.dataset.compatibilityInitialised = 'true';
    container.setAttribute('role', 'region');
    container.setAttribute('aria-live', 'polite');
    container.setAttribute('aria-busy', 'true');

    const dataUrl = new URL('data/plugin-registry.json', docsRoot);
    const loadRegistry = cachedRegistry
      ? Promise.resolve(cachedRegistry)
      : fetch(dataUrl)
          .then((response) => {
            if (!response.ok) {
              throw new Error(`Failed to load plugin registry: ${response.status}`);
            }
            return response.json();
          })
          .then((payload) => {
            if (Array.isArray(payload)) {
              return { plugins: payload, glyph_versions: [] };
            }
            return payload;
          });

    loadRegistry
      .then((registry) => {
        cachedRegistry = registry;
        const plugins = Array.isArray(registry.plugins) ? registry.plugins : [];
        const glyphVersions = Array.isArray(registry.glyph_versions) ? registry.glyph_versions : [];
        populateFilters(glyphFilter, statusFilter, glyphVersions);
        renderTable(container, plugins, glyphVersions, {
          query: '',
          glyph: '',
          status: '',
        });

        const handleChange = () => {
          const filters = {
            query: (searchField.value || '').trim().toLowerCase(),
            glyph: glyphFilter.value,
            status: statusFilter.value,
          };
          renderTable(container, plugins, glyphVersions, filters);
        };

        searchField.addEventListener('input', handleChange);
        glyphFilter.addEventListener('change', handleChange);
        statusFilter.addEventListener('change', handleChange);
      })
      .catch((error) => {
        console.error(error); // eslint-disable-line no-console
        container.innerHTML = '';
        const failure = document.createElement('p');
        failure.className = 'plugin-compatibility__empty';
        failure.textContent = 'Unable to load compatibility data. Please try reloading the page.';
        failure.setAttribute('role', 'alert');
        container.appendChild(failure);
        container.setAttribute('aria-busy', 'false');
      });
  }

  function populateFilters(glyphFilter, statusFilter, glyphVersions) {
    resetSelectOptions(glyphFilter);
    glyphVersions
      .slice()
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
      .forEach((version) => {
        const option = document.createElement('option');
        option.value = version;
        option.textContent = `Glyph v${version}`;
        glyphFilter.appendChild(option);
      });

    resetSelectOptions(statusFilter);
    ['compatible', 'limited', 'unsupported'].forEach((status) => {
      const option = document.createElement('option');
      option.value = status;
      option.textContent = statusLabel(status);
      statusFilter.appendChild(option);
    });
  }

  function renderTable(container, plugins, glyphVersions, filters) {
    container.setAttribute('aria-busy', 'true');
    container.innerHTML = '';

    const filtered = plugins
      .filter((plugin) => filterPlugin(plugin, glyphVersions, filters))
      .sort((a, b) => (a.name || a.id || '').localeCompare(b.name || b.id || ''));

    if (!filtered.length) {
      const empty = document.createElement('p');
      empty.className = 'plugin-compatibility__empty';
      empty.textContent = 'No plugins match the selected filters yet.';
      empty.setAttribute('role', 'status');
      container.appendChild(empty);
      container.setAttribute('aria-busy', 'false');
      return;
    }

    const table = document.createElement('table');
    table.className = 'plugin-compatibility__table';
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    ['Plugin', 'Latest version', ...glyphVersions.map((version) => `Glyph v${version}`)].forEach((heading, index) => {
      const cell = document.createElement('th');
      cell.scope = 'col';
      cell.textContent = heading;
      if (index === 0) {
        cell.style.minWidth = '12rem';
      }
      headRow.appendChild(cell);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    filtered.forEach((plugin) => {
      const row = document.createElement('tr');

      const nameCell = document.createElement('th');
      nameCell.scope = 'row';
      const link = resolvePluginLink(plugin);
      if (link) {
        const anchor = document.createElement('a');
        anchor.href = link;
        anchor.textContent = plugin.name || plugin.id;
        anchor.rel = 'noopener noreferrer';
        nameCell.appendChild(anchor);
      } else {
        nameCell.textContent = plugin.name || plugin.id;
      }
      row.appendChild(nameCell);

      const versionCell = document.createElement('td');
      versionCell.textContent = plugin.version ? `v${plugin.version}` : 'Unversioned';
      row.appendChild(versionCell);

      glyphVersions.forEach((version) => {
        const cell = document.createElement('td');
        const entry = plugin.compatibility ? plugin.compatibility[version] : null;
        if (entry && entry.status) {
          cell.appendChild(renderStatus(entry));
        } else {
          cell.textContent = '—';
          cell.style.textAlign = 'center';
        }
        row.appendChild(cell);
      });

      tbody.appendChild(row);
    });

    table.appendChild(tbody);
    container.appendChild(table);
    container.setAttribute('aria-busy', 'false');
  }

  function renderStatus(entry) {
    const wrapper = document.createElement('div');
    wrapper.className = `plugin-compatibility__status plugin-compatibility__status--${entry.status}`;
    const icon = document.createElement('span');
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = statusIcon(entry.status);
    wrapper.appendChild(icon);

    const label = document.createElement('span');
    label.textContent = statusLabel(entry.status);
    wrapper.appendChild(label);

    if (entry.notes) {
      const notes = document.createElement('div');
      notes.className = 'plugin-compatibility__notes';
      notes.textContent = entry.notes;
      wrapper.appendChild(notes);
    }

    return wrapper;
  }

  function filterPlugin(plugin, glyphVersions, filters) {
    const query = filters.query;
    const glyph = filters.glyph;
    const status = filters.status;

    if (glyph) {
      const entry = plugin.compatibility ? plugin.compatibility[glyph] : null;
      if (!entry) {
        return false;
      }
      if (status && entry.status !== status) {
        return false;
      }
    } else if (status) {
      const hasStatus = Object.values(plugin.compatibility || {}).some(
        (entry) => entry && entry.status === status,
      );
      if (!hasStatus) {
        return false;
      }
    }

    if (!query) {
      return true;
    }

    const haystack = [
      plugin.name,
      plugin.id,
      plugin.summary,
      plugin.author,
      plugin.language,
      ...(plugin.capabilities || []),
      ...((plugin.categories || [])),
    ];

    if (plugin.compatibility) {
      Object.entries(plugin.compatibility).forEach(([version, entry]) => {
        if (!entry) {
          return;
        }
        haystack.push(`glyph v${version}`);
        if (entry.status) {
          haystack.push(entry.status);
        }
        if (entry.notes) {
          haystack.push(entry.notes);
        }
      });
    }

    return haystack
      .filter(Boolean)
      .join(' ')
      .toLowerCase()
      .includes(query);
  }

  function resolvePluginLink(plugin) {
    const base = docsRoot;
    const href = plugin.links?.documentation || plugin.links?.readme;
    if (!href) {
      return null;
    }
    try {
      return new URL(href, base).href;
    } catch (error) {
      console.warn('Unable to resolve plugin link', error); // eslint-disable-line no-console
      return href;
    }
  }

  function resetSelectOptions(select) {
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
