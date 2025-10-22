(function () {
  const scriptId = 'quickstart-demo.js';
  let cachedScenario = null;

  const STRINGS = {
    en: {
      title: 'Try 0xgen now',
      description: 'Simulate the `0xgenctl demo` command and watch each stage complete without leaving your browser.',
      statusReady: 'Ready to simulate `0xgenctl demo`.',
      statusRunning: 'Running the walkthrough…',
      statusComplete: 'Demo finished — explore the generated artifacts below.',
      run: 'Run full demo',
      step: 'Step through',
      reset: 'Reset',
      artifacts: 'Generated artifacts',
      artifactHint: 'Open the reference outputs that `0xgenctl demo` produces.',
      commandPrefix: '$ ',
    },
    es: {
      title: 'Prueba 0xgen ahora',
      description: 'Simula el comando `0xgenctl demo` y observa cada etapa sin salir de la documentación.',
      statusReady: 'Listo para simular `0xgenctl demo`.',
      statusRunning: 'Ejecutando la demostración…',
      statusComplete: 'Demostración finalizada; explora los artefactos generados más abajo.',
      run: 'Ejecutar demostración',
      step: 'Avanzar paso a paso',
      reset: 'Restablecer',
      artifacts: 'Artefactos generados',
      artifactHint: 'Abre las salidas de referencia que produce `0xgenctl demo`.',
      commandPrefix: '$ ',
    },
  };

  const resolveLocale = () => {
    const htmlLang = (document.documentElement.getAttribute('lang') || 'en').toLowerCase();
    return htmlLang.startsWith('es') ? 'es' : 'en';
  };

  const resolveDocsRoot = (name) => {
    let script = document.currentScript;
    if (!script || !(script.src || '').includes(name)) {
      script = Array.from(document.getElementsByTagName('script')).find((element) =>
        (element.src || '').includes(name),
      );
    }
    if (!script) {
      return new URL('.', window.location.href);
    }
    const scriptUrl = new URL(script.src, window.location.href);
    return new URL('..', scriptUrl);
  };

  const fetchScenario = () => {
    if (cachedScenario) {
      return Promise.resolve(cachedScenario);
    }
    const docsRoot = resolveDocsRoot(scriptId);
    const locale = resolveLocale();
    const url = new URL('data/quickstart-demo.json', docsRoot);
    const fetchJson = (targetUrl) =>
      fetch(targetUrl).then((response) => {
        if (!response.ok) {
          throw new Error(`Unable to load quickstart scenario: ${response.status}`);
        }
        return response.json();
      });
    return fetchJson(url)
      .catch((error) => {
        if (locale === 'en') {
          throw error;
        }
        const englishRoot = new URL('../en/', docsRoot);
        const fallbackUrl = new URL('data/quickstart-demo.json', englishRoot);
        return fetchJson(fallbackUrl);
      })
      .then((scenario) => {
        cachedScenario = scenario;
        return scenario;
      });
  };

  const initialise = () => {
    const host = document.getElementById('run-the-pipeline');
    if (!host || host.dataset.demoInitialised) {
      return;
    }

    host.dataset.demoInitialised = 'true';
    host.classList.add('demo-runner');

    const locale = resolveLocale();
    const strings = STRINGS[locale] || STRINGS.en;

    const heading = document.createElement('h3');
    heading.className = 'demo-runner__heading';
    heading.textContent = strings.title;

    const description = document.createElement('p');
    description.className = 'demo-runner__lead';
    description.textContent = strings.description;

    const terminal = document.createElement('div');
    terminal.className = 'demo-runner__terminal';
    terminal.setAttribute('tabindex', '0');
    terminal.setAttribute('role', 'log');
    terminal.setAttribute('aria-live', 'polite');
    terminal.setAttribute('aria-label', strings.title);

    const status = document.createElement('p');
    status.className = 'demo-runner__status';
    status.textContent = strings.statusReady;

    const actions = document.createElement('div');
    actions.className = 'demo-runner__actions';

    const runButton = document.createElement('button');
    runButton.type = 'button';
    runButton.textContent = strings.run;
    runButton.dataset.variant = 'primary';

    const stepButton = document.createElement('button');
    stepButton.type = 'button';
    stepButton.textContent = strings.step;
    stepButton.dataset.variant = 'secondary';

    const resetButton = document.createElement('button');
    resetButton.type = 'button';
    resetButton.textContent = strings.reset;
    resetButton.dataset.variant = 'ghost';

    actions.append(runButton, stepButton, resetButton);

    const artifactsPanel = document.createElement('section');
    artifactsPanel.className = 'demo-runner__artifacts';
    artifactsPanel.hidden = true;

    const artifactsHeading = document.createElement('h4');
    artifactsHeading.textContent = strings.artifacts;

    const artifactsHint = document.createElement('p');
    artifactsHint.className = 'demo-runner__hint';
    artifactsHint.textContent = strings.artifactHint;

    const artifactsList = document.createElement('ul');

    artifactsPanel.append(artifactsHeading, artifactsHint, artifactsList);

    host.append(heading, description, terminal, status, actions, artifactsPanel);

    let timer = null;
    let lineIndex = 0;
    let lines = [];

    const updateStatus = (text) => {
      status.textContent = text;
    };

    const stopTimer = () => {
      if (timer) {
        window.clearInterval(timer);
        timer = null;
      }
    };

    const resetDemo = () => {
      stopTimer();
      lineIndex = 0;
      lines = [];
      terminal.innerHTML = '';
      artifactsList.innerHTML = '';
      artifactsPanel.hidden = true;
      updateStatus(strings.statusReady);
      runButton.disabled = false;
      stepButton.disabled = false;
    };

    const appendLine = (content, className) => {
      const line = document.createElement('div');
      line.className = 'demo-runner__output-line';
      if (className) {
        line.classList.add(className);
      }
      line.textContent = content;
      terminal.appendChild(line);
      terminal.scrollTop = terminal.scrollHeight;
    };

    const revealArtifacts = (scenario) => {
      artifactsList.innerHTML = '';
      (scenario.artifacts || []).forEach((artifact) => {
        const item = document.createElement('li');
        const link = document.createElement('a');
        link.href = artifact.href;
        link.target = '_blank';
        link.rel = 'noreferrer noopener';
        link.textContent = artifact.label;
        item.appendChild(link);
        if (artifact.description) {
          const details = document.createElement('div');
          details.textContent = artifact.description;
          item.appendChild(details);
        }
        artifactsList.appendChild(item);
      });
      artifactsPanel.hidden = !artifactsList.childElementCount;
    };

    const completeRun = (scenario) => {
      stopTimer();
      runButton.disabled = false;
      stepButton.disabled = true;
      updateStatus(strings.statusComplete);
      revealArtifacts(scenario);
    };

    const playNextLine = (scenario) => {
      if (!lines.length) {
        return completeRun(scenario);
      }
      if (lineIndex >= lines.length) {
        return completeRun(scenario);
      }
      const entry = lines[lineIndex];
      appendLine(entry.text, entry.kind);
      lineIndex += 1;
      if (lineIndex >= lines.length) {
        completeRun(scenario);
      }
    };

    const scheduleRun = (scenario) => {
      stopTimer();
      timer = window.setInterval(() => playNextLine(scenario), 650);
    };

    const hydrate = (scenario) => {
      resetDemo();
      const compiled = [];
      compiled.push({ text: `${strings.commandPrefix}${scenario.command}`, kind: 'demo-runner__prompt' });
      (scenario.steps || []).forEach((step) => {
        if (step.title) {
          compiled.push({ text: `▶ ${step.title}`, kind: 'demo-runner__step' });
        }
        (step.lines || []).forEach((line) => {
          compiled.push({ text: `  ${line}`, kind: 'demo-runner__line' });
        });
      });
      (scenario.summary || []).forEach((line) => {
        compiled.push({ text: line, kind: 'demo-runner__summary' });
      });
      lines = compiled;
    };

    const ensureScenario = () =>
      fetchScenario()
        .then((scenario) => {
          hydrate(scenario);
          return scenario;
        })
        .catch((error) => {
          console.error(error); // eslint-disable-line no-console
          resetDemo();
          updateStatus('Unable to load the interactive demo.');
          runButton.disabled = true;
          stepButton.disabled = true;
          return null;
        });

    runButton.addEventListener('click', () => {
      ensureScenario().then((scenario) => {
        if (!scenario) {
          return;
        }
        updateStatus(strings.statusRunning);
        runButton.disabled = true;
        stepButton.disabled = false;
        scheduleRun(scenario);
      });
    });

    stepButton.addEventListener('click', () => {
      ensureScenario().then((scenario) => {
        if (!scenario) {
          return;
        }
        if (!timer && lineIndex === 0) {
          updateStatus(strings.statusRunning);
        }
        stopTimer();
        runButton.disabled = false;
        playNextLine(scenario);
      });
    });

    resetButton.addEventListener('click', () => {
      resetDemo();
    });

    ensureScenario();
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
})();
