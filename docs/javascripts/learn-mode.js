(function () {
  const STORAGE_KEY = 'oxg-learn-mode';
  const ACTIVE_CLASS = 'learn-mode-active';
  const BADGE_CLASS = 'learn-mode-badge';
  const STEP_SELECTOR = '.learn-step';

  let toggleButton;
  let panel;
  let activeStepId = null;

  function createToggle() {
    toggleButton = document.createElement('button');
    toggleButton.type = 'button';
    toggleButton.className = 'learn-mode-toggle';
    toggleButton.setAttribute('aria-label', 'Toggle Learn mode');
    toggleButton.addEventListener('click', () => {
      const next = !document.body.classList.contains(ACTIVE_CLASS);
      setActive(next, true);
    });
    document.body.appendChild(toggleButton);
  }

  function ensurePanel() {
    if (panel) {
      return panel;
    }
    panel = document.createElement('aside');
    panel.className = 'learn-mode-panel';
    panel.setAttribute('role', 'status');
    panel.setAttribute('aria-live', 'polite');

    const heading = document.createElement('h2');
    heading.textContent = 'Learn mode';
    panel.appendChild(heading);

    const body = document.createElement('p');
    body.className = 'learn-mode-panel__body';
    body.textContent = 'Select a highlighted step to see guidance.';
    panel.appendChild(body);

    document.body.appendChild(panel);
    return panel;
  }

  function destroyPanel() {
    if (panel) {
      panel.remove();
      panel = null;
    }
  }

  function formatToggleLabel(active) {
    return active ? 'Learn mode: on' : 'Learn mode: off';
  }

  function setActive(active, persist) {
    document.body.classList.toggle(ACTIVE_CLASS, active);
    if (toggleButton) {
      toggleButton.setAttribute('aria-pressed', String(active));
      toggleButton.textContent = formatToggleLabel(active);
    }

    if (active) {
      if (persist) {
        localStorage.setItem(STORAGE_KEY, '1');
      }
      initialiseSteps();
      ensurePanel();
    } else {
      if (persist) {
        localStorage.setItem(STORAGE_KEY, '0');
      }
      teardownSteps();
      destroyPanel();
    }
  }

  function handleStepInteraction(step, badge, index) {
    const panelEl = ensurePanel();
    const body = panelEl.querySelector('.learn-mode-panel__body');
    const label = step.getAttribute('data-learn-text') || step.textContent?.trim() || '';

    activeStepId = step.dataset.learnId || null;

    if (body) {
      body.textContent = label || 'Step details unavailable.';
    }

    document.querySelectorAll(`.${BADGE_CLASS}.is-active`).forEach((el) => {
      el.classList.remove('is-active');
    });
    badge.classList.add('is-active');

    document.querySelectorAll(`${STEP_SELECTOR}.is-active`).forEach((el) => {
      el.classList.remove('is-active');
    });
    step.classList.add('is-active');
  }

  function initialiseSteps() {
    const steps = document.querySelectorAll(STEP_SELECTOR);
    let counter = 1;
    steps.forEach((step) => {
      if (step.classList.contains('has-learn-badge')) {
        return;
      }
      const badge = document.createElement('span');
      badge.className = BADGE_CLASS;
      badge.textContent = String(counter);
      badge.setAttribute('aria-hidden', 'true');
      step.dataset.learnId = `learn-${counter}`;
      step.classList.add('has-learn-badge');
      step.insertAdjacentElement('afterbegin', badge);

      const listener = () => handleStepInteraction(step, badge, counter);
      badge.addEventListener('click', listener);
      step.addEventListener('click', (event) => {
        if (event.target === badge || badge.contains(event.target)) {
          return;
        }
        listener();
      });
      counter += 1;
    });

    if (steps.length > 0 && !activeStepId) {
      const firstBadge = steps[0].querySelector(`.${BADGE_CLASS}`);
      if (firstBadge instanceof HTMLElement) {
        firstBadge.click();
      }
    }
  }

  function teardownSteps() {
    document.querySelectorAll(STEP_SELECTOR).forEach((step) => {
      step.classList.remove('has-learn-badge', 'is-active');
      const badge = step.querySelector(`.${BADGE_CLASS}`);
      if (badge) {
        badge.remove();
      }
      delete step.dataset.learnId;
    });
    activeStepId = null;
  }

  function init() {
    createToggle();

    const url = new URL(window.location.href);
    const queryFlag = url.searchParams.get('learn');
    if (queryFlag === '1') {
      localStorage.setItem(STORAGE_KEY, '1');
    }

    const persisted = localStorage.getItem(STORAGE_KEY) === '1';
    setActive(persisted || queryFlag === '1', false);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
