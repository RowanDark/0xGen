(function () {
  const FALLBACK_ID = "doc-search-fallback";

  function renderFallback(container, input, results) {
    const query = input.value.trim();
    const existing = container.querySelector(`#${FALLBACK_ID}`);
    const hasResults = results.querySelector(".md-search-result__item") !== null;

    if (!query || hasResults) {
      if (existing) {
        existing.remove();
      }
      return;
    }

    const url = `https://github.com/RowanDark/0xgen/search?q=${encodeURIComponent(query)}&type=code`;
    const fallback = existing || document.createElement("div");
    fallback.id = FALLBACK_ID;
    fallback.className = "md-search-result__meta md-typeset";

    const paragraph = fallback.querySelector("p") || document.createElement("p");
    paragraph.className = "doc-search-fallback__text";
    paragraph.innerHTML = `No results found. <a href="${url}" target="_blank" rel="noopener">Search the entire repository</a>.`;
    if (!paragraph.parentNode) {
      fallback.appendChild(paragraph);
    }

    if (!existing) {
      container.appendChild(fallback);
    }
  }

  function initialize() {
    const searchDialog = document.querySelector('[data-md-component="search"]');
    if (!searchDialog) {
      return;
    }

    const input = searchDialog.querySelector('input[data-md-component="search-query"]');
    const resultsContainer = searchDialog.querySelector('.md-search-result__scrollwrap');
    const resultsList = searchDialog.querySelector('.md-search-result__list');
    if (!input || !resultsContainer || !resultsList) {
      return;
    }

    const observer = new MutationObserver(function () {
      renderFallback(resultsContainer, input, resultsList);
    });
    observer.observe(resultsList, { childList: true, subtree: false });

    input.addEventListener("input", function () {
      window.requestAnimationFrame(function () {
        renderFallback(resultsContainer, input, resultsList);
      });
    });

    searchDialog.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        window.requestAnimationFrame(function () {
          renderFallback(resultsContainer, input, resultsList);
        });
      }
    });

    renderFallback(resultsContainer, input, resultsList);
  }

  if (document.readyState !== "loading") {
    initialize();
  } else {
    document.addEventListener("DOMContentLoaded", initialize);
  }
})();
