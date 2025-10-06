(function () {
  const applyLazyAttributes = () => {
    const images = document.querySelectorAll('img:not([loading])');
    images.forEach((image) => {
      image.setAttribute('loading', 'lazy');
      if (!image.hasAttribute('decoding')) {
        image.setAttribute('decoding', 'async');
      }
    });

    const observers = [];
    const attachObserver = (element) => {
      if ('IntersectionObserver' in window) {
        const observer = new IntersectionObserver((entries, current) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) {
              const target = entry.target;
              const lazySrc = target.getAttribute('data-lazy-src');
              if (lazySrc && !target.src) {
                target.src = lazySrc;
              }
              current.unobserve(target);
            }
          });
        }, {
          rootMargin: '150px',
        });
        observer.observe(element);
        observers.push(observer);
      } else {
        const lazySrc = element.getAttribute('data-lazy-src');
        if (lazySrc && !element.src) {
          element.src = lazySrc;
        }
      }
    };

    document.querySelectorAll('iframe[data-lazy-src]').forEach((frame) => {
      if (frame.src) {
        return;
      }
      attachObserver(frame);
    });
  };

  const schedule = () => window.requestAnimationFrame(applyLazyAttributes);

  if (window.document$ && typeof window.document$.subscribe === 'function') {
    window.document$.subscribe(schedule);
  }

  if (document.readyState !== 'loading') {
    schedule();
  } else {
    document.addEventListener('DOMContentLoaded', schedule, { once: true });
  }
})();
