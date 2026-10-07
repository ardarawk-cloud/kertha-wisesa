const menuBtn = document.getElementById('menuBtn');
const nav = document.getElementById('nav');
const progress = document.getElementById('progress');
const year = document.getElementById('year');

if (year) year.textContent = new Date().getFullYear();

if (menuBtn && nav) {
  menuBtn.addEventListener('click', () => {
    const open = nav.classList.toggle('open');
    menuBtn.setAttribute('aria-expanded', String(open));
  });

  nav.querySelectorAll('a').forEach(a => a.addEventListener('click', () => {
    nav.classList.remove('open');
    menuBtn.setAttribute('aria-expanded', 'false');
  }));
}

if (progress) {
  window.addEventListener('scroll', () => {
    const max = document.documentElement.scrollHeight - window.innerHeight;
    const pct = max > 0 ? (window.scrollY / max) * 100 : 0;
    progress.style.width = pct + '%';
  });
}

document.querySelectorAll('[data-b64-image]').forEach(async img => {
  try {
    const response = await fetch(img.dataset.b64Image, { cache: 'force-cache' });
    if (!response.ok) throw new Error('image data unavailable');
    const encoded = (await response.text()).trim();
    img.src = 'data:image/webp;base64,' + encoded;
  } catch (error) {
    img.classList.add('archive-image-error');
  }
});

// Archive source links: use current-tab navigation so they also work in embedded/in-app browsers.
document.querySelectorAll('.source-list a[href]').forEach(a => {
  a.addEventListener('click', event => {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    window.location.assign(a.href);
  });
});
