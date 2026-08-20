/* Insyrium — static UI preview pages: shared behaviours */
(function () {
  /* Footer year */
  document.querySelectorAll('.js-year').forEach(function (el) {
    el.textContent = new Date().getFullYear();
  });

  /* Reveal on scroll */
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (e.isIntersecting) { e.target.classList.add('visible'); io.unobserve(e.target); }
    });
  }, { threshold: 0.12 });
  document.querySelectorAll('.reveal').forEach(function (el) { io.observe(el); });

  /* FAQ accordion */
  document.querySelectorAll('.faq-item').forEach(function (item) {
    var q = item.querySelector('.faq-q');
    if (!q) return;
    q.addEventListener('click', function () {
      var open = item.classList.contains('open');
      document.querySelectorAll('.faq-item.open').forEach(function (el) { el.classList.remove('open'); });
      if (!open) item.classList.add('open');
    });
  });

  /* Demo password strength meter */
  var pw = document.getElementById('demo-password');
  var bar = document.getElementById('demo-pw-bar');
  if (pw && bar) {
    pw.addEventListener('input', function () {
      var v = pw.value, score = 0;
      if (v.length >= 8) score++;
      if (/[A-Z]/.test(v)) score++;
      if (/[a-z]/.test(v)) score++;
      if (/\d/.test(v)) score++;
      if (v.length >= 12) score++;
      bar.className = score >= 4 ? 'strong' : score >= 3 ? 'good' : score >= 2 ? 'ok' : 'weak';
      bar.style.width = (score * 20) + '%';
    });
  }

  /* Demo toast */
  window.demoToast = function (msg, type) {
    var wrap = document.getElementById('toasts');
    if (!wrap) return;
    var t = document.createElement('div');
    t.className = 'toast ' + (type || 'info');
    t.innerHTML = '<span class="toast-dot"></span><span>' + msg + '</span>';
    wrap.appendChild(t);
    requestAnimationFrame(function () { t.classList.add('in'); });
    setTimeout(function () { t.classList.remove('in'); setTimeout(function () { t.remove(); }, 350); }, 2600);
  };

  /* Copy buttons on code blocks */
  document.querySelectorAll('.pre').forEach(function (pre) {
    var btn = document.createElement('button');
    btn.type = 'button'; btn.className = 'pre-copy'; btn.textContent = 'Copy';
    pre.appendChild(btn);
    btn.addEventListener('click', function () {
      var text = pre.innerText.replace('Copy', '').replace('Copied ✓', '').replace('Copy failed', '').trim();
      var done = function (ok) { btn.textContent = ok ? 'Copied ✓' : 'Copy failed'; setTimeout(function () { btn.textContent = 'Copy'; }, 1500); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
      } else { done(false); }
    });
  });
})();
