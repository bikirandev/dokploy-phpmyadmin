// DB Portal: small progressive enhancements. Everything else works without JavaScript.
(function () {
  'use strict';

  var csrfMeta = document.querySelector('meta[name="csrf-token"]');
  var csrf = csrfMeta ? csrfMeta.getAttribute('content') : '';

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (key) {
      if (key === 'text') { node.textContent = attrs[key]; } else { node.setAttribute(key, attrs[key]); }
    });
    (children || []).forEach(function (child) { if (child) { node.appendChild(child); } });
    return node;
  }

  function svgIcon(name) {
    var paths = {
      check: 'M5 12.5l4.5 4.5L19 7.5',
      alert: 'M12 4l9 16H3l9-16zM12 10v4M12 17h.01',
      spin: 'M12 3a9 9 0 1 0 9 9'
    };
    var ns = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('class', 'icon' + (name === 'spin' ? ' spin' : ''));
    svg.setAttribute('width', '18');
    svg.setAttribute('height', '18');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    var path = document.createElementNS(ns, 'path');
    path.setAttribute('d', paths[name]);
    svg.appendChild(path);
    return svg;
  }

  // Show local times for <time data-local>.
  document.querySelectorAll('time[data-local]').forEach(function (node) {
    var date = new Date(node.getAttribute('datetime'));
    if (!isNaN(date.getTime())) {
      node.textContent = date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
      node.title = node.getAttribute('datetime');
    }
  });

  // Copy buttons.
  document.querySelectorAll('[data-copy]').forEach(function (button) {
    if (!navigator.clipboard) { return; }
    button.hidden = false;
    button.addEventListener('click', function () {
      navigator.clipboard.writeText(button.getAttribute('data-copy')).then(function () {
        button.textContent = 'Copied';
      });
    });
  });

  // Show / hide password.
  document.querySelectorAll('[data-toggle-password]').forEach(function (button) {
    var input = document.getElementById(button.getAttribute('data-toggle-password'));
    if (!input) { return; }
    button.hidden = false;
    button.addEventListener('click', function () {
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      button.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    });
  });

  var form = document.getElementById('server-form');
  if (!form) { return; }

  // Placeholders (default ports, example host names) follow the database engine.
  function syncPlaceholders() {
    var checked = form.querySelector('input[name="kind"]:checked');
    var kind = checked && checked.value === 'postgres' ? 'postgres' : 'mysql';
    form.querySelectorAll('[data-placeholder-' + kind + ']').forEach(function (input) {
      input.setAttribute('placeholder', input.getAttribute('data-placeholder-' + kind));
    });
  }
  form.querySelectorAll('input[name="kind"]').forEach(function (radio) {
    radio.addEventListener('change', syncPlaceholders);
  });
  syncPlaceholders();

  // New Production servers default to "Ask every time" until the user picks a mode themselves.
  var modeTouched = false;
  var isEdit = !!form.querySelector('input[name="server_id"]');
  form.querySelectorAll('input[name="cred_mode"]').forEach(function (radio) {
    radio.addEventListener('change', function () { modeTouched = true; });
  });
  form.querySelectorAll('input[name="environment"]').forEach(function (radio) {
    radio.addEventListener('change', function () {
      if (modeTouched || isEdit) { return; }
      var mode = radio.value === 'Production' ? 'ask' : 'saved';
      var target = form.querySelector('input[name="cred_mode"][value="' + mode + '"]');
      if (target) { target.checked = true; }
    });
  });

  // Connection test.
  var testButton = form.querySelector('[data-test-connection]');
  var panelStatus = document.querySelector('[data-test-status]');
  var panelBody = document.querySelector('[data-test-body]');
  var pinInput = form.querySelector('[data-pin-token]');
  if (!testButton || !panelStatus || !panelBody) { return; }
  testButton.hidden = false;

  function setStatus(label, state) {
    panelStatus.textContent = label;
    panelStatus.className = 'status-pill' + (state ? ' is-' + state : '');
  }

  function clearFieldErrors() {
    form.querySelectorAll('[data-js-error]').forEach(function (node) { node.remove(); });
    form.querySelectorAll('[data-js-invalid]').forEach(function (node) {
      node.removeAttribute('aria-invalid');
      node.removeAttribute('data-js-invalid');
    });
  }

  function showFieldErrors(errors) {
    var map = {
      host: ['internal_host', 'host', 'ssh_db_host'], port: ['internal_port', 'port', 'ssh_db_port'],
      ssh_host: ['ssh_host'], ssh_port: ['ssh_port'], ssh_user: ['ssh_user'], ssh_key: ['ssh_key'],
      ssh_password: ['ssh_password'], db_user: ['db_user'], db_password: ['db_password'], ca_file: ['ca_file'],
      db_name: ['db_name']
    };
    Object.keys(errors).forEach(function (key) {
      (map[key] || []).forEach(function (name) {
        var input = form.querySelector('[name="' + name + '"]');
        if (!input || input.offsetParent === null) { return; }
        input.setAttribute('aria-invalid', 'true');
        input.setAttribute('data-js-invalid', '1');
        var holder = input.closest('.field');
        if (holder) { holder.appendChild(el('span', { 'class': 'field-error', 'data-js-error': '1', text: errors[key] })); }
      });
    });
  }

  function renderPin(pin) {
    var kindLabel = pin.kind === 'ssh' ? 'SSH host key' : 'Certificate fingerprint (SHA-256)';
    var noun = pin.kind === 'ssh' ? 'host key' : 'certificate';
    var box = el('div', { 'class': 'pin-box' }, [
      el('span', { 'class': 'overline', text: kindLabel }),
      el('code', { 'class': 'wrap small', text: pin.fingerprint })
    ]);
    if (pin.mismatch) {
      box.appendChild(el('span', { 'class': 'field-error', text: 'This is different from the ' + noun + ' you trusted before. Only trust it if you changed it yourself.' }));
    } else if (pin.kind === 'tls' && !pin.strict) {
      box.appendChild(el('span', { 'class': 'small muted', text: 'This certificate is checked before every connection.' }));
    }
    var hint = el('span', { 'class': 'small muted', text: 'Check that this matches your server, then trust it.' });
    var trust = el('button', { type: 'button', 'class': 'btn btn-small btn-outline', text: 'Trust this ' + noun });
    trust.addEventListener('click', function () {
      if (pinInput) { pinInput.value = pin.token; }
      box.classList.add('is-trusted');
      hint.remove();
      trust.replaceWith(el('span', { 'class': 'small trusted-text', text: 'Trusted. Save the server to keep it.' }));
    });
    box.appendChild(hint);
    box.appendChild(trust);
    return box;
  }

  testButton.addEventListener('click', function () {
    clearFieldErrors();
    if (pinInput) { pinInput.value = ''; }
    setStatus('Testing', 'testing');
    panelBody.replaceChildren(el('div', { 'class': 'with-icon small', role: 'status' }, [svgIcon('spin'), el('span', { text: 'Connecting…' })]));
    testButton.disabled = true;

    var data = new FormData(form);
    fetch('/servers/test', {
      method: 'POST',
      body: data,
      credentials: 'same-origin',
      headers: { 'X-CSRF-Token': csrf, 'Accept': 'application/json' }
    }).then(function (response) {
      return response.json().catch(function () { return { ok: false, error: 'Unexpected answer from the server.' }; });
    }).then(function (result) {
      var nodes = [];
      if (result.errors) { showFieldErrors(result.errors); }
      if (result.checks && result.checks.length) {
        var list = el('ul', { 'class': 'checks' });
        result.checks.forEach(function (text) { list.appendChild(el('li', {}, [svgIcon('check'), el('span', { text: text })])); });
        if (result.superuser) {
          list.appendChild(el('li', { 'class': 'warn' }, [svgIcon('alert'), el('span', { text: 'This user has administrator-level privileges. Consider a more limited user.' })]));
        }
        nodes.push(list);
      }
      if (result.pin) { nodes.push(renderPin(result.pin)); }
      if (result.grants && result.grants.length) {
        nodes.push(el('div', { 'class': 'stack-6' }, [
          el('span', { 'class': 'overline', text: 'This user can' }),
          el('code', { 'class': 'code-box', text: result.grants.join('\n') })
        ]));
      }
      if (!result.ok) {
        nodes.unshift(el('div', { 'class': 'callout callout-danger', role: 'alert' }, [svgIcon('alert'), el('span', { text: result.error || 'The test failed.' })]));
      }
      setStatus(result.ok ? 'Passed' : 'Failed', result.ok ? 'passed' : 'failed');
      panelBody.replaceChildren.apply(panelBody, nodes);
    }).catch(function () {
      setStatus('Failed', 'failed');
      panelBody.replaceChildren(el('div', { 'class': 'callout callout-danger', role: 'alert' }, [svgIcon('alert'), el('span', { text: 'Could not reach the portal. Check your connection and try again.' })]));
    }).then(function () {
      testButton.disabled = false;
    });
  });
})();
