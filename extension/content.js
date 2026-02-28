function textIncludesAny(haystack, terms) {
  const lower = haystack.toLowerCase();
  return terms.some((term) => lower.includes(term));
}

function guessRegisteredDomain(hostname) {
  const host = String(hostname || '').toLowerCase();
  const parts = host.split('.').filter(Boolean);
  if (parts.length <= 2) return host;

  const twoPartSuffixes = new Set(['co.uk', 'org.uk', 'com.au', 'net.au', 'org.au']);
  const tail = parts.slice(-2).join('.');
  const tail3 = parts.slice(-3).join('.');

  if (twoPartSuffixes.has(tail)) {
    return tail3;
  }

  return parts.slice(-2).join('.');
}

function findCurrency() {
  const metaCurrency = document.querySelector(
    'meta[itemprop="priceCurrency"], meta[property="product:price:currency"], meta[name="currency"]'
  );
  if (metaCurrency?.content) {
    return metaCurrency.content.toUpperCase();
  }

  const localeMeta = document.querySelector('meta[property="og:locale"], html[lang]');
  const localeText = String(localeMeta?.content || localeMeta?.getAttribute?.('lang') || '').toLowerCase();
  if (localeText.includes('en_au') || localeText.includes('en-au')) return 'AUD';

  const currencyNodesText = Array.from(document.querySelectorAll(
    '[itemprop="priceCurrency"], [data-currency], [class*="currency" i], [id*="currency" i], [class*="price" i], [id*="price" i]'
  ))
    .map((node) => `${node?.textContent || ''} ${node?.getAttribute?.('content') || ''} ${node?.getAttribute?.('data-currency') || ''}`)
    .join(' ')
    .slice(0, 30000);

  const bodyText = document.body?.innerText?.slice(0, 60000) || '';
  const combinedText = `${currencyNodesText} ${bodyText}`;

  if (/\bAUD\b/i.test(combinedText) || /\bAU\$\b/i.test(combinedText) || /A\$/i.test(combinedText)) return 'AUD';
  if (/\bGBP\b/i.test(combinedText) || /£/i.test(combinedText)) return 'GBP';
  if (/\bUSD\b/i.test(combinedText) || /US\$/i.test(combinedText)) return 'USD';
  if (/\$/i.test(combinedText)) {
    const host = String(window.location.hostname || '').toLowerCase();
    if (host.endsWith('.au')) return 'AUD';
    return 'USD';
  }
  return null;
}

function detectPlatform() {
  const html = document.documentElement.outerHTML.slice(0, 120000).toLowerCase();
  const scripts = Array.from(document.querySelectorAll('script[src]')).map((node) => node.src.toLowerCase());

  if (scripts.some((src) => src.includes('cdn.shopify.com')) || html.includes('shopify')) {
    return 'shopify';
  }
  if (html.includes('woocommerce') || scripts.some((src) => src.includes('/woocommerce/'))) {
    return 'woocommerce';
  }
  if (html.includes('magento') || html.includes('mage/')) {
    return 'magento';
  }
  if (scripts.some((src) => src.includes('bigcommerce.com')) || html.includes('bigcommerce')) {
    return 'bigcommerce';
  }

  return 'unknown';
}

function hasProductSchema() {
  const scripts = document.querySelectorAll('script[type="application/ld+json"]');
  for (const script of scripts) {
    const raw = script.textContent || '';
    if (raw.includes('"@type"') && raw.toLowerCase().includes('product')) {
      return true;
    }
  }
  return false;
}

function detectEcommerce(platform) {
  const bodyText = document.body?.innerText?.slice(0, 7000) || '';
  const hasCartButton = Boolean(
    document.querySelector(
      'a[href*="cart" i], button[name*="cart" i], [aria-label*="cart" i], button[class*="add-to-cart" i], button[id*="add-to-cart" i], button[class*="add-to-bag" i], button[id*="add-to-bag" i]'
    )
  );
  const hasCheckoutRoute = Boolean(
    document.querySelector('a[href*="checkout" i], form[action*="checkout" i], a[href*="/cart" i]')
  );
  const hasSchemaProduct = hasProductSchema();
  const hasPriceMarker = Boolean(
    document.querySelector('meta[property="product:price:amount"], [itemprop="price"], [data-price], .price, [class*="price" i]')
  );
  const hasStoreText = textIncludesAny(bodyText, [
    'add to cart',
    'add to bag',
    'buy now',
    'proceed to checkout',
    'shopping cart'
  ]);
  const hasKnownPlatform = platform !== 'unknown';

  const strongSignals = [hasCartButton, hasCheckoutRoute, hasSchemaProduct, hasPriceMarker].filter(Boolean).length;
  const weakSignals = [hasStoreText, hasKnownPlatform].filter(Boolean).length;

  return {
    hasCartButton,
    hasCheckoutRoute,
    hasSchemaProduct,
    hasPriceMarker,
    hasStoreText,
    hasKnownPlatform,
    isEcommerce: strongSignals >= 2 || (strongSignals >= 1 && weakSignals >= 1)
  };
}

function extractPolicies() {
  const links = Array.from(document.querySelectorAll('a'));
  const linkTexts = links.map((link) => `${link.textContent || ''} ${link.href || ''}`.toLowerCase());

  return {
    refund: linkTexts.some((value) => (
      value.includes('refund') ||
      value.includes('return policy') ||
      value.includes('returns') ||
      value.includes('money back')
    )),
    privacy: linkTexts.some((value) => value.includes('privacy')),
    terms: linkTexts.some((value) => (
      value.includes('terms') ||
      value.includes('conditions') ||
      value.includes('terms of service')
    ))
  };
}

function extractContact() {
  return {
    email: Boolean(document.querySelector('a[href^="mailto:"]')),
    phone: Boolean(document.querySelector('a[href^="tel:"]')),
    contact_page: Boolean(document.querySelector('a[href*="contact" i], a[href*="support" i]')),
    address: Boolean(document.querySelector('address'))
  };
}

function extractAddressText() {
  const footer = document.querySelector('footer')?.innerText || '';
  const bodySlice = document.body?.innerText?.slice(0, 10000) || '';
  const combined = `${footer} ${bodySlice}`;
  return combined.slice(0, 800);
}

function extractShippingDestinations() {
  const text = (document.body?.innerText || '').slice(0, 12000).toUpperCase();
  const destinations = [];

  if (text.includes('AUSTRALIA') || text.includes(' SHIP TO AU ') || text.includes(' SHIPS TO AU ')) {
    destinations.push('AU');
  }
  if (
    text.includes('UNITED STATES') ||
    text.includes('USA') ||
    text.includes(' SHIP TO US ') ||
    text.includes(' SHIPS TO US ')
  ) {
    destinations.push('US');
  }
  if (text.includes('UNITED KINGDOM') || text.includes(' SHIP TO UK ') || text.includes(' SHIPS TO UK ')) {
    destinations.push('UK');
  }

  return destinations;
}

function extractPaymentSignals() {
  const text = (document.body?.innerText || '').slice(0, 24000).toLowerCase();
  const paymentContextText = Array.from(document.querySelectorAll(
    '[class*="payment" i], [id*="payment" i], [class*="checkout" i], [id*="checkout" i], [class*="billing" i], [id*="billing" i], [class*="cart" i], [id*="cart" i], form[action*="checkout" i]'
  ))
    .map((node) => (node?.innerText || '').toLowerCase())
    .filter(Boolean)
    .join(' ')
    .slice(0, 14000);
  const risky = [];
  const trusted = [];
  const methods = [];
  const riskyEvidence = [];

  const map = [
    ['gift_card', ['gift card', 'itunes card', 'google play card', 'steam card']],
    ['crypto', ['bitcoin', 'ethereum', 'usdt', 'crypto']],
    ['wire_transfer', ['wire transfer', 'bank transfer', 'swift']],
    ['money_transfer', ['western union', 'moneygram']],
    ['payid', ['payid']],
    ['paypal', ['paypal']],
    ['apple_pay', ['apple pay']],
    ['google_pay', ['google pay', 'gpay']],
    ['afterpay', ['afterpay']],
    ['klarna', ['klarna']],
    ['stripe', ['stripe']],
    ['shop_pay', ['shop pay']],
  ];

  map.forEach(([key, terms]) => {
    if (terms.some((term) => text.includes(term))) {
      methods.push(key);
    }
  });

  if (methods.includes('gift_card')) {
    risky.push('gift_card');
    riskyEvidence.push('gift_card_terms');
  }
  if (methods.includes('wire_transfer')) {
    risky.push('wire_transfer');
    riskyEvidence.push('wire_transfer_terms');
  }
  if (methods.includes('money_transfer')) {
    risky.push('money_transfer');
    riskyEvidence.push('money_transfer_terms');
  }
  if (methods.includes('payid')) {
    risky.push('payid');
    riskyEvidence.push('payid_terms');
  }

  const cryptoStrongPattern = /(pay(?:ment)?|checkout|accept(?:ed|ing|s)?|purchase)\W{0,24}(bitcoin|crypto|ethereum|usdt)|(bitcoin|crypto|ethereum|usdt)\W{0,24}(pay(?:ment)?|checkout|accept(?:ed|ing|s)?|purchase)/;
  const cryptoSoftPattern = /\b(bitcoin|crypto|ethereum|usdt)\b/;
  const cryptoStrong = cryptoStrongPattern.test(paymentContextText) || cryptoStrongPattern.test(text);
  const cryptoSoft = cryptoSoftPattern.test(paymentContextText);
  if (cryptoStrong || (cryptoSoft && paymentContextText.includes('payment'))) {
    risky.push('crypto');
    riskyEvidence.push(cryptoStrong ? 'crypto_strong_payment_context' : 'crypto_payment_context');
    if (!methods.includes('crypto')) {
      methods.push('crypto');
    }
  }

  if (methods.includes('paypal')) trusted.push('paypal');
  if (methods.includes('apple_pay')) trusted.push('apple_pay');
  if (methods.includes('google_pay')) trusted.push('google_pay');
  if (methods.includes('afterpay')) trusted.push('afterpay');
  if (methods.includes('klarna')) trusted.push('klarna');
  if (methods.includes('stripe')) trusted.push('stripe');
  if (methods.includes('shop_pay')) trusted.push('shop_pay');

  const uniqueMethods = [...new Set(methods)];
  const uniqueRisky = [...new Set(risky)];
  const uniqueTrusted = [...new Set(trusted)];
  const riskEvidenceCount = riskyEvidence.length;
  const riskyConfidence = uniqueRisky.length
    ? (riskEvidenceCount >= 2 ? 0.85 : 0.62)
    : 0;

  return {
    methods: uniqueMethods,
    risky_methods: uniqueRisky,
    trusted_methods: uniqueTrusted,
    risky_evidence_count: riskEvidenceCount,
    risky_confidence: riskyConfidence,
    risky_evidence: riskyEvidence.slice(0, 8),
  };
}

function extractAbnSignals() {
  const footerText = document.querySelector('footer')?.innerText || '';
  const bodyText = document.body?.innerText || '';
  const text = `${footerText}\n${bodyText}`.slice(0, 180000);
  const pattern = /\b(?:ABN[:\s#-]*)?(\d[\d\s]{10,24})\b/g;
  const normalized = new Set();
  let match;

  while ((match = pattern.exec(text)) !== null) {
    const digits = String(match[1] || '').replace(/[^\d]/g, '');
    if (digits.length === 11) {
      normalized.add(digits);
    }
    if (normalized.size >= 5) break;
  }

  if (!normalized.size) {
    const loosePattern = /\b\d[\d\s]{10,24}\b/g;
    let looseMatch;
    while ((looseMatch = loosePattern.exec(text)) !== null) {
      const digits = String(looseMatch[0] || '').replace(/[^\d]/g, '');
      if (digits.length === 11) {
        normalized.add(digits);
      }
      if (normalized.size >= 5) break;
    }
  }

  return {
    candidates: [...normalized],
    candidate_count: normalized.size,
  };
}

function extractContactProfile() {
  const contactLinks = Array.from(
    document.querySelectorAll('a[href*="contact" i], a[href*="support" i], a[href*="about" i], a[href*="help" i]')
  )
    .map((node) => (node.getAttribute('href') || '').trim().toLowerCase())
    .filter(Boolean)
    .slice(0, 20);

  const emailLinks = Array.from(document.querySelectorAll('a[href^="mailto:"]'))
    .map((node) => (node.getAttribute('href') || '').replace(/^mailto:/i, '').trim().toLowerCase())
    .filter(Boolean)
    .slice(0, 10);

  const phoneLinks = Array.from(document.querySelectorAll('a[href^="tel:"]'))
    .map((node) => (node.getAttribute('href') || '').replace(/^tel:/i, '').replace(/[^\d+]/g, '').trim())
    .filter(Boolean)
    .slice(0, 10);

  const addressBlocks = Array.from(document.querySelectorAll('address'))
    .map((node) => (node.innerText || '').replace(/\s+/g, ' ').trim().toLowerCase())
    .filter(Boolean)
    .slice(0, 6);

  const footerText = (document.querySelector('footer')?.innerText || '')
    .replace(/\s+/g, ' ')
    .toLowerCase()
    .slice(0, 1200);

  return {
    contact_links: contactLinks,
    emails: emailLinks,
    phones: phoneLinks,
    addresses: addressBlocks,
    footer_excerpt: footerText,
  };
}

function getCheckoutLink() {
  const anchor = document.querySelector(
    'a[href*="checkout" i], a[href*="/cart" i], form[action*="checkout" i], form[action*="/cart" i], [data-checkout-url], [data-cart-url]'
  );
  if (!anchor) return null;

  const href =
    anchor.getAttribute('href') ||
    anchor.getAttribute('action') ||
    anchor.getAttribute('data-checkout-url') ||
    anchor.getAttribute('data-cart-url');
  if (!href) return null;

  try {
    return new URL(href, window.location.href).href;
  } catch (_error) {
    return null;
  }
}

async function computeStableFingerprintHash(payload) {
  const data = new TextEncoder().encode(JSON.stringify(payload));
  const digest = await crypto.subtle.digest('SHA-256', data);
  const bytes = Array.from(new Uint8Array(digest));
  return bytes.map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function extractSignals(options = {}) {
  const force = Boolean(options?.force);
  if (window.location.protocol !== 'http:' && window.location.protocol !== 'https:') {
    return null;
  }

  const platform = detectPlatform();
  const ecommerce = detectEcommerce(platform);
  if (!ecommerce.isEcommerce && !force) {
    return null;
  }

  const checkoutLink = getCheckoutLink();
  const checkoutDomain = checkoutLink ? new URL(checkoutLink).hostname : null;
  const rootDomain = guessRegisteredDomain(window.location.hostname);
  const checkoutRootDomain = checkoutDomain ? guessRegisteredDomain(checkoutDomain) : null;
  const policySignals = extractPolicies();
  const contactSignals = extractContact();
  const shippingDestinations = extractShippingDestinations();
  const paymentSignals = extractPaymentSignals();
  const abnSignals = extractAbnSignals();
  const contactProfile = extractContactProfile();
  const contactProfileHash = await computeStableFingerprintHash(contactProfile);
  const addressProfileHash = await computeStableFingerprintHash({
    addresses: contactProfile.addresses,
    footer_excerpt: contactProfile.footer_excerpt,
    address_text: extractAddressText(),
  });

  const signals = {
    is_ecommerce: ecommerce.isEcommerce,
    is_https: window.location.protocol === 'https:',
    currency: findCurrency(),
    cart_present: ecommerce.hasCartButton,
    checkout_link: checkoutLink,
    checkout_domain: checkoutDomain,
    platform,
    custom_checkout: Boolean(checkoutRootDomain && checkoutRootDomain !== rootDomain),
    policies: policySignals,
    contact: contactSignals,
    payment_methods: paymentSignals,
    abn_signals: abnSignals,
    shipping_destinations: shippingDestinations,
    address_text: extractAddressText(),
    contact_profile: contactProfile,
    contact_profile_hash: contactProfileHash,
    address_profile_hash: addressProfileHash,
    dom_features: {
      cart_button: ecommerce.hasCartButton,
      checkout_route: ecommerce.hasCheckoutRoute,
      schema_product: ecommerce.hasSchemaProduct,
      price_marker: ecommerce.hasPriceMarker,
      store_text: ecommerce.hasStoreText,
      known_platform: ecommerce.hasKnownPlatform
    }
  };

  signals.html_hash = await computeStableFingerprintHash({
    domain: window.location.hostname.toLowerCase(),
    is_https: signals.is_https,
    platform: signals.platform,
    custom_checkout: signals.custom_checkout,
    checkout_root_domain: checkoutRootDomain,
    currency: signals.currency || null,
    policies: policySignals,
    contact: contactSignals,
    payment_methods: paymentSignals,
    abn_signals: abnSignals,
    contact_profile_hash: contactProfileHash,
    address_profile_hash: addressProfileHash,
    shipping_destinations: [...shippingDestinations].sort(),
    dom_features: signals.dom_features,
  });
  return signals;
}

function sendNotEcommerce() {
  chrome.runtime.sendMessage({ type: 'NOT_ECOMMERCE' }, () => {
    void chrome.runtime.lastError;
  });
}

function toastId(payload) {
  return `ss-toast-${String(payload?.domain || window.location.hostname).toLowerCase()}`;
}

function dismissedToastDomainKey(payload) {
  return `ss-toast-dismissed:${String(payload?.domain || window.location.hostname).toLowerCase()}`;
}

function isToastDismissedForDomain(payload) {
  try {
    return sessionStorage.getItem(dismissedToastDomainKey(payload)) === '1';
  } catch (_error) {
    return false;
  }
}

function markToastDismissedForDomain(payload) {
  try {
    sessionStorage.setItem(dismissedToastDomainKey(payload), '1');
  } catch (_error) {
    // Ignore environments where storage is blocked.
  }
}

function clearToastSessionState() {
  try {
    const keysToRemove = [];
    for (let index = 0; index < sessionStorage.length; index += 1) {
      const key = sessionStorage.key(index);
      if (key && key.startsWith('ss-toast-dismissed:')) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach((key) => sessionStorage.removeItem(key));
  } catch (_error) {
    // Ignore environments where storage is blocked.
  }
  const root = document.getElementById('ss-toast-root');
  if (root) {
    root.remove();
  }
}

function ensureToastContainer() {
  let root = document.getElementById('ss-toast-root');
  if (root) {
    return root;
  }
  root = document.createElement('div');
  root.id = 'ss-toast-root';
  root.style.position = 'fixed';
  root.style.top = '18px';
  root.style.right = '18px';
  root.style.zIndex = '2147483647';
  root.style.display = 'grid';
  root.style.gap = '10px';
  root.style.maxWidth = '360px';
  root.style.pointerEvents = 'none';
  document.documentElement.appendChild(root);
  return root;
}

function showRiskToast(payload) {
  if (isToastDismissedForDomain(payload)) {
    return;
  }

  const id = toastId(payload);
  const existingCard = document.getElementById(id);
  if (existingCard) {
    existingCard.remove();
  }
  const existingAny = document.querySelector('#ss-toast-root > section');
  if (existingAny) {
    existingAny.remove();
  }

  const root = ensureToastContainer();
  const card = document.createElement('section');
  card.id = id;
  card.style.pointerEvents = 'auto';
  card.style.borderRadius = '12px';
  card.style.padding = '12px';
  card.style.border = '1px solid rgba(220, 38, 38, 0.45)';
  card.style.background = 'linear-gradient(180deg, rgba(25,35,56,0.96), rgba(9,16,29,0.98))';
  card.style.color = '#e5eefb';
  card.style.boxShadow = '0 18px 38px rgba(2, 8, 23, 0.45)';
  card.style.fontFamily = '"Segoe UI", Tahoma, sans-serif';
  card.style.transform = 'translateY(-10px)';
  card.style.opacity = '0';
  card.style.transition = 'opacity 160ms ease, transform 180ms ease';

  const title = document.createElement('div');
  title.style.fontSize = '13px';
  title.style.fontWeight = '700';
  title.textContent = `SafeSpend warning: ${payload.domain}`;

  const score = document.createElement('div');
  score.style.marginTop = '4px';
  score.style.fontSize = '12px';
  score.style.color = '#fecaca';
  const riskLabel = String(payload?.risk_label || '').trim() || 'Elevated Risk';
  score.textContent = `${riskLabel} \u2022 ${payload.risk_score}/100`;

  const reasons = Array.isArray(payload?.reasons) ? payload.reasons : [];
  const uniqueReasons = [...new Set(reasons.map((item) => String(item || '').trim()).filter(Boolean))];
  const reasonsList = document.createElement('ul');
  reasonsList.style.margin = '8px 0 0';
  reasonsList.style.paddingLeft = '18px';
  reasonsList.style.color = '#e3eefc';
  reasonsList.style.fontSize = '12px';
  reasonsList.style.lineHeight = '1.35';
  uniqueReasons.slice(0, 5).forEach((text) => {
    const li = document.createElement('li');
    li.style.marginBottom = '4px';
    li.textContent = text;
    reasonsList.appendChild(li);
  });

  const close = document.createElement('button');
  close.type = 'button';
  close.textContent = 'Dismiss';
  close.style.marginTop = '10px';
  close.style.border = '1px solid rgba(148,163,184,0.44)';
  close.style.borderRadius = '8px';
  close.style.background = 'rgba(148,163,184,0.15)';
  close.style.color = '#dce8f7';
  close.style.fontSize = '11px';
  close.style.fontWeight = '700';
  close.style.padding = '6px 10px';
  close.style.cursor = 'pointer';
  close.onclick = () => {
    markToastDismissedForDomain(payload);
    card.style.opacity = '0';
    card.style.transform = 'translateY(-10px)';
    setTimeout(() => card.remove(), 200);
  };

  const open = document.createElement('button');
  open.type = 'button';
  open.textContent = 'See More Info';
  open.style.marginTop = '10px';
  open.style.marginLeft = '8px';
  open.style.border = '1px solid rgba(29,155,240,0.6)';
  open.style.borderRadius = '8px';
  open.style.background = 'rgba(29,155,240,0.2)';
  open.style.color = '#dce8f7';
  open.style.fontSize = '11px';
  open.style.fontWeight = '700';
  open.style.padding = '6px 10px';
  open.style.cursor = 'pointer';
  open.onclick = () => {
    chrome.runtime.sendMessage({ type: 'OPEN_EXTENSION_POPUP' }, () => {
      void chrome.runtime.lastError;
    });
  };

  const actions = document.createElement('div');
  actions.style.display = 'flex';
  actions.style.alignItems = 'center';
  actions.appendChild(close);
  actions.appendChild(open);

  card.appendChild(title);
  card.appendChild(score);
  if (reasonsList.children.length) {
    card.appendChild(reasonsList);
  }
  card.appendChild(actions);
  root.appendChild(card);

  requestAnimationFrame(() => {
    card.style.opacity = '1';
    card.style.transform = 'translateY(0)';
  });
}

async function runExtraction() {
  try {
    const signals = await extractSignals({ force: false });
    if (!signals) {
      sendNotEcommerce();
      return;
    }

    chrome.runtime.sendMessage(
      {
        type: 'PAGE_SIGNALS',
        payload: {
          domain: window.location.hostname,
          signals
        }
      },
      () => {
        void chrome.runtime.lastError;
      }
    );
  } catch (_error) {
    // Best effort extraction.
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'EXTRACT_SIGNALS') {
    extractSignals({ force: Boolean(message?.force) })
      .then((signals) => sendResponse({ ok: true, payload: { signals } }))
      .catch(() => sendResponse({ ok: false, payload: { signals: null } }));
    return true;
  }
  if (message?.type === 'RUN_EXTRACTION') {
    runExtraction()
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }
  if (message?.type === 'SHOW_RISK_TOAST') {
    showRiskToast(message.payload || {});
    sendResponse({ ok: true });
    return true;
  }
  if (message?.type === 'CLEAR_RISK_TOAST_SESSION') {
    clearToastSessionState();
    sendResponse({ ok: true });
    return true;
  }
  return false;
});

(async () => {
  await runExtraction();
  // Many storefronts hydrate late; run one delayed pass.
  setTimeout(runExtraction, 2500);
})();
