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

  const bodyText = document.body?.innerText?.slice(0, 6000) || '';
  if (/\bAUD\b/i.test(bodyText) || /A\$/i.test(bodyText)) return 'AUD';
  if (/\bGBP\b/i.test(bodyText) || /£/i.test(bodyText)) return 'GBP';
  if (/\bUSD\b/i.test(bodyText) || /US\$/i.test(bodyText)) return 'USD';
  if (/\$/i.test(bodyText)) return 'USD';
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

function detectEcommerce() {
  const bodyText = document.body?.innerText?.slice(0, 7000) || '';
  const hasCartButton = Boolean(
    document.querySelector(
      'a[href*="cart" i], button[name*="cart" i], [aria-label*="cart" i], button[class*="add-to-cart" i], button[id*="add-to-cart" i]'
    )
  );
  const hasCheckoutRoute = Boolean(
    document.querySelector('a[href*="checkout" i], form[action*="checkout" i], a[href*="/cart" i]')
  );
  const hasSchemaProduct = hasProductSchema();
  const hasStoreText = textIncludesAny(bodyText, ['add to cart', 'buy now', 'checkout', 'shipping', 'returns']);

  return {
    hasCartButton,
    hasCheckoutRoute,
    hasSchemaProduct,
    isEcommerce: hasCartButton || hasCheckoutRoute || hasSchemaProduct || hasStoreText
  };
}

function extractPolicies() {
  const links = Array.from(document.querySelectorAll('a'));
  const linkTexts = links.map((link) => `${link.textContent || ''} ${link.href || ''}`.toLowerCase());

  return {
    refund: linkTexts.some((value) => value.includes('refund') || value.includes('return policy')),
    privacy: linkTexts.some((value) => value.includes('privacy')),
    terms: linkTexts.some((value) => value.includes('terms') || value.includes('conditions'))
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

function getCheckoutLink() {
  const anchor = document.querySelector('a[href*="checkout" i], form[action*="checkout" i]');
  if (!anchor) return null;

  const href = anchor.getAttribute('href') || anchor.getAttribute('action');
  if (!href) return null;

  try {
    return new URL(href, window.location.href).href;
  } catch (_error) {
    return null;
  }
}

async function computeHtmlHash() {
  const html = document.documentElement.outerHTML.slice(0, 250000);
  const data = new TextEncoder().encode(html);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const bytes = Array.from(new Uint8Array(digest));
  return bytes.map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function extractSignals() {
  const ecommerce = detectEcommerce();
  if (!ecommerce.isEcommerce) {
    return null;
  }

  const checkoutLink = getCheckoutLink();
  const checkoutDomain = checkoutLink ? new URL(checkoutLink).hostname : null;
  const rootDomain = guessRegisteredDomain(window.location.hostname);
  const checkoutRootDomain = checkoutDomain ? guessRegisteredDomain(checkoutDomain) : null;

  const signals = {
    is_ecommerce: true,
    is_https: window.location.protocol === 'https:',
    currency: findCurrency(),
    cart_present: ecommerce.hasCartButton,
    checkout_link: checkoutLink,
    checkout_domain: checkoutDomain,
    platform: detectPlatform(),
    custom_checkout: Boolean(checkoutRootDomain && checkoutRootDomain !== rootDomain),
    policies: extractPolicies(),
    contact: extractContact(),
    shipping_destinations: extractShippingDestinations(),
    address_text: extractAddressText(),
    dom_features: {
      cart_button: ecommerce.hasCartButton,
      checkout_route: ecommerce.hasCheckoutRoute,
      schema_product: ecommerce.hasSchemaProduct
    }
  };

  signals.html_hash = await computeHtmlHash();
  return signals;
}

function sendNotEcommerce() {
  chrome.runtime.sendMessage({ type: 'NOT_ECOMMERCE' }, () => {
    void chrome.runtime.lastError;
  });
}

async function runExtraction() {
  try {
    const signals = await extractSignals();
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
  if (message?.type === 'RUN_EXTRACTION') {
    runExtraction()
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }
  return false;
});

(async () => {
  await runExtraction();
  // Many storefronts hydrate late; run one delayed pass.
  setTimeout(runExtraction, 2500);
})();
