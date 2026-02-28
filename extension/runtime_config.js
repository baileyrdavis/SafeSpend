/*
  Publish-time runtime configuration.
  Set API_BASE_URL once before packaging so end users never need to enter backend URLs manually.
*/
globalThis.SAFESPEND_RUNTIME_CONFIG = {
  API_BASE_URL: 'https://safespend-api.up.railway.app',
};
