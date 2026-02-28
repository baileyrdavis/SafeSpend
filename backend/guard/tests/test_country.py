from django.test import SimpleTestCase

from guard.risk_engine.country import infer_country


class CountryInferenceTests(SimpleTestCase):
    def test_infer_country_au_signals(self):
        country, confidence, evidence = infer_country(
            'example.com.au',
            {
                'currency': 'AUD',
                'shipping_destinations': ['AU'],
                'address_text': 'Sydney NSW 2000',
            },
        )

        self.assertEqual(country, 'AU')
        self.assertGreater(confidence, 0.5)
        self.assertGreaterEqual(evidence['votes']['AU'], 3)
