from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from guard.brand_intel import reset_brand_domain_cache
from guard.models import Brand, BrandDomain


@receiver(post_save, sender=Brand)
@receiver(post_delete, sender=Brand)
@receiver(post_save, sender=BrandDomain)
@receiver(post_delete, sender=BrandDomain)
def _reset_brand_cache_on_change(**_kwargs):
    reset_brand_domain_cache()

