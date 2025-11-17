# apps/webhooks/tasks.py
import json
import logging
import requests
from celery import shared_task
from django.utils import timezone
from django.conf import settings
from .models import WebhookDelivery, Webhook

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3)
def deliver_webhook(self, delivery_id):
    """
    Deliver a webhook payload to the configured endpoint
    
    Args:
        delivery_id: UUID of WebhookDelivery record
    """
    try:
        delivery = WebhookDelivery.objects.select_related('webhook', 'tenant').get(id=delivery_id)
        webhook = delivery.webhook
        
        # Skip if webhook is inactive
        if not webhook.is_active:
            delivery.status = 'abandoned'
            delivery.error_message = 'Webhook is inactive'
            delivery.completed_at = timezone.now()
            delivery.save()
            return
        
        # Update delivery attempt
        delivery.attempt_count += 1
        delivery.attempted_at = timezone.now()
        delivery.status = 'retrying' if delivery.attempt_count > 1 else 'pending'
        delivery.save()
        
        # Prepare payload
        payload_data = {
            'event': {
                'id': str(delivery.event_id),
                'type': delivery.event_type,
                'created_at': delivery.created_at.isoformat(),
                'tenant_id': str(delivery.tenant.id),
                'tenant_slug': delivery.tenant.slug,
            },
            'data': delivery.payload
        }
        
        payload_json = json.dumps(payload_data, default=str)
        
        # Generate HMAC signature
        signature = webhook.generate_signature(payload_json)
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': f'Authly-Webhooks/1.0',
            'X-Authly-Event': delivery.event_type,
            'X-Authly-Delivery': str(delivery.id),
            'X-Authly-Signature-256': f'sha256={signature}',
            'X-Authly-Tenant': delivery.tenant.slug,
        }
        
        try:
            # Make HTTP request
            response = requests.post(
                webhook.url,
                data=payload_json,
                headers=headers,
                timeout=webhook.timeout_seconds,
                allow_redirects=False
            )
            
            # Record response
            delivery.response_status = response.status_code
            delivery.response_body = response.text[:10000]  # Limit to 10KB
            delivery.response_headers = dict(response.headers)
            delivery.completed_at = timezone.now()
            
            # Check if successful (2xx status codes)
            if 200 <= response.status_code < 300:
                delivery.status = 'success'
                webhook.record_delivery(success=True)
                logger.info(f"Webhook delivered successfully: {delivery.id}")
                
            else:
                # HTTP error
                delivery.status = 'failed'
                delivery.error_message = f"HTTP {response.status_code}: {response.text[:500]}"
                webhook.record_delivery(success=False)
                
                # Schedule retry if possible
                if delivery.can_retry():
                    delivery.next_retry_at = delivery.calculate_next_retry()
                    delivery.status = 'retrying'
                    delivery.save()
                    
                    # Schedule retry task
                    retry_delay = (delivery.next_retry_at - timezone.now()).total_seconds()
                    deliver_webhook.apply_async(args=[delivery_id], countdown=retry_delay)
                    logger.warning(f"Webhook delivery failed, retrying: {delivery.id}")
                else:
                    delivery.status = 'abandoned'
                    logger.error(f"Webhook delivery abandoned after retries: {delivery.id}")
            
            delivery.save()
            
        except requests.exceptions.RequestException as e:
            # Network error
            delivery.status = 'failed'
            delivery.error_message = str(e)[:1000]
            delivery.completed_at = timezone.now()
            webhook.record_delivery(success=False)
            
            # Schedule retry if possible
            if delivery.can_retry():
                delivery.next_retry_at = delivery.calculate_next_retry()
                delivery.status = 'retrying'
                delivery.save()
                
                # Schedule retry task
                retry_delay = (delivery.next_retry_at - timezone.now()).total_seconds()
                deliver_webhook.apply_async(args=[delivery_id], countdown=retry_delay)
                logger.warning(f"Webhook delivery failed (network), retrying: {delivery.id}")
            else:
                delivery.status = 'abandoned'
                delivery.save()
                logger.error(f"Webhook delivery abandoned after network errors: {delivery.id}")
                
    except WebhookDelivery.DoesNotExist:
        logger.error(f"WebhookDelivery not found: {delivery_id}")
        return
    except Exception as e:
        logger.error(f"Unexpected error in webhook delivery {delivery_id}: {e}")
        raise

@shared_task
def cleanup_old_webhook_deliveries():
    """
    Clean up old webhook delivery records
    
    Removes delivery records older than 30 days to keep database size manageable
    """
    cutoff_date = timezone.now() - timezone.timedelta(days=30)
    
    deleted_count, _ = WebhookDelivery.objects.filter(
        created_at__lt=cutoff_date
    ).delete()
    
    logger.info(f"Cleaned up {deleted_count} old webhook delivery records")
    return deleted_count

@shared_task
def retry_failed_webhooks():
    """
    Retry failed webhook deliveries that are ready for retry
    """
    now = timezone.now()
    
    # Find deliveries ready for retry
    ready_deliveries = WebhookDelivery.objects.filter(
        status='retrying',
        next_retry_at__lte=now
    ).select_related('webhook')
    
    count = 0
    for delivery in ready_deliveries:
        # Only retry if webhook is still active
        if delivery.webhook.is_active:
            deliver_webhook.delay(delivery.id)
            count += 1
        else:
            # Mark as abandoned if webhook was deactivated
            delivery.status = 'abandoned'
            delivery.error_message = 'Webhook was deactivated'
            delivery.save()
    
    logger.info(f"Queued {count} webhook deliveries for retry")
    return count

@shared_task
def webhook_health_check():
    """
    Perform health checks on webhook endpoints
    
    This can be used to proactively test webhook endpoints
    """
    active_webhooks = Webhook.objects.filter(is_active=True)
    results = []
    
    for webhook in active_webhooks:
        try:
            # Send a simple HEAD request to check endpoint availability
            response = requests.head(
                webhook.url,
                timeout=webhook.timeout_seconds,
                allow_redirects=True
            )
            
            is_healthy = 200 <= response.status_code < 400
            
            results.append({
                'webhook_id': str(webhook.id),
                'webhook_name': webhook.name,
                'url': webhook.url,
                'status_code': response.status_code,
                'is_healthy': is_healthy,
                'response_time': response.elapsed.total_seconds()
            })
            
        except requests.exceptions.RequestException as e:
            results.append({
                'webhook_id': str(webhook.id),
                'webhook_name': webhook.name,
                'url': webhook.url,
                'is_healthy': False,
                'error': str(e)
            })
    
    logger.info(f"Webhook health check completed for {len(results)} webhooks")
    return results