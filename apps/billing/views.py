import stripe
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from datetime import timedelta

from .models import (
    BillingPlan, TenantSubscription, Invoice, PaymentMethod, 
    UsageRecord, BillingEvent
)
from .serializers import (
    BillingPlanSerializer, TenantSubscriptionSerializer, InvoiceSerializer,
    PaymentMethodSerializer, UsageRecordSerializer, BillingEventSerializer
)
from apps.roles.decorators import IsTenantAdmin

# Configure Stripe
stripe.api_key = settings.STRIPE_SECRET_KEY


class BillingPlanViewSet(viewsets.ReadOnlyModelViewSet):
    """Public billing plans"""
    queryset = BillingPlan.objects.filter(is_active=True, is_public=True)
    serializer_class = BillingPlanSerializer
    permission_classes = []  # Public endpoint
    
    @action(detail=False, methods=['get'])
    def pricing(self, request):
        """Get pricing information for all plans"""
        plans = self.get_queryset()
        
        pricing_data = []
        for plan in plans:
            pricing_data.append({
                'id': plan.id,
                'name': plan.name,
                'type': plan.plan_type,
                'description': plan.description,
                'pricing': {
                    'monthly': {
                        'price': plan.price_monthly,
                        'stripe_price_id': plan.stripe_price_id_monthly,
                    },
                    'yearly': {
                        'price': plan.price_yearly,
                        'stripe_price_id': plan.stripe_price_id_yearly,
                    }
                },
                'limits': {
                    'users': plan.user_limit,
                    'api_calls': plan.api_call_limit,
                    'storage_gb': plan.storage_limit_gb,
                },
                'features': plan.features,
                'overage_pricing': {
                    'users': plan.overage_user_price,
                    'api_calls': plan.overage_api_call_price,
                    'storage_gb': plan.overage_storage_price_gb,
                }
            })
        
        return Response({
            'plans': pricing_data,
            'currency': 'USD',
            'tax_rate': getattr(settings, 'BILLING_TAX_RATE', 0.08)
        })


class TenantSubscriptionViewSet(viewsets.ModelViewSet):
    """Manage tenant subscription"""
    serializer_class = TenantSubscriptionSerializer
    permission_classes = [IsAuthenticated, IsTenantAdmin]
    
    def get_queryset(self):
        return TenantSubscription.objects.filter(tenant=self.request.tenant)
    
    @action(detail=False, methods=['post'])
    def create_subscription(self, request):
        """Create new subscription with Stripe"""
        plan_id = request.data.get('plan_id')
        billing_interval = request.data.get('billing_interval', 'monthly')
        payment_method_id = request.data.get('payment_method_id')
        
        try:
            plan = BillingPlan.objects.get(id=plan_id, is_active=True)
        except BillingPlan.DoesNotExist:
            return Response({'error': 'Invalid plan'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Get or create Stripe customer
        stripe_customer_id = self.get_or_create_stripe_customer(request.tenant)
        
        # Attach payment method to customer
        if payment_method_id:
            stripe.PaymentMethod.attach(
                payment_method_id,
                customer=stripe_customer_id,
            )
        
        # Create Stripe subscription
        stripe_subscription = stripe.Subscription.create(
            customer=stripe_customer_id,
            items=[{
                'price': plan.get_stripe_price_id(billing_interval),
                'quantity': 1,
            }],
            default_payment_method=payment_method_id,
            trial_period_days=14 if not request.tenant.subscription else None,
        )
        
        # Create or update local subscription
        subscription, created = TenantSubscription.objects.update_or_create(
            tenant=request.tenant,
            defaults={
                'plan': plan,
                'stripe_subscription_id': stripe_subscription.id,
                'stripe_customer_id': stripe_customer_id,
                'status': stripe_subscription.status,
                'billing_interval': billing_interval,
                'current_period_start': timezone.datetime.fromtimestamp(
                    stripe_subscription.current_period_start
                ),
                'current_period_end': timezone.datetime.fromtimestamp(
                    stripe_subscription.current_period_end
                ),
                'trial_start': timezone.datetime.fromtimestamp(
                    stripe_subscription.trial_start
                ) if stripe_subscription.trial_start else None,
                'trial_end': timezone.datetime.fromtimestamp(
                    stripe_subscription.trial_end
                ) if stripe_subscription.trial_end else None,
            }
        )
        
        # Log billing event
        BillingEvent.objects.create(
            tenant=request.tenant,
            event_type='subscription_created',
            description=f'Subscription created for {plan.name} plan',
            subscription=subscription,
            event_data={
                'plan_name': plan.name,
                'billing_interval': billing_interval,
                'stripe_subscription_id': stripe_subscription.id,
            }
        )
        
        return Response(
            TenantSubscriptionSerializer(subscription).data,
            status=status.HTTP_201_CREATED
        )
    
    @action(detail=True, methods=['post'])
    def change_plan(self, request, pk=None):
        """Change subscription plan"""
        subscription = self.get_object()
        new_plan_id = request.data.get('plan_id')
        
        try:
            new_plan = BillingPlan.objects.get(id=new_plan_id, is_active=True)
        except BillingPlan.DoesNotExist:
            return Response({'error': 'Invalid plan'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Update Stripe subscription
        stripe_subscription = stripe.Subscription.retrieve(subscription.stripe_subscription_id)
        stripe.Subscription.modify(
            subscription.stripe_subscription_id,
            items=[{
                'id': stripe_subscription['items']['data'][0].id,
                'price': new_plan.get_stripe_price_id(subscription.billing_interval),
            }]
        )
        
        # Update local subscription
        old_plan = subscription.plan
        subscription.plan = new_plan
        subscription.save()
        
        # Log billing event
        BillingEvent.objects.create(
            tenant=request.tenant,
            event_type='subscription_updated',
            description=f'Plan changed from {old_plan.name} to {new_plan.name}',
            subscription=subscription,
            event_data={
                'old_plan': old_plan.name,
                'new_plan': new_plan.name,
            }
        )
        
        return Response(TenantSubscriptionSerializer(subscription).data)
    
    @action(detail=True, methods=['post'])
    def cancel_subscription(self, request, pk=None):
        """Cancel subscription"""
        subscription = self.get_object()
        cancel_immediately = request.data.get('cancel_immediately', False)
        
        if cancel_immediately:
            # Cancel immediately
            stripe.Subscription.delete(subscription.stripe_subscription_id)
            subscription.status = 'canceled'
            subscription.canceled_at = timezone.now()
            subscription.ended_at = timezone.now()
        else:
            # Cancel at period end
            stripe.Subscription.modify(
                subscription.stripe_subscription_id,
                cancel_at_period_end=True
            )
            subscription.canceled_at = timezone.now()
        
        subscription.save()
        
        # Log billing event
        BillingEvent.objects.create(
            tenant=request.tenant,
            event_type='subscription_canceled',
            description='Subscription canceled',
            subscription=subscription,
            event_data={'cancel_immediately': cancel_immediately}
        )
        
        return Response({'message': 'Subscription canceled successfully'})
    
    @action(detail=False, methods=['get'])
    def usage_summary(self, request):
        """Get current usage summary"""
        try:
            subscription = TenantSubscription.objects.get(tenant=request.tenant)
        except TenantSubscription.DoesNotExist:
            return Response({'error': 'No active subscription'}, status=404)
        
        # Calculate overage charges
        overage_charges = subscription.calculate_overage_charges()
        
        usage_data = {
            'subscription': {
                'plan_name': subscription.plan.name,
                'status': subscription.status,
                'current_period_end': subscription.current_period_end,
                'is_trial': subscription.is_trial(),
                'days_until_renewal': subscription.days_until_renewal(),
            },
            'usage': {
                'users': {
                    'current': subscription.current_users,
                    'limit': subscription.plan.user_limit,
                    'overage': max(0, subscription.current_users - subscription.plan.user_limit),
                },
                'api_calls': {
                    'current': subscription.current_api_calls,
                    'limit': subscription.plan.api_call_limit,
                    'overage': max(0, subscription.current_api_calls - subscription.plan.api_call_limit),
                },
                'storage': {
                    'current_gb': subscription.current_storage_gb,
                    'limit_gb': subscription.plan.storage_limit_gb,
                    'overage_gb': max(0, subscription.current_storage_gb - subscription.plan.storage_limit_gb),
                }
            },
            'overage_charges': overage_charges,
            'features': subscription.plan.features,
        }
        
        return Response(usage_data)
    
    def get_or_create_stripe_customer(self, tenant):
        """Get or create Stripe customer for tenant"""
        try:
            subscription = TenantSubscription.objects.get(tenant=tenant)
            if subscription.stripe_customer_id:
                return subscription.stripe_customer_id
        except TenantSubscription.DoesNotExist:
            pass
        
        # Create new Stripe customer
        customer = stripe.Customer.create(
            email=tenant.admin_email if hasattr(tenant, 'admin_email') else '',
            name=tenant.name,
            metadata={'tenant_id': str(tenant.id)}
        )
        
        return customer.id


class InvoiceViewSet(viewsets.ReadOnlyModelViewSet):
    """View tenant invoices"""
    serializer_class = InvoiceSerializer
    permission_classes = [IsAuthenticated, IsTenantAdmin]
    
    def get_queryset(self):
        return Invoice.objects.filter(tenant=self.request.tenant)
    
    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """Download invoice PDF"""
        invoice = self.get_object()
        
        if not invoice.stripe_invoice_id:
            return Response({'error': 'Invoice not available for download'}, status=400)
        
        try:
            # Get invoice PDF URL from Stripe
            stripe_invoice = stripe.Invoice.retrieve(invoice.stripe_invoice_id)
            pdf_url = stripe_invoice.invoice_pdf
            
            return Response({'download_url': pdf_url})
        except stripe.error.StripeError as e:
            return Response({'error': str(e)}, status=400)


class PaymentMethodViewSet(viewsets.ModelViewSet):
    """Manage tenant payment methods"""
    serializer_class = PaymentMethodSerializer
    permission_classes = [IsAuthenticated, IsTenantAdmin]
    
    def get_queryset(self):
        return PaymentMethod.objects.filter(tenant=self.request.tenant)
    
    @action(detail=False, methods=['post'])
    def add_card(self, request):
        """Add credit card payment method"""
        token = request.data.get('token')  # Stripe token
        
        if not token:
            return Response({'error': 'Payment token required'}, status=400)
        
        try:
            # Create payment method from token
            payment_method = stripe.PaymentMethod.create(
                type='card',
                card={'token': token}
            )
            
            # Store payment method
            pm = PaymentMethod.objects.create(
                tenant=request.tenant,
                stripe_payment_method_id=payment_method.id,
                payment_type='card',
                card_last4=payment_method.card.last4,
                card_brand=payment_method.card.brand,
                card_exp_month=payment_method.card.exp_month,
                card_exp_year=payment_method.card.exp_year,
                is_default=not PaymentMethod.objects.filter(tenant=request.tenant).exists()
            )
            
            return Response(PaymentMethodSerializer(pm).data, status=201)
            
        except stripe.error.StripeError as e:
            return Response({'error': str(e)}, status=400)
    
    @action(detail=True, methods=['post'])
    def set_default(self, request, pk=None):
        """Set payment method as default"""
        payment_method = self.get_object()
        
        # Clear other default payment methods
        PaymentMethod.objects.filter(tenant=request.tenant).update(is_default=False)
        
        # Set this one as default
        payment_method.is_default = True
        payment_method.save()
        
        return Response({'message': 'Default payment method updated'})


class UsageRecordViewSet(viewsets.ReadOnlyModelViewSet):
    """View usage records for billing"""
    serializer_class = UsageRecordSerializer
    permission_classes = [IsAuthenticated, IsTenantAdmin]
    
    def get_queryset(self):
        try:
            subscription = TenantSubscription.objects.get(tenant=self.request.tenant)
            return UsageRecord.objects.filter(subscription=subscription)
        except TenantSubscription.DoesNotExist:
            return UsageRecord.objects.none()
    
    @action(detail=False, methods=['get'])
    def current_month(self, request):
        """Get current month usage"""
        start_of_month = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end_of_month = (start_of_month + timedelta(days=32)).replace(day=1) - timedelta(days=1)
        
        records = self.get_queryset().filter(
            record_date__range=[start_of_month.date(), end_of_month.date()]
        )
        
        # Aggregate usage
        total_usage = {
            'api_calls': sum(r.api_calls_count for r in records),
            'users': max((r.users_count for r in records), default=0),
            'storage_gb': max((r.storage_used_gb for r in records), default=0),
            'active_users': sum(r.active_users for r in records),
        }
        
        return Response({
            'period': {
                'start': start_of_month.date(),
                'end': end_of_month.date(),
            },
            'usage': total_usage,
            'records': UsageRecordSerializer(records, many=True).data
        })


class BillingEventViewSet(viewsets.ReadOnlyModelViewSet):
    """View billing events for audit"""
    serializer_class = BillingEventSerializer
    permission_classes = [IsAuthenticated, IsTenantAdmin]
    
    def get_queryset(self):
        return BillingEvent.objects.filter(tenant=self.request.tenant)