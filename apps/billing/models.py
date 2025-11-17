import uuid
from decimal import Decimal
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta

User = get_user_model()


class BillingPlan(models.Model):
    """Subscription plans for tenants"""
    
    PLAN_TYPES = [
        ('starter', 'Starter'),
        ('professional', 'Professional'),
        ('enterprise', 'Enterprise'),
        ('custom', 'Custom'),
    ]
    
    BILLING_INTERVALS = [
        ('monthly', 'Monthly'),
        ('yearly', 'Yearly'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    plan_type = models.CharField(max_length=20, choices=PLAN_TYPES)
    description = models.TextField(blank=True)
    
    # Pricing
    price_monthly = models.DecimalField(max_digits=10, decimal_places=2)
    price_yearly = models.DecimalField(max_digits=10, decimal_places=2)
    stripe_price_id_monthly = models.CharField(max_length=100, blank=True)
    stripe_price_id_yearly = models.CharField(max_length=100, blank=True)
    
    # Limits
    user_limit = models.IntegerField(help_text="Maximum number of users")
    api_call_limit = models.IntegerField(help_text="API calls per month")
    storage_limit_gb = models.IntegerField(help_text="Storage limit in GB")
    
    # Features
    features = models.JSONField(
        default=list,
        help_text="List of included features: ['sso', 'mfa', 'audit_logs', 'custom_branding']"
    )
    
    # Overage pricing
    overage_user_price = models.DecimalField(max_digits=6, decimal_places=2, default=0)
    overage_api_call_price = models.DecimalField(max_digits=6, decimal_places=4, default=0)
    overage_storage_price_gb = models.DecimalField(max_digits=6, decimal_places=2, default=0)
    
    # Plan status
    is_active = models.BooleanField(default=True)
    is_public = models.BooleanField(default=True, help_text="Show in public pricing")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['price_monthly']
        verbose_name = 'Billing Plan'
        verbose_name_plural = 'Billing Plans'
    
    def __str__(self):
        return f"{self.name} (${self.price_monthly}/month)"
    
    def get_price(self, interval='monthly'):
        """Get price for billing interval"""
        return self.price_yearly if interval == 'yearly' else self.price_monthly
    
    def get_stripe_price_id(self, interval='monthly'):
        """Get Stripe price ID for billing interval"""
        return self.stripe_price_id_yearly if interval == 'yearly' else self.stripe_price_id_monthly


class TenantSubscription(models.Model):
    """Tenant subscription to a billing plan"""
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('past_due', 'Past Due'),
        ('canceled', 'Canceled'),
        ('incomplete', 'Incomplete'),
        ('incomplete_expired', 'Incomplete Expired'),
        ('trialing', 'Trialing'),
        ('paused', 'Paused'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.OneToOneField('tenants.Tenant', on_delete=models.CASCADE, related_name='subscription')
    plan = models.ForeignKey(BillingPlan, on_delete=models.PROTECT, related_name='subscriptions')
    
    # Stripe integration
    stripe_subscription_id = models.CharField(max_length=100, unique=True, blank=True)
    stripe_customer_id = models.CharField(max_length=100, blank=True)
    
    # Subscription details
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    billing_interval = models.CharField(max_length=20, choices=BillingPlan.BILLING_INTERVALS, default='monthly')
    quantity = models.IntegerField(default=1, help_text="Number of licenses/seats")
    
    # Dates
    current_period_start = models.DateTimeField()
    current_period_end = models.DateTimeField()
    trial_start = models.DateTimeField(null=True, blank=True)
    trial_end = models.DateTimeField(null=True, blank=True)
    canceled_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    
    # Usage tracking
    current_users = models.IntegerField(default=0)
    current_api_calls = models.IntegerField(default=0)
    current_storage_gb = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    # Billing contact
    billing_email = models.EmailField(blank=True)
    billing_name = models.CharField(max_length=200, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Tenant Subscription'
        verbose_name_plural = 'Tenant Subscriptions'
    
    def __str__(self):
        return f"{self.tenant.name} - {self.plan.name} ({self.status})"
    
    def is_trial(self):
        """Check if subscription is in trial period"""
        if not self.trial_end:
            return False
        return timezone.now() < self.trial_end
    
    def days_until_renewal(self):
        """Calculate days until next renewal"""
        if not self.current_period_end:
            return 0
        delta = self.current_period_end - timezone.now()
        return max(0, delta.days)
    
    def calculate_overage_charges(self):
        """Calculate overage charges for current period"""
        charges = Decimal('0.00')
        
        # User overage
        if self.current_users > self.plan.user_limit:
            overage_users = self.current_users - self.plan.user_limit
            charges += overage_users * self.plan.overage_user_price
        
        # API call overage
        if self.current_api_calls > self.plan.api_call_limit:
            overage_calls = self.current_api_calls - self.plan.api_call_limit
            charges += overage_calls * self.plan.overage_api_call_price
        
        # Storage overage
        if self.current_storage_gb > self.plan.storage_limit_gb:
            overage_storage = self.current_storage_gb - self.plan.storage_limit_gb
            charges += overage_storage * self.plan.overage_storage_price_gb
        
        return charges
    
    def has_feature(self, feature_name):
        """Check if subscription plan includes a feature"""
        return feature_name in self.plan.features


class Invoice(models.Model):
    """Invoice records for billing"""
    
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('open', 'Open'),
        ('paid', 'Paid'),
        ('void', 'Void'),
        ('uncollectible', 'Uncollectible'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='invoices')
    subscription = models.ForeignKey(TenantSubscription, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Stripe integration
    stripe_invoice_id = models.CharField(max_length=100, unique=True, blank=True)
    
    # Invoice details
    invoice_number = models.CharField(max_length=50, unique=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    
    # Amounts
    subtotal = models.DecimalField(max_digits=10, decimal_places=2)
    tax_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    currency = models.CharField(max_length=3, default='USD')
    
    # Dates
    invoice_date = models.DateTimeField(default=timezone.now)
    due_date = models.DateTimeField()
    paid_at = models.DateTimeField(null=True, blank=True)
    
    # Billing period
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    
    # Additional info
    description = models.TextField(blank=True)
    notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-invoice_date']
        verbose_name = 'Invoice'
        verbose_name_plural = 'Invoices'
    
    def __str__(self):
        return f"Invoice {self.invoice_number} - {self.tenant.name}"
    
    def is_overdue(self):
        """Check if invoice is overdue"""
        return self.status == 'open' and timezone.now() > self.due_date


class InvoiceLineItem(models.Model):
    """Line items for invoices"""
    
    ITEM_TYPES = [
        ('subscription', 'Subscription Fee'),
        ('overage_users', 'User Overage'),
        ('overage_api', 'API Call Overage'),
        ('overage_storage', 'Storage Overage'),
        ('setup_fee', 'Setup Fee'),
        ('discount', 'Discount'),
        ('tax', 'Tax'),
        ('other', 'Other'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, related_name='line_items')
    
    item_type = models.CharField(max_length=20, choices=ITEM_TYPES)
    description = models.CharField(max_length=500)
    quantity = models.DecimalField(max_digits=10, decimal_places=2, default=1)
    unit_price = models.DecimalField(max_digits=10, decimal_places=4)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    
    # Period for subscription items
    period_start = models.DateTimeField(null=True, blank=True)
    period_end = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['created_at']
        verbose_name = 'Invoice Line Item'
        verbose_name_plural = 'Invoice Line Items'
    
    def __str__(self):
        return f"{self.description} - ${self.amount}"


class PaymentMethod(models.Model):
    """Stored payment methods for tenants"""
    
    PAYMENT_TYPES = [
        ('card', 'Credit Card'),
        ('bank_account', 'Bank Account'),
        ('paypal', 'PayPal'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='payment_methods')
    
    # Stripe integration
    stripe_payment_method_id = models.CharField(max_length=100, unique=True)
    
    payment_type = models.CharField(max_length=20, choices=PAYMENT_TYPES)
    is_default = models.BooleanField(default=False)
    
    # Card details (last 4 digits, brand, etc.)
    card_last4 = models.CharField(max_length=4, blank=True)
    card_brand = models.CharField(max_length=20, blank=True)
    card_exp_month = models.IntegerField(null=True, blank=True)
    card_exp_year = models.IntegerField(null=True, blank=True)
    
    # Bank account details
    bank_last4 = models.CharField(max_length=4, blank=True)
    bank_name = models.CharField(max_length=100, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Payment Method'
        verbose_name_plural = 'Payment Methods'
    
    def __str__(self):
        if self.payment_type == 'card':
            return f"{self.card_brand} ending in {self.card_last4}"
        elif self.payment_type == 'bank_account':
            return f"{self.bank_name} ending in {self.bank_last4}"
        return f"{self.get_payment_type_display()}"


class UsageRecord(models.Model):
    """Usage tracking for billing"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    subscription = models.ForeignKey(TenantSubscription, on_delete=models.CASCADE, related_name='usage_records')
    
    # Usage period
    record_date = models.DateField()
    
    # Usage metrics
    users_count = models.IntegerField(default=0)
    api_calls_count = models.IntegerField(default=0)
    storage_used_gb = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    # Additional metrics
    active_users = models.IntegerField(default=0)
    sso_logins = models.IntegerField(default=0)
    webhook_deliveries = models.IntegerField(default=0)
    audit_events = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = [['subscription', 'record_date']]
        ordering = ['-record_date']
        verbose_name = 'Usage Record'
        verbose_name_plural = 'Usage Records'
    
    def __str__(self):
        return f"Usage for {self.subscription.tenant.name} - {self.record_date}"


class BillingEvent(models.Model):
    """Track billing-related events for audit purposes"""
    
    EVENT_TYPES = [
        ('subscription_created', 'Subscription Created'),
        ('subscription_updated', 'Subscription Updated'),
        ('subscription_canceled', 'Subscription Canceled'),
        ('invoice_created', 'Invoice Created'),
        ('invoice_paid', 'Invoice Paid'),
        ('payment_failed', 'Payment Failed'),
        ('trial_started', 'Trial Started'),
        ('trial_ended', 'Trial Ended'),
        ('overage_warning', 'Overage Warning'),
        ('payment_method_added', 'Payment Method Added'),
        ('payment_method_removed', 'Payment Method Removed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE, related_name='billing_events')
    
    event_type = models.CharField(max_length=30, choices=EVENT_TYPES)
    description = models.TextField()
    
    # Related objects
    subscription = models.ForeignKey(TenantSubscription, on_delete=models.SET_NULL, null=True, blank=True)
    invoice = models.ForeignKey(Invoice, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Event data
    event_data = models.JSONField(default=dict)
    
    # Stripe webhook event ID
    stripe_event_id = models.CharField(max_length=100, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Billing Event'
        verbose_name_plural = 'Billing Events'
    
    def __str__(self):
        return f"{self.get_event_type_display()} - {self.tenant.name}"