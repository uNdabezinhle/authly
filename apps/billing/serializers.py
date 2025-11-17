from rest_framework import serializers
from .models import (
    BillingPlan, TenantSubscription, Invoice, InvoiceLineItem,
    PaymentMethod, UsageRecord, BillingEvent
)


class BillingPlanSerializer(serializers.ModelSerializer):
    monthly_price = serializers.DecimalField(source='price_monthly', max_digits=10, decimal_places=2, read_only=True)
    yearly_price = serializers.DecimalField(source='price_yearly', max_digits=10, decimal_places=2, read_only=True)
    
    class Meta:
        model = BillingPlan
        fields = [
            'id', 'name', 'plan_type', 'description',
            'monthly_price', 'yearly_price',
            'user_limit', 'api_call_limit', 'storage_limit_gb',
            'features',
            'overage_user_price', 'overage_api_call_price', 'overage_storage_price_gb',
            'is_active', 'is_public'
        ]


class TenantSubscriptionSerializer(serializers.ModelSerializer):
    plan_name = serializers.CharField(source='plan.name', read_only=True)
    plan_features = serializers.ListField(source='plan.features', read_only=True)
    is_trial = serializers.SerializerMethodField()
    days_until_renewal = serializers.SerializerMethodField()
    overage_charges = serializers.SerializerMethodField()
    
    class Meta:
        model = TenantSubscription
        fields = [
            'id', 'plan', 'plan_name', 'plan_features',
            'status', 'billing_interval', 'quantity',
            'current_period_start', 'current_period_end',
            'trial_start', 'trial_end', 'is_trial',
            'current_users', 'current_api_calls', 'current_storage_gb',
            'billing_email', 'billing_name',
            'days_until_renewal', 'overage_charges',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'status', 'current_period_start', 'current_period_end',
            'trial_start', 'trial_end', 'created_at', 'updated_at'
        ]
    
    def get_is_trial(self, obj):
        return obj.is_trial()
    
    def get_days_until_renewal(self, obj):
        return obj.days_until_renewal()
    
    def get_overage_charges(self, obj):
        return obj.calculate_overage_charges()


class InvoiceLineItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = InvoiceLineItem
        fields = [
            'id', 'item_type', 'description', 'quantity',
            'unit_price', 'amount', 'period_start', 'period_end'
        ]


class InvoiceSerializer(serializers.ModelSerializer):
    line_items = InvoiceLineItemSerializer(many=True, read_only=True)
    is_overdue = serializers.SerializerMethodField()
    
    class Meta:
        model = Invoice
        fields = [
            'id', 'invoice_number', 'status',
            'subtotal', 'tax_amount', 'total_amount', 'amount_paid', 'currency',
            'invoice_date', 'due_date', 'paid_at',
            'period_start', 'period_end',
            'description', 'notes',
            'line_items', 'is_overdue'
        ]
    
    def get_is_overdue(self, obj):
        return obj.is_overdue()


class PaymentMethodSerializer(serializers.ModelSerializer):
    display_name = serializers.SerializerMethodField()
    
    class Meta:
        model = PaymentMethod
        fields = [
            'id', 'payment_type', 'is_default',
            'card_last4', 'card_brand', 'card_exp_month', 'card_exp_year',
            'bank_last4', 'bank_name',
            'display_name', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']
    
    def get_display_name(self, obj):
        return str(obj)


class UsageRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = UsageRecord
        fields = [
            'id', 'record_date',
            'users_count', 'api_calls_count', 'storage_used_gb',
            'active_users', 'sso_logins', 'webhook_deliveries', 'audit_events',
            'created_at'
        ]


class BillingEventSerializer(serializers.ModelSerializer):
    subscription_plan = serializers.CharField(source='subscription.plan.name', read_only=True)
    invoice_number = serializers.CharField(source='invoice.invoice_number', read_only=True)
    
    class Meta:
        model = BillingEvent
        fields = [
            'id', 'event_type', 'description',
            'subscription_plan', 'invoice_number',
            'event_data', 'created_at'
        ]