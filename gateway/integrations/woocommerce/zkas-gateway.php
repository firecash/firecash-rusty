<?php
/**
 * Plugin Name: ZKas Payments for WooCommerce
 * Description: Accept private ZKAS payments through hosted or self-hosted ZKas Gateway.
 * Version: 0.1.0
 * License: ISC
 */

defined('ABSPATH') || exit;

add_action('plugins_loaded', function () {
    if (!class_exists('WC_Payment_Gateway')) return;

    class WC_Gateway_ZKas extends WC_Payment_Gateway {
        public function __construct() {
            $this->id = 'zkas';
            $this->method_title = 'ZKas';
            $this->method_description = 'Private ZKAS payments using a hosted or self-hosted gateway.';
            $this->has_fields = false;
            $this->supports = array('products');
            $this->init_form_fields();
            $this->init_settings();
            $this->title = $this->get_option('title', 'Pay with ZKAS');
            add_action('woocommerce_update_options_payment_gateways_' . $this->id, array($this, 'process_admin_options'));
        }

        public function init_form_fields() {
            $this->form_fields = array(
                'enabled' => array('title' => 'Enable', 'type' => 'checkbox', 'label' => 'Accept ZKAS', 'default' => 'no'),
                'title' => array('title' => 'Checkout title', 'type' => 'text', 'default' => 'Pay privately with ZKAS'),
                'gateway_url' => array('title' => 'Gateway URL', 'type' => 'url', 'description' => 'Hosted pay.zkas.info or your self-hosted gateway.'),
                'api_key' => array('title' => 'API key', 'type' => 'password'),
                'webhook_secret' => array('title' => 'Webhook secret', 'type' => 'password'),
                'rate' => array('title' => 'ZKAS per store currency unit', 'type' => 'text', 'description' => 'Temporary fixed rate until the optional quote service is configured.', 'default' => '1'),
                'confirmations' => array('title' => 'Required blue-score distance', 'type' => 'number', 'default' => '10'),
            );
        }

        public function process_payment($order_id) {
            $order = wc_get_order($order_id);
            $rate = (float) $this->get_option('rate', '1');
            $sompi = (string) max(1, (int) round(((float) $order->get_total()) * $rate * 100000000));
            $body = array(
                'orderId' => (string) $order_id,
                'amountSompi' => $sompi,
                'expiresIn' => 900,
                'requiredBlueScore' => (int) $this->get_option('confirmations', '10'),
                'redirectUrl' => $this->get_return_url($order),
                'metadata' => array('platform' => 'woocommerce', 'currency' => $order->get_currency()),
            );
            $response = wp_remote_post(rtrim($this->get_option('gateway_url'), '/') . '/api/v1/invoices', array(
                'timeout' => 20,
                'headers' => array(
                    'Authorization' => 'Bearer ' . $this->get_option('api_key'),
                    'Idempotency-Key' => 'woocommerce-' . $order_id,
                    'Content-Type' => 'application/json',
                ),
                'body' => wp_json_encode($body),
            ));
            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) >= 300) {
                wc_add_notice('The ZKAS payment service is temporarily unavailable.', 'error');
                return array('result' => 'failure');
            }
            $invoice = json_decode(wp_remote_retrieve_body($response), true);
            if (empty($invoice['id']) || empty($invoice['checkoutUrl'])) {
                wc_add_notice('The ZKAS gateway returned an invalid invoice.', 'error');
                return array('result' => 'failure');
            }
            $order->update_meta_data('_zkas_invoice_id', sanitize_text_field($invoice['id']));
            $order->update_status('on-hold', 'Waiting for ZKAS payment.');
            $order->save();
            wc_reduce_stock_levels($order_id);
            return array('result' => 'success', 'redirect' => esc_url_raw($invoice['checkoutUrl']));
        }
    }

    add_filter('woocommerce_payment_gateways', function ($methods) {
        $methods[] = 'WC_Gateway_ZKas';
        return $methods;
    });
});

add_action('rest_api_init', function () {
    register_rest_route('zkas/v1', '/webhook', array(
        'methods' => 'POST',
        'permission_callback' => '__return_true',
        'callback' => function (WP_REST_Request $request) {
            $settings = get_option('woocommerce_zkas_settings', array());
            $signature = $request->get_header('zkas-signature');
            $body = $request->get_body();
            if (!preg_match('/^t=(\d+),v1=([a-f0-9]{64})$/', $signature, $matches)) return new WP_REST_Response(null, 401);
            if (abs(time() - (int) $matches[1]) > 300) return new WP_REST_Response(null, 401);
            $expected = hash_hmac('sha256', $matches[1] . '.' . $body, $settings['webhook_secret'] ?? '');
            if (!hash_equals($expected, $matches[2])) return new WP_REST_Response(null, 401);
            $event = json_decode($body, true);
            $invoice = $event['invoice'] ?? array();
            $order_id = $invoice['orderId'] ?? null;
            $order = $order_id ? wc_get_order($order_id) : null;
            if (!$order || $order->get_meta('_zkas_invoice_id') !== ($invoice['id'] ?? '')) return new WP_REST_Response(null, 202);
            if (in_array($invoice['status'] ?? '', array('confirmed', 'overpaid'), true) && !$order->is_paid()) {
                $tx = $invoice['payments'][0]['transactionId'] ?? 'ZKAS';
                if (is_array($tx)) $tx = implode('', array_map(function ($byte) { return sprintf('%02x', $byte); }, $tx));
                $order->payment_complete($tx);
                $order->add_order_note('ZKAS invoice confirmed: ' . sanitize_text_field($invoice['id']));
            }
            return new WP_REST_Response(null, 200);
        },
    ));
});
