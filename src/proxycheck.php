<?php

/**
 * proxycheck-php
 *
 * Version: 1.0.5
 * Date:    2026-09-29
 * GitHub:  https://github.com/proxycheck/proxycheck-php
 */

namespace proxycheck;

class proxycheck
{
    const OPTION_API_KEY = 'API_KEY';
    const OPTION_ASN_DATA = 'ASN_DATA';
    const OPTION_ALLOWED_COUNTRIES = 'ALLOWED_COUNTRIES';
    const OPTION_BLOCKED_COUNTRIES = 'BLOCKED_COUNTRIES';
    const OPTION_TLS_SECURITY = 'TLS_SECURITY';
    const OPTION_INF_ENGINE = 'INF_ENGINE';
    const OPTION_RISK_DATA = 'RISK_DATA';
    const OPTION_ANONYMOUS_DETECTION = 'ANONYMOUS_DETECTION';
    const OPTION_PROXY_DETECTION = 'PROXY_DETECTION';
    const OPTION_VPN_DETECTION = 'VPN_DETECTION';
    const OPTION_SCRAPER_DETECTION = 'SCRAPER_DETECTION';
    const OPTION_TOR_DETECTION = 'TOR_DETECTION';
    const OPTION_COMPROMISED_DETECTION = 'COMPROMISED_DETECTION';
    const OPTION_HOST_DETECTION = 'HOSTING_DETECTION';
    const OPTION_HOSTING_DETECTION = 'HOSTING_DETECTION';
    const OPTION_DAY_RESTRICTOR = 'DAY_RESTRICTOR';
    const OPTION_QUERY_TAGGING = 'QUERY_TAGGING';
    const OPTION_CUSTOM_TAG = 'CUSTOM_TAG';
    const OPTION_MASK_ADDRESS = 'MASK_ADDRESS';
    const OPTION_LIST_SELECTION = 'LIST_SELECTION';
    const OPTION_LIST_ACTION = 'LIST_ACTION';
    const OPTION_RULE_SELECTION = 'RULE_SELECTION';
    const OPTION_RULE_ACTION = 'RULE_ACTION';
    const OPTION_LIMIT = 'LIMIT';
    const OPTION_OFFSET = 'OFFSET';
    const OPTION_STAT_SELECTION = 'STAT_SELECTION';
    const OPTION_CONNECTION_TIMEOUT_MS = 'CUSTOM_CONNECTION_TIMEOUT';
    const OPTION_TRANSFER_TIMEOUT_MS = 'CUSTOM_TRANSFER_TIMEOUT';
    const OPTION_CUSTOM_CURL_OPTIONS = 'CUSTOM_CURL_OPTIONS';


    public static function check($address, $options)
    {
        // Setup the correct querying string for the transport security selected.
        if (isset($options['TLS_SECURITY']) && $options['TLS_SECURITY'] === true) {
            $url = "https://";
            if ( isset($options['HMAC_KEY']) && !empty($options['HMAC_KEY']) && strlen($options['HMAC_KEY']) == 64 ) {
                $perform_hmac = true;
            } else if ( isset($options['HMAC_KEY']) && !empty($options['HMAC_KEY']) && strlen($options['HMAC_KEY']) != 64 ) {
                $decoded_json["body"]["status"] = "error";
                $decoded_json["body"]["message"] = "Invalid HMAC key provided by your code to the proxycheck library.";
                $decoded_json["body"]["block"] = false;
                $decoded_json["body"]["block_reason"] = "na";
                $perform_hmac = false;
                return $decoded_json["body"];
            } else {
                $perform_hmac = false;
            }
        } else {
            $url = "http://";
            $perform_hmac = false;
        }
        
        $url .= "proxycheck.io/v3/";
        
        // Check if email masking has been enabled and perform that masking if we're checking an email address.
        if ( isset($options['MASK_ADDRESS']) && $options['MASK_ADDRESS'] === true ) {
            if (is_array($address)) {
                $Anonymised_Addresses = array();
                foreach ( $address as $single_address ) {
                    if ( strpos($single_address, "@") !== false ) {
                        $Anonymised_Addresses[] = "anonymous@" . explode("@", $single_address)[1];
                    } else {
                        $Anonymised_Addresses[] = $single_address;
                    }
                }
                $address = $Anonymised_Addresses;
            } else {
                if ( strpos($address, "@") !== false ) {
                    $address = "anonymous@" . explode("@", $address)[1];
                }
            }
        }

        // Check if the address is an array of addresses to be checked.
        if (is_array($address)) {
            $post_fields[] = "ips=" . urlencode(implode(",", $address));
        } else {
            $post_fields[] = "ips=" . urlencode($address);
        }

        // Build up the URL string with the selected flags.
        $url .= "?key=" . rawurlencode($options['API_KEY'] ?? '');

        if (isset($options['DAY_RESTRICTOR'])) {
            $url .= "&days=" . rawurlencode($options['DAY_RESTRICTOR']);
        }

        $url .= "&node=1";

        // By default the tag used is your querying domain and the webpage being accessed
        // However you can supply your own descriptive tag or disable tagging altogether.
        if (isset($options['QUERY_TAGGING']) && $options['QUERY_TAGGING'] === true) {
            if (!empty($options['CUSTOM_TAG'])) {
                $tag = $options['CUSTOM_TAG'];
            } else {
                $tag = ($_SERVER['SERVER_NAME'] ?? '') . ($_SERVER['REQUEST_URI'] ?? '');
            }
            $post_fields[] = "tag=" . urlencode($tag);
        }
        
        $curl_options = array();

        // Get the connection timeout in ms if supplied by options.
        if (isset($options['CONNECTION_TIMEOUT_MS'])) {
            $curl_options[CURLOPT_CONNECTTIMEOUT_MS] = $options['CONNECTION_TIMEOUT_MS'];
        }

        // Get the data transfer timeout in ms if supplied by options.
        if (isset($options['TRANSFER_TIMEOUT_MS'])) {
            $curl_options[CURLOPT_TIMEOUT_MS] = $options['TRANSFER_TIMEOUT_MS'];
        }

        // Allow fully custom cURL options if provided by options.
        if (isset($options['CUSTOM_CURL_OPTIONS']) && is_array($options['CUSTOM_CURL_OPTIONS'])) {
            foreach ($options['CUSTOM_CURL_OPTIONS'] as $key => $value) {
                $resolved_key = is_string($key) ? constant($key) : $key;
                $curl_options[$resolved_key] = $value;
            }
        }

        // Performing the API query to proxycheck.io/v3/ using cURL
        if ( isset($post_fields) && !empty($post_fields) ) {
            $decoded_json = self::makeRequest($url, $curl_options, implode("&", $post_fields), 'POST');
        } else {
            $decoded_json = self::makeRequest($url, $curl_options);
        }

        // Request failed (cURL error or non-JSON response).
        if (!is_array($decoded_json["body"] ?? null)) {
            return [
                "status"       => "error",
                "message"      => $decoded_json["error"] ?? "Invalid or empty API response.",
                "block"        => false,
                "block_reason" => "na",
            ];
        }
        
        // If we're using TLS and a HMAC key has been provided, hash the JSON payload and perform a signature validation
        if ( isset($perform_hmac) && $perform_hmac === true ) {
          
          if ( isset($decoded_json["headers"]["http_x_signature"]) ) {
            // Hash the payload using the HMAC key
            $hmac_hash = hash_hmac('sha256', $decoded_json["raw"], $options['HMAC_KEY']);
            if ( !hash_equals($hmac_hash, $decoded_json["headers"]["http_x_signature"]) ) {
                if (isset($decoded_json)) { unset($decoded_json); }
                $decoded_json["body"]["status"] = "error";
                $decoded_json["body"]["message"] = "Invalid HMAC signature.";
                $decoded_json["body"]["block"] = false;
                $decoded_json["body"]["block_reason"] = "na";
                return $decoded_json["body"];
            }
          } else {
              if (isset($decoded_json)) { unset($decoded_json); }
              $decoded_json["body"]["status"] = "error";
              $decoded_json["body"]["message"] = "Missing http_x_signature (HMAC) in API response.";
              $decoded_json["body"]["block"] = false;
              $decoded_json["body"]["block_reason"] = "na";
              return $decoded_json["body"];
          }
          
        }

        // Defaults - always present in the returned array.
        $decoded_json["body"]["block"] = false;
        $decoded_json["body"]["block_reason"] = "na";

        // Multiple addresses: per-address block logic doesn't apply.
        if (is_array($address)) {
            return $decoded_json["body"];
        }

        $result = $decoded_json["body"][$address] ?? null;
        if ($result === null) {
            return $decoded_json["body"]; // address not in response
        }

        // Email lookups: only the disposable check applies.
        if (strpos($address, "@") !== false) {
            if (($result["detections"]["disposable"] ?? false) === true) {
                $decoded_json["body"]["block"] = true;
                $decoded_json["body"]["block_reason"] = "disposable";
            }
            return $decoded_json["body"];
        }

        // Detection-based blocking.
        foreach (($result["detections"] ?? []) as $detection_key => $detection_value) {
            if ($detection_value === true && ($options[strtoupper($detection_key) . "_DETECTION"] ?? false) === true) {
                $decoded_json["body"]["block"] = true;
                $decoded_json["body"]["block_reason"] = $detection_key;
                break;
            }
        }

        // Country blocking / allowing by name or ISO code.
        $country_name = $result["location"]["country_name"] ?? null;
        $country_code = $result["location"]["country_code"] ?? null;

        if ($decoded_json["body"]["block"] === false && !empty($options['BLOCKED_COUNTRIES'][0])) {
            if (in_array($country_name, $options['BLOCKED_COUNTRIES'], true) || in_array($country_code, $options['BLOCKED_COUNTRIES'], true)) {
                $decoded_json["body"]["block"] = true;
                $decoded_json["body"]["block_reason"] = "country";
            }
        } elseif ($decoded_json["body"]["block"] === true && !empty($options['ALLOWED_COUNTRIES'][0])) {
            if (in_array($country_name, $options['ALLOWED_COUNTRIES'], true) || in_array($country_code, $options['ALLOWED_COUNTRIES'], true)) {
                $decoded_json["body"]["block"] = false;
                $decoded_json["body"]["block_reason"] = "na";
            }
        }

        return $decoded_json["body"];
    }

    public static function listing($options)
    {
        // Setup the correct querying string for the transport security selected.
        if (isset($options['TLS_SECURITY']) && $options['TLS_SECURITY'] === true) {
            $url = "https://";
        } else {
            $url = "http://";
        }

        // Build up the URL string for the selected list and action.
        $url .= "proxycheck.io/dashboard/" . rawurlencode($options['LIST_SELECTION']) . "/" . rawurlencode($options['LIST_ACTION']) . "/";
        $url .= "?key=" . rawurlencode($options['API_KEY']);

        if ($options['LIST_ACTION'] == "add" or $options['LIST_ACTION'] == "remove" or $options['LIST_ACTION'] == "set") {
            if (!empty($options['LIST_ENTRIES'])) {
                $post_fields = "data=" . urlencode(implode("\r\n", $options['LIST_ENTRIES']));
            } else {
                $post_fields = "";
            }
        } else {
            $post_fields = "";
        }

        
        $curl_options = array();
        
        // Get the connection timeout in ms if supplied by options.
        if (isset($options['CONNECTION_TIMEOUT_MS'])) {
            $curl_options[CURLOPT_CONNECTTIMEOUT_MS] = $options['CONNECTION_TIMEOUT_MS'];
        }

        // Get the data transfer timeout in ms if supplied by options.
        if (isset($options['TRANSFER_TIMEOUT_MS'])) {
            $curl_options[CURLOPT_TIMEOUT_MS] = $options['TRANSFER_TIMEOUT_MS'];
        }

        // Allow fully custom cURL options if provided by options.
        if (isset($options['CUSTOM_CURL_OPTIONS']) && is_array($options['CUSTOM_CURL_OPTIONS'])) {
            foreach ($options['CUSTOM_CURL_OPTIONS'] as $key => $value) {
                $resolved_key = is_string($key) ? constant($key) : $key;
                $curl_options[$resolved_key] = $value;
            }
        }

        // Performing the API query to proxycheck.io/dashboard/ using cURL
        $decoded_json = self::makeRequest($url, $curl_options, $post_fields, 'POST');

        if (!is_array($decoded_json["body"] ?? null)) {
            return ["status" => "error", "message" => $decoded_json["error"] ?? "Invalid or empty API response."];
        }
        
        return $decoded_json["body"];
    }

    public static function rules($options)
    {
        // Setup the correct querying string for the transport security selected.
        if (isset($options['TLS_SECURITY']) && $options['TLS_SECURITY'] === true) {
            $url = "https://";
        } else {
            $url = "http://";
        }

                // Build up the URL string for the selected rule and action.
        $url .= "proxycheck.io/dashboard/rules/" . rawurlencode($options['RULE_ACTION']) . "/";
        $url .= "?key=" . rawurlencode($options['API_KEY']);

        $post_data = array();

        if (!empty($options['RULE_SELECTION'])) {
            $post_data['name'] = $options['RULE_SELECTION'];
        }

        if (!empty($options['RULE_ENTRIES'])) {
            $post_data['data'] = is_array($options['RULE_ENTRIES'])
                ? implode("\r\n", $options['RULE_ENTRIES'])
                : $options['RULE_ENTRIES'];
        }

        $post_fields = http_build_query($post_data);

        $curl_options = array();

        // Get the connection timeout in ms if supplied by options.
        if (isset($options['CONNECTION_TIMEOUT_MS'])) {
            $curl_options[CURLOPT_CONNECTTIMEOUT_MS] = $options['CONNECTION_TIMEOUT_MS'];
        }

        // Get the data transfer timeout in ms if supplied by options.
        if (isset($options['TRANSFER_TIMEOUT_MS'])) {
            $curl_options[CURLOPT_TIMEOUT_MS] = $options['TRANSFER_TIMEOUT_MS'];
        }

        // Allow fully custom cURL options if provided by options.
        if (isset($options['CUSTOM_CURL_OPTIONS']) && is_array($options['CUSTOM_CURL_OPTIONS'])) {
            foreach ($options['CUSTOM_CURL_OPTIONS'] as $key => $value) {
                $resolved_key = is_string($key) ? constant($key) : $key;
                $curl_options[$resolved_key] = $value;
            }
        }
        
        // Performing the API query to proxycheck.io/dashboard/rules/ using cURL
        $decoded_json = self::makeRequest($url, $curl_options, $post_fields, 'POST');

        if (!is_array($decoded_json["body"] ?? null)) {
            return ["status" => "error", "message" => $decoded_json["error"] ?? "Invalid or empty API response."];
        }

        return $decoded_json["body"];
    }

    public static function stats($options)
    {
        // Setup the correct querying string for the transport security selected.
        if (isset($options['TLS_SECURITY']) && $options['TLS_SECURITY'] === true) {
            $url = "https://";
        } else {
            $url = "http://";
        }

        // Build up the URL string for the selected export stat.
        $url .= "proxycheck.io/dashboard/export/" . rawurlencode($options['STAT_SELECTION']) . "/";
        $url .= "?key=" . rawurlencode($options['API_KEY']);

        if (strcasecmp($options['STAT_SELECTION'], "detections") == 0 or strcasecmp(
                $options['STAT_SELECTION'],
                "queries"
            ) == 0) {
            $url .= "&json=1";
        }

        if (strcasecmp($options['STAT_SELECTION'], "detections") == 0) {
            // Cast to int so user-supplied values can't inject extra query parameters.
            $limit  = (int) ($options['LIMIT'] ?? 0);
            $offset = (int) ($options['OFFSET'] ?? 0);

            if ($limit <= 0) {
                $limit = 100;
            }
            if ($offset < 0) {
                $offset = 0;
            }

            $url .= "&limit=" . $limit;
            $url .= "&offset=" . $offset;
        }
      
        $curl_options = array();
        
        // Get the connection timeout in ms if supplied by options.
        if (isset($options['CONNECTION_TIMEOUT_MS'])) {
            $curl_options[CURLOPT_CONNECTTIMEOUT_MS] = $options['CONNECTION_TIMEOUT_MS'];
        }

        // Get the data transfer timeout in ms if supplied by options.
        if (isset($options['TRANSFER_TIMEOUT_MS'])) {
            $curl_options[CURLOPT_TIMEOUT_MS] = $options['TRANSFER_TIMEOUT_MS'];
        }

        // Allow fully custom cURL options if provided by options.
        if (isset($options['CUSTOM_CURL_OPTIONS']) && is_array($options['CUSTOM_CURL_OPTIONS'])) {
            foreach ($options['CUSTOM_CURL_OPTIONS'] as $key => $value) {
                $resolved_key = is_string($key) ? constant($key) : $key;
                $curl_options[$resolved_key] = $value;
            }
        }

        // Performing the API query to proxycheck.io/dashboard/ using cURL
        $decoded_json = self::makeRequest($url, $curl_options);

        if (!is_array($decoded_json["body"] ?? null)) {
            return ["status" => "error", "message" => $decoded_json["error"] ?? "Invalid or empty API response."];
        }

        return $decoded_json["body"];
    }

    public static function makeRequest($url, $curl_options_input, $params = [], $method = 'GET')
    {
        $ch = curl_init($url);

        $curl_options = array(
            CURLOPT_CONNECTTIMEOUT_MS => 3000,
            CURLOPT_TIMEOUT_MS => 15000,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_USERAGENT => 'proxycheck-php/1.0.5'
        );
        
        if ( isset($curl_options_input) && $curl_options_input != null ) {
            $resolved = array();
            foreach ( $curl_options_input as $key => $value ) {
                $resolved_key = is_string($key) ? constant($key) : $key;
                $resolved[$resolved_key] = $value;
            }
            $curl_options = $resolved + $curl_options;
        }

        if ($method === 'POST') {
            $curl_options[CURLOPT_POST] = 1;
            $curl_options[CURLOPT_POSTFIELDS] = $params;
        }

        curl_setopt_array($ch, $curl_options);

        $response = curl_exec($ch);

        if ($response === false) {
            $error = curl_error($ch);
            curl_close($ch);
            return [
                'headers' => [],
                'body' => null,
                'error' => $error
            ];
        }

        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $raw_headers = substr($response, 0, $header_size);
        $body = substr($response, $header_size);

        curl_close($ch);

        // Parse headers into array
        $headers = [];
        foreach (explode("\r\n", trim($raw_headers)) as $line) {
            if (strpos($line, ':') !== false) {
                list($key, $value) = explode(':', $line, 2);
                $headers[trim($key)] = trim($value);
            } elseif (!empty($line)) {
                $headers['Status'] = $line;
            }
        }

        return [
            'headers' => $headers,
            'raw' => $body,
            'body' => json_decode($body, true)
        ];
    }

}
