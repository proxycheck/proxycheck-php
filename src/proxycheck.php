<?php

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
    const OPTION_HOST_DETECTION = 'HOST_DETECTION';
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


    public static function check($address, $options)
    {
        // Setup the correct querying string for the transport security selected.
        if (isset($options['TLS_SECURITY']) && $options['TLS_SECURITY'] === true) {
            $url = "https://";
            if ( isset($options['HMAC_KEY']) && !empty($options['HMAC_KEY']) && strlen($options['HMAC_KEY']) == 64 ) {
                $perform_hmac = true;
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
            $post_fields[] = "ips=" . implode(",", $address);
        } else {
            $post_fields[] = "ips=" . $address;
        }

        // Build up the URL string with the selected flags.
        if (isset($options['API_KEY'])) {
            $url .= "?key=" . $options['API_KEY'];
        } else {
            $url .= "?key=";
        }
        
        if (isset($options['DAY_RESTRICTOR'])) {
            $url .= "&days=" . $options['DAY_RESTRICTOR'];
        }
        
        $url .= "&node=1";

        // By default the tag used is your querying domain and the webpage being accessed
        // However you can supply your own descriptive tag or disable tagging altogether.
        if (isset($options['QUERY_TAGGING']) && $options['QUERY_TAGGING'] === true && empty($options['CUSTOM_TAG'])) {
            $post_fields[] = "tag=" . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI'];
        } else {
            if (isset($options['QUERY_TAGGING']) && $options['QUERY_TAGGING'] === true && !empty($options['CUSTOM_TAG'])) {
                $post_fields[] = "tag=" . $options['CUSTOM_TAG'];
            }
        }

        // Performing the API query to proxycheck.io/v2/ using cURL
        if ( isset($post_fields) && !empty($post_fields) ) {
            $decoded_json = self::makeRequest($url, implode("&", $post_fields), 'POST');
        } else {
            $decoded_json = self::makeRequest($url);
        }
        
        // If we're using TLS and a HMAC key has been provided, hash the JSON payload and perform a signature validation
        if ( isset($perform_hmac) && $perform_hmac === true ) {
          
          if ( isset($decoded_json["headers"]["http_x_signature"]) ) {
            // Hash the payload using the HMAC key
            $hmac_hash = hash_hmac('sha256', $decoded_json["raw"], $options['HMAC_KEY']);
            if ( $hmac_hash !== $decoded_json["headers"]["http_x_signature"] ) {
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
        
        // If we're checking multiple addresses the block, block_reason and local country blocking doesn't apply.
        // Thus we'll return early before that code is run.
        if (is_array($address)) {
            $decoded_json["body"]["block"] = false;
            $decoded_json["body"]["block_reason"] = "na";
            return $decoded_json["body"];
        }
            
        // Check if we're looking up an email address to see if it's disposable or not.
        // We return straight after as country and other checks are not applicable.
        if ( strpos($address, "@") !== false && isset($decoded_json[$address]["detections"]["disposable"]) ) {
          if ( $decoded_json[$address]["detections"]["disposable"] === true ) {
              $decoded_json["body"]["block"] = true;
              $decoded_json["body"]["block_reason"] = "disposable";
          } else {
              $decoded_json["body"]["block"] = false;
              $decoded_json["body"]["block_reason"] = "na";
          }
          return $decoded_json["body"];
        }

        // Output the clear block and block reasons for the address we're checking.
        // Read through the API's detections response and match the entries to the detection types supplied in the options array
        if ( isset($decoded_json[$address]["detections"]) ) {
          foreach ( $decoded_json[$address]["detections"] as $detection_key => $detection_value ) {
            
            if ( isset($options[strtoupper($detection_key) . "_DETECTION"]) && $options[strtoupper($detection_key) . "_DETECTION"] === true && $detection_value === true ) {
                $decoded_json["body"]["block"] = true;
                $decoded_json["body"]["block_reason"] = $detection_key;
                break;
            }
            
          }
        } else {
            $decoded_json["body"]["block"] = false;
            $decoded_json["body"]["block_reason"] = "na";
        }
        
        // Country checking for blocking and allowing specific countries by name or isocode.
        if ($decoded_json["body"]["block"] === false && isset($options['BLOCKED_COUNTRIES']) && !empty($options['BLOCKED_COUNTRIES'][0])) {
            if (in_array($decoded_json[$address]["location"]["country_name"], $options['BLOCKED_COUNTRIES']) or in_array(
                    $decoded_json[$address]["location"]["country_code"],
                    $options['BLOCKED_COUNTRIES']
                )) {
                $decoded_json["body"]["block"] = true;
                $decoded_json["body"]["block_reason"] = "country";
            }
        } else if ($decoded_json["body"]["block"] === true && isset($options['ALLOWED_COUNTRIES']) && !empty($options['ALLOWED_COUNTRIES'][0])) {
            if (in_array($decoded_json[$address]["location"]["country_name"], $options['ALLOWED_COUNTRIES']) or in_array(
                    $decoded_json[$address]["location"]["country_code"],
                    $options['ALLOWED_COUNTRIES']
                )) {
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
        $url .= "proxycheck.io/dashboard/" . $options['LIST_SELECTION'] . "/" . $options['LIST_ACTION'] . "/";
        $url .= "?key=" . $options['API_KEY'];

        if ($options['LIST_ACTION'] == "add" or $options['LIST_ACTION'] == "remove" or $options['LIST_ACTION'] == "set") {
            if (!empty($options['LIST_ENTRIES'])) {
                $post_fields = "data=" . implode("\r\n", $options['LIST_ENTRIES']);
            } else {
                $post_fields = "";
            }
        } else {
            $post_fields = "";
        }

        // Performing the API query to proxycheck.io/dashboard/ using cURL
        $decoded_json = self::makeRequest($url, $post_fields, 'POST');

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
        $url .= "proxycheck.io/dashboard/rules/" . $options['RULE_ACTION'] . "/";
        $url .= "?key=" . $options['API_KEY'];

        if (!empty($options['RULE_SELECTION'])) {
            $post_fields = "name=" . $options['RULE_SELECTION'];
        }
        
        if (!empty($options['RULE_ENTRIES'])) {
            $post_fields .= "data=" . $options['RULE_ENTRIES'];
        }
        
        if ( !isset($post_fields) OR empty($post_fields) ) {
          $post_fields = '';
        }
        
        // Performing the API query to proxycheck.io/dashboard/rules/ using cURL
        $decoded_json = self::makeRequest($url, $post_fields, 'POST');

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
        $url .= "proxycheck.io/dashboard/export/" . $options['STAT_SELECTION'] . "/";
        $url .= "?key=" . $options['API_KEY'];

        if (strcasecmp($options['STAT_SELECTION'], "detections") == 0 or strcasecmp(
                $options['STAT_SELECTION'],
                "queries"
            ) == 0) {
            $url .= "&json=1";
        }

        if (strcasecmp($options['STAT_SELECTION'], "detections") == 0) {
            if (empty($options['LIMIT'])) {
                $options['LIMIT'] = 100;
            }
            if (empty($options['OFFSET'])) {
                $options['OFFSET'] = 0;
            }
            $url .= "&limit=" . $options['LIMIT'];
            $url .= "&offset=" . $options['OFFSET'];
        }

        // Performing the API query to proxycheck.io/dashboard/ using cURL
        $decoded_json = self::makeRequest($url);

        return $decoded_json["body"];
    }

    public static function makeRequest($url, $params = [], $method = 'GET')
    {
        $ch = curl_init($url);

        $curl_options = array(
            CURLOPT_CONNECTTIMEOUT => 30,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true
        );

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
