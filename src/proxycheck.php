<?php
  
  namespace proxycheck;
  
  use proxycheck\proxycheck as proxycheck;
  
  class proxycheck {

    public static function check($Visitor_IP, $Options) {


      // Setup the correct querying string for the transport security selected.
      if ( $Options['TLS_SECURITY'] == TRUE ) { $URL = "https://"; } else { $URL = "http://"; }
      
      // Check if they have enabled blocking or allowing countries and if so, enable ASN checking.
      if ( !empty($Options['BLOCKED_COUNTRIES']) OR !empty($Options['ALLOWED_COUNTRIES'])) {
        $Options['ASN_DATA'] = 1;
      }
      
      // Build up the URL string with the selected flags.
      $URL .= "proxycheck.io/v2/" . $Visitor_IP;
      $URL .= "?key=" . $Options['API_KEY'];
      $URL .= "&days=" . $Options['DAY_RESTRICTOR'];
      $URL .= "&vpn=" . $Options['VPN_DETECTION'];
      $URL .= "&inf=" . $Options['INF_ENGINE'];
      $URL .= "&asn=" . $Options['ASN_DATA'];
      $URL .= "&node=1";
      $URL .= "&port=1";
      $URL .= "&seen=1";
      
      // By default the tag used is your querying domain and the webpage being accessed
      // However you can supply your own descriptive tag or disable tagging altogether.
      if ( $Options['QUERY_TAGGING'] == TRUE && empty($Options['CUSTOM_TAG']) ) {
        $Post_Field = "tag=" . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI'];
      } else if ( $Options['QUERY_TAGGING'] == TRUE && !empty($Options['CUSTOM_TAG']) ) {
        $Post_Field = "tag=" . $Options['CUSTOM_TAG'];
      } else {
        $Post_Field = "";
      }
      
      // Performing the API query to proxycheck.io/v2/ using cURL
      $ch = curl_init($URL);
      
      $curl_options = array(
        CURLOPT_CONNECTTIMEOUT => 30,
        CURLOPT_POST => 1,
        CURLOPT_POSTFIELDS => $Post_Field,
        CURLOPT_RETURNTRANSFER => true
      );
      
      curl_setopt_array($ch, $curl_options);
      $API_JSON_Result = curl_exec($ch);
      curl_close($ch);
      
      // Decode the JSON from our API
      $Decoded_JSON = json_decode($API_JSON_Result, true);

      // Output the clear block and block reasons for the IP we're checking.
      if ( isset($Decoded_JSON[$Visitor_IP]["proxy"]) && $Decoded_JSON[$Visitor_IP]["proxy"] == "yes" && $Decoded_JSON[$Visitor_IP]["type"] == "VPN" ) {
        
        $Decoded_JSON["block"] = "yes";
        $Decoded_JSON["block_reason"] = "vpn";
        
      } else if ( isset($Decoded_JSON[$Visitor_IP]["proxy"]) && $Decoded_JSON[$Visitor_IP]["proxy"] == "yes" ) {
        
        $Decoded_JSON["block"] = "yes";
        $Decoded_JSON["block_reason"] = "proxy";
        
      } else {
        
        $Decoded_JSON["block"] = "no";
        $Decoded_JSON["block_reason"] = "na";
        
      }
      
      // Country checking for blocking and allowing specific countries by name or isocode.
      if ( $Decoded_JSON["block"] == "no" && !empty($Options['BLOCKED_COUNTRIES']) ) {
          if ( in_array($Decoded_JSON[$Visitor_IP]["country"],$Options['BLOCKED_COUNTRIES']) OR in_array($Decoded_JSON[$Visitor_IP]["isocode"],$Options['BLOCKED_COUNTRIES'])  ) {
            $Decoded_JSON["block"] = "yes";
            $Decoded_JSON["block_reason"] = "country";
          }
      } else if ( $Decoded_JSON["block"] == "yes" && !empty($Options['ALLOWED_COUNTRIES'])) {
          if ( in_array($Decoded_JSON[$Visitor_IP]["country"],$Options['ALLOWED_COUNTRIES']) OR in_array($Decoded_JSON[$Visitor_IP]["isocode"],$Options['ALLOWED_COUNTRIES'])  ) {
            $Decoded_JSON["block"] = "no";
            $Decoded_JSON["block_reason"] = "na";
          }
      }
      
      return $Decoded_JSON;
      
    }

    public static function listing($Options) {

      // Setup the correct querying string for the transport security selected.
      if ( $Options['TLS_SECURITY'] == TRUE ) { $URL = "https://"; } else { $URL = "http://"; }
      
      // Build up the URL string for the selected list and action.
      $URL .= "proxycheck.io/dashboard/" . $Options['LIST_SELECTION'] . "/" . $Options['LIST_ACTION'] . "/";
      $URL .= "?key=" . $Options['API_KEY'];
      
      if ( $Options['LIST_ACTION'] == "add" OR $Options['LIST_ACTION'] == "remove" OR $Options['LIST_ACTION'] == "set") {
        if ( !empty($Options['LIST_ENTRIES']) ) {
          $Post_Field = "data=" . implode("\r\n", $Options['LIST_ENTRIES']);
        } else {
          $Post_Field = "";
        }
      } else {
        $Post_Field = "";
      }
      
      // Performing the API query to proxycheck.io/dashboard/ using cURL
      $ch = curl_init($URL);
      
      $curl_options = array(
        CURLOPT_CONNECTTIMEOUT => 30,
        CURLOPT_POST => 1,
        CURLOPT_POSTFIELDS => $Post_Field,
        CURLOPT_RETURNTRANSFER => true
      );
      
      curl_setopt_array($ch, $curl_options);
      $API_JSON_Result = curl_exec($ch);
      curl_close($ch);
      
      // Decode the JSON from our API
      $Decoded_JSON = json_decode($API_JSON_Result, true);
      
      return $Decoded_JSON;
      
    }

    public static function stats($Options) {

      // Setup the correct querying string for the transport security selected.
      if ( $Options['TLS_SECURITY'] == TRUE ) { $URL = "https://"; } else { $URL = "http://"; }
      
      // Build up the URL string for the selected export stat.
      $URL .= "proxycheck.io/dashboard/export/" . $Options['STAT_SELECTION'] . "/";
      $URL .= "?key=" . $Options['API_KEY'];
      
      if ( strcasecmp($Options['STAT_SELECTION'], "detections") == 0 OR strcasecmp($Options['STAT_SELECTION'], "queries") == 0  ) {
        $URL .= "&json=1";
      }
      
      if ( strcasecmp($Options['STAT_SELECTION'], "detections") == 0 ) {
        if ( empty($Options['LIMIT']) ) { $Options['LIMIT'] = 100; }
        if ( empty($Options['OFFSET']) ) { $Options['OFFSET'] = 0; }
        $URL .= "&limit=" . $Options['LIMIT'];
        $URL .= "&offset=" . $Options['OFFSET'];
      }
      
      // Performing the API query to proxycheck.io/dashboard/ using cURL
      $ch = curl_init($URL);
      
      $curl_options = array(
        CURLOPT_CONNECTTIMEOUT => 30,
        CURLOPT_RETURNTRANSFER => true
      );
      
      curl_setopt_array($ch, $curl_options);
      $API_JSON_Result = curl_exec($ch);
      curl_close($ch);
      
      // Decode the JSON from our API
      $Decoded_JSON = json_decode($API_JSON_Result, true);
      
      return $Decoded_JSON;
      
    }
  
  }
