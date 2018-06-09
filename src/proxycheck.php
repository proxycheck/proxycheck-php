<?php
  
  namespace proxycheck;
  
  use proxycheck\proxycheck as proxycheck;
  
  class proxycheck {

    public static function check($Visitor_IP, $Options) {


      // Setup the correct querying string for the transport security selected.
      if ( $Options['TLS_SECURITY'] == TRUE ) { $URL = "https://"; } else { $URL = "http://"; }
      
      // Check if they have enabled the blocked country feature by providing countries.
      if ( !empty($Options['BLOCKED_COUNTRIES']) ) {
        $Options['ASN_DATA'] = 1;
      }
      
      // Build up the URL string with the selected flags.
      $URL .= "proxycheck.io/v2/" . $Visitor_IP;
      $URL .= "?key=" . $Options['API_KEY'];
      $URL .= "&days=" . $Options['DAY_RESTRICTOR'];
      $URL .= "&vpn=" . $Options['VPN_DETECTION'];
      $URL .= "&inf=" . $Options['INF_ENGINE'];
      $URL .= "&asn=" . $Options['ASN_DATA'];
      
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

      // Check if the IP we're testing is a proxy server
      if ( isset($Decoded_JSON[$Visitor_IP]["proxy"]) && $Decoded_JSON[$Visitor_IP]["proxy"] == "yes" && $Decoded_JSON[$Visitor_IP]["type"] == "VPN" ) {
        
        $Decoded_JSON["block"] = "yes";
        $Decoded_JSON["block_reason"] = "vpn";
        
      } else if ( isset($Decoded_JSON[$Visitor_IP]["proxy"]) && $Decoded_JSON[$Visitor_IP]["proxy"] == "yes" ) {
        
        $Decoded_JSON["block"] = "yes";
        $Decoded_JSON["block_reason"] = "proxy";
        
      } else if ( isset($Decoded_JSON[$Visitor_IP]["proxy"]) && in_array($Decoded_JSON[$Visitor_IP]["country"],$Options['BLOCKED_COUNTRIES']) ) {
        
        $Decoded_JSON["block"] = "yes";
        $Decoded_JSON["block_reason"] = "country";
        
      } else {
        
        $Decoded_JSON["block"] = "no";
        $Decoded_JSON["block_reason"] = "na";
        
      }
      
      return $Decoded_JSON;
      
    }
  
  }