# Upgrading from v0.2.x to v1.0.0 #

## General description of changes ##
On September 11th 2025 a new version of the library was released which makes major changes to the options array you pass to the library and also to the full API response you receive from proxycheck.io. The reason for these changes is because starting with version 1.0.0 of this library we now make API calls to the v3 API from proxycheck.io and not the v2 API.

There are no changes to the Dashboard API's which are also utilised by this library so only checking an address needs your attention when upgrading from the old library to the new one except where the ```TLS_SECURITY``` option is concerned as this now needs to be set to true or false instead of 1 or 0.

## Rundown on specific changes ##
1. The options array now uses booleans (true/false) instead of integers (1/0) to indicate if something is enabled or disabled.
2. The ```block: yes/no``` response will now give a boolean (true/false) response
3. The full API response is completely changed due to moving from the proxycheck.io v2 API to the v3 API [`(view v3 docs here)`](https://proxycheck.io/api)

## The new Options Array ##
In versions v0.2.x and below the options array looked like this:

```php
// Get your visitors IP address or email address
// If you're using CloudFlare change $_SERVER["REMOTE_ADDR"] to $_SERVER["HTTP_CF_CONNECTING_IP"]
// You may also supply an array of addresses in $address to check multiple addresses at once.
$address = $_SERVER["REMOTE_ADDR"];

// Input your options for this query including your optional API Key and query flags.
$proxycheck_options = array(
  'API_KEY' => '######-######-######-######', // Your API Key.
  'ASN_DATA' => 1, // Enable ASN data response.
  'DAY_RESTRICTOR' => 7, // Restrict checking to proxies seen in the past # of days.
  'VPN_DETECTION' => 1, // Check for both VPN's and Proxies instead of just Proxies.
  'RISK_DATA' => 1, // 0 = Off, 1 = Risk Score (0-100), 2 = Risk Score & Attack History.
  'INF_ENGINE' => 1, // Enable or disable the real-time inference engine.
  'TLS_SECURITY' => 0, // Enable or disable transport security (TLS).
  'QUERY_TAGGING' => 1, // Enable or disable query tagging.
  'MASK_ADDRESS' => 1, // Anonymises the local-part of an email address (e.g. anonymous@domain.tld)
  'CUSTOM_TAG' => '', // Specify a custom query tag instead of the default (Domain+Page).
  'BLOCKED_COUNTRIES' => array('Wakanda', 'WA'), // Specify an array of countries or isocodes to be blocked.
  'ALLOWED_COUNTRIES' => array('Azeroth', 'AJ') // Specify an array of countries or isocodes to be allowed.
);

$result_array = \proxycheck\proxycheck::check($address, $proxycheck_options);
```

Take special note to the options which used either 0 or 1 to indicate if an option was turned on or off. This has been replaced by true and false like in the examples below. We've also removed redundant options that are no longer needed due to the API giving a fuller result by default.

In addition to that change you now have a choice of detecting, you can either detect just annonymous addresses without care for their sub-type (Proxy, VPN, TOR, Comrpomised, Hosting etc) or you can specify the exact type of detections you're interested in.

These options will be used for the ```block: true/false``` and ```block: reason``` responses from the library, they will not alter the raw API result you receive alongside the block suggestion and block reason because the v3 API always provides a detailed response containing all the various detections the IP has triggered, this differs from the v2 API that only showed a single detection type.

#### Blocking based on just anonymous addresses example ####
Below we've set ```ANONYMOUS_DETECTION``` to true. This means if the API responds that the address is anonymous you will receive a ```block: true``` result.

```php
// Get your visitors IP address or email address
// If you're using CloudFlare change $_SERVER["REMOTE_ADDR"] to $_SERVER["HTTP_CF_CONNECTING_IP"]
// You may also supply an array of addresses in $address to check multiple addresses at once.
$address = $_SERVER["REMOTE_ADDR"];

// Input your options for this query including your optional API Key and query flags.
$proxycheck_options = array(
  'API_KEY' => '######-######-######-######', // Your API Key.
  'DAY_RESTRICTOR' => 7, // Restrict checking to proxies seen in the past # of days.
  'ANONYMOUS_DETECTION' => true, // Set to true to enable Anonymous detections
  'TLS_SECURITY' => false, // Enable or disable transport security (TLS).
  'QUERY_TAGGING' => true, // Enable or disable query tagging.
  'MASK_ADDRESS' => true, // Anonymises the local-part of an email address (e.g. anonymous@domain.tld)
  'CUSTOM_TAG' => '0', // Specify a custom query tag instead of the default (Domain+Page).
  'CUSTOM_TAG' => '', // Specify a custom query tag instead of the default (Domain+Page).
  'BLOCKED_COUNTRIES' => array('Wakanda', 'WA'), // Specify an array of countries or isocodes to be blocked.
  'ALLOWED_COUNTRIES' => array('Azeroth', 'AJ') // Specify an array of countries or isocodes to be allowed.
);

$result_array = \proxycheck\proxycheck::check($address, $proxycheck_options);
```

#### Blocking based on specific detection types ####
Below we've set specific detection types we're interested in to true. So for example proxies, vpn's, scraper bots, TOR and compromised addresses will trigger a ```block: true``` response from the API. But we've set ```HOSTING_DETECTION``` to false so if this IP address was only detected as a server host with no other detections, it will receive a ```block: false``` response from the library.

Also please note we set the ```ANONYMOUS_DETECTION``` option to false. We did this so that it wont superseed other more specific detection type options so for example if you only wanted to detect VPN's but not Proxies, you would need to set ```ANONYMOUS_DETECTION``` to false to make sure that will happen, otherwise the anonymous detection will take precedent and you would receive a ```block: true``` response.

```php
// Get your visitors IP address or email address
// If you're using CloudFlare change $_SERVER["REMOTE_ADDR"] to $_SERVER["HTTP_CF_CONNECTING_IP"]
// You may also supply an array of addresses in $address to check multiple addresses at once.
$address = $_SERVER["REMOTE_ADDR"];

// Input your options for this query including your optional API Key and query flags.
$proxycheck_options = array(
  'API_KEY' => '######-######-######-######', // Your API Key.
  'DAY_RESTRICTOR' => 7, // Restrict checking to proxies seen in the past # of days.
  'ANONYMOUS_DETECTION' => true, // Set to true to enable Anonymous detections
  'PROXY_DETECTION' => true, // Set to true to enable Proxy detections
  'VPN_DETECTION' => true, // Set to true to enable VPN detections
  'SCRAPER_DETECTION' => true, // Set to true to enable Scraper detections
  'TOR_DETECTION' => true, // Set to true to enable TOR detections
  'COMPROMISED_DETECTION' => true, // Set to true to enable Compromised Address detections
  'HOSTING_DETECTION' => false, // Set to true to enable Hosting detections
  'TLS_SECURITY' => false, // Enable or disable transport security (TLS).
  'QUERY_TAGGING' => true, // Enable or disable query tagging.
  'MASK_ADDRESS' => true, // Anonymises the local-part of an email address (e.g. anonymous@domain.tld)
  'CUSTOM_TAG' => '0', // Specify a custom query tag instead of the default (Domain+Page).
  'CUSTOM_TAG' => '', // Specify a custom query tag instead of the default (Domain+Page).
  'BLOCKED_COUNTRIES' => array('Wakanda', 'WA'), // Specify an array of countries or isocodes to be blocked.
  'ALLOWED_COUNTRIES' => array('Azeroth', 'AJ') // Specify an array of countries or isocodes to be allowed.
);

$result_array = \proxycheck\proxycheck::check($address, $proxycheck_options);
```

## The new API response ##
Like in previous versions of the library the entire response from proxycheck.io is made available to you when checking an address. However since this library is now using the v3 API instead of v2 you will need to provision your software to support the new response format. You can view an example of the new format below or access our full documentation on our website [`here`](https://proxycheck.io/api).

The key thing to note is we've switched to booleans (true/false) for all responses, keys that we don't have values for will have their values set to ```Unknown``` and much of the data is now setup in specific sections including ```network```, ```location```, ```detections```, ```device_estimate``` and ```operator```.

```
{
    "status": "ok",
    "185.59.221.75": {
        "network": {
            "asn": "AS60068",
            "range": "185.59.221.0/24",
            "hostname": "185.59.221.75.adsl.inet-telecom.org",
            "provider": "Datacamp Limited",
            "organisation": "CDN77 - London POP",
            "type": "Hosting"
        },
        "location": {
            "continent_name": "Europe",
            "continent_code": "EU",
            "country_name": "United Kingdom",
            "country_code": "GB",
            "region_name": "England",
            "region_code": "ENG",
            "city_name": "London",
            "postal_code": "W1B",
            "latitude": 51.5072,
            "longitude": -0.1276,
            "timezone": "Europe/Paris",
            "currency": {
                "code": "Pound",
                "name": "GBP",
                "symbol": "£"
            }
        },
        "device_estimate": {
            "address": 50,
            "subnet": 1890
        },
        "detections": {
            "proxy": false,
            "vpn": true,
            "compromised": true,
            "scraper": false,
            "tor": false,
            "hosting": true,
            "anonymous": true,
            "risk": 100
        },
        "operator": {
            "name": "IVPN",
            "url": "https://www.ivpn.net/",
            "anonymity": "high",
            "popularity": "medium",
            "protocols": [
                "WireGuard",
                "OpenVPN",
                "IPSec",
                "IKEv2"
            ],
            "policies": {
                "ad_filtering": true,
                "free_access": false,
                "paid_access": true,
                "port_forwarding": false,
                "logging": false,
                "anonymous_payments": true,
                "crypto_payments": true,
                "traceable_ownership": true
            }
        },
        "last_updated": 1757590444
    },
    "query_time": 5
}
```
