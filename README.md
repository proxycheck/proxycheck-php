# proxycheck-php
php library for calling the proxycheck.io v2 API.

## Install via Composer ##

You can install the library via [Composer](http://getcomposer.org/) by running the following command:

```bash
composer require proxycheck/proxycheck-php
```
To use the library, use Composer's [autoload](https://getcomposer.org/doc/01-basic-usage.md#autoloading):

```php
require_once('vendor/autoload.php');
```

## Dependencies ##

The library requires the following extensions in order to work properly:

- [`curl`](https://secure.php.net/manual/en/book.curl.php) (Please make sure your cacert.pem is up to date if you intend to use TLS querying)
- [`json`](https://secure.php.net/manual/en/book.json.php)

## Service Limits ##

* Free users without an API Key = 100 Daily Queries
* Free users with an API Key = 1,000 Daily Queries
* Paid users with an API Key = 10,000 to 10.24 Million+ Daily Queries

Get your API Key at [proxycheck.io](http://proxycheck.io/) it's free.

## Getting Started ##

Performing a check on an IP Address (IPv4 and IPv6 supported).

```php
  // Get your visitors IP Address
  // If you're using CloudFlare change $_SERVER["REMOTE_ADDR"] to $_SERVER["HTTP_CF_CONNECTING_IP"]
  $ip = $_SERVER["REMOTE_ADDR"];

  // Input your options for this query including your optional API Key and query flags.
  $proxycheck_options = array(
    'API_KEY' => '######-######-######-######', // Your API Key.
    'ASN_DATA' => 1, // Enable ASN data response.
    'DAY_RESTRICTOR' => 7, // Restrict checking to proxies seen in the past # of days.
    'VPN_DETECTION' => 1, // Check for both VPN's and Proxies instead of just Proxies.
    'INF_ENGINE' => 1, // Enable or disable the real-time inference engine.
    'TLS_SECURITY' => 0, // Enable or disable transport security (TLS).
    'QUERY_TAGGING' => 1, // Enable or disable query tagging.
    'CUSTOM_TAG' => '', // Specify a custom query tag instead of the default (Domain+Page).
    'BLOCKED_COUNTRIES' => array('Wakanda', 'Mordor') // Specify an array of countries to be blocked.
  );
  
  $result_array = \proxycheck\proxycheck::check($ip, $proxycheck_options);
```

## Viewing the query result ##

When performing a query you will receive back an array which contains various information. Below is an example of parsing that array to determine if this user should be blocked or not.

```php
  if ( $result_array['block'] == "yes" ) {
    
    // Example of a block and the reason why.
    echo "Blocked, reason: " . $result_array['block_reason'];
    exit;

  } else {
    
    // No Proxy / VPN / Blocked Country detected.
    echo "Not blocked.";
    
  }
```

## Extra information included in the query result ##

When performing a query you will receive not just ```block: yes/no``` and ```block_reason: [reason]``` but also the entirety of the API response from proxycheck.io, we do this so you can either make an easy block system or utilise the data presented by the API as you see fit. A full result example is shown below.

```php
Array
(
    [status] => ok/warning/denied/error
    [###.###.###.###] => Array
        (
            [asn] => AS#####
            [provider] => Acme Incorperated
            [country] => Wakanda
            [proxy] => yes/no
            [type] => VPN/SOCKS5/SOCKS4/SOCKS/HTTP/HTTPS/Inference Engine/Compromised Server
        )
    [block] => yes/no
    [block_reason] => proxy/vpn/country
)
```

In the above example the ```status``` field lets you know the status of this query. You can view all our API responses [here](https://proxycheck.io/api/) within our API documentation page. Also where in our example we show ```###.###.###.###``` you will receive the actual IP Address you sent to the API for checking.

