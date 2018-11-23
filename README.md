# proxycheck-php
php library for calling the [proxycheck.io](https://proxycheck.io/) v2 API which allows you to check if an IP Address is a Proxy or VPN and get the Country, ASN and Provider for the IP Address being checked.

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
    [node] => answering_node_name
    [###.###.###.###] => Array
        (
            [asn] => AS#####
            [provider] => Acme Incorperated
            [country] => Wakanda
            [isocode] => WA
            [proxy] => yes/no
            [type] => VPN/SOCKS5/SOCKS4/SOCKS/HTTP/HTTPS/Inference Engine/Compromised Server
            [port] => #####
            [last seen human] => 6 hours, 18 minutes, 49 seconds ago
            [last seen unix] => 1528687645
        )
    [block] => yes/no
    [block_reason] => proxy/vpn/country
)
```

In the above example the ```status``` field lets you know the status of this query. You can view all our API responses [here](https://proxycheck.io/api/) within our API documentation page. Also where in our example we show ```###.###.###.###``` you will receive the actual IP Address you sent to the API for checking.

## Manipulating your Whitelist/Blacklist ##

In version 0.1.2 (Nov 2018) we added the ability to view, add, remove, set and clear your whitelist and blacklist through this library. Below is an example of adding three entries to your whitelist in a single query.

```php
$proxycheck_options = array(
  'API_KEY' => '', // Your API Key.
  'TLS_SECURITY' => 0, // Enable or disable transport security (TLS).
  'LIST_SELECTION' => 'whitelist', // Specify the list you're accessing: whitelist or blacklist
  'LIST_ACTION' => 'add', // Specify an action: list, add, remove, set or clear.
  'LIST_ENTRIES' => array('8.8.8.8', '1.1.1.1/24', 'AS888') // Addresses, Ranges or ASN's to be added, removed or set
);
    
$result_array = \proxycheck\proxycheck::listing($proxycheck_options);
```

When accessing dashboard API's an API Key is always required as the dashboard is only for registered users (both free and paid have full dashboard access). You will also need to make sure you have Dashboard API access enabled [within your dashboard](https://proxycheck.io/dashboard/) on our website.

You can see that in the LIST_ENTRIES field we are providing an array of three seperate entries, this field is only used if you're performing an add, remove or set action. When providing entries in the LIST_ENTRIES field you can include comments, for example ```'LIST_ENTRIES' => array('8.8.8.8 #this is google')``` would create a new entry with the comment intact.

If an entry you're removing has a comment next to it you will need to include that comment in the removal request aswell, like in the example above where we included a comment next to the IP Address we were adding you would do the same when removing it.
