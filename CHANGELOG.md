CHANGELOG
=========

0.2.2 (January 4th 2023)
------------------

* Improved the reliability of sending addresses to the API by always using the POST method
  This now applies to sending a singular address in addition to multiple addresses.
  

0.2.1 (October 28th 2022)
------------------

* Corrected an exception when checking an IP which doesn't have Country data available.
  

0.2.0 (February 18th 2022)
------------------

* Added full support for checking email addresses in addition to ip addresses.
  

0.1.9 (December 9th 2021)
------------------

* Added support for checking multiple addresses in a single request by passsing an
  array as the $ip variable instead of a string.
  

0.1.8 (November 12th 2021)
------------------

* Moves around the required and optional parameters for our makeRequest() function
  to support PHP8+ which has deprecated our previous implementation.
  

0.1.7 (December 29th 2020)
------------------

* Corrected an issue where custom tags wouldn't be sent with requests.
  This bug was introduced by the 0.1.6 release.
  

0.1.6 (December 9th 2020)
------------------

* Updated code formatting to meet PSR-12 specifications.
* Improved the cURL implementation with GET/POST method arguments.
* Corrected an issue where omitting the DAY_RESTRICTOR within your options
  array would cause your API Key to not be sent with your requests.
  

0.1.5 (June 27th 2019)
------------------

* Added better protection against absent parameters in array options.
  

0.1.4 (June 25th 2019)
------------------

* Added a new query flag: risk which lets you view both risk scores
  and attack history for IP Addresses.


0.1.3 (May 18th 2019)
------------------

* Added a new function called stats which allows you to view the stats
  from your dashboard using our official dashboard API's
* Updated the check function to support a new option array called
  ALLOWED_COUNTRIES so you can do local country based whitelisting.
* Updated the COUNTRIES feature to allow isocodes to be used in addition
  to country names.
* Improved the classes handling of errors when options were not supplied
  in the options array.


0.1.2 (November 23rd 2018)
------------------

* Added a new function called listing which allows you to view and modify
  your whitelist and blacklist using our official dashboard API.


0.1.1 (June 11th 2018)
------------------

* Added Last Seen, Port and Node flags to the query library.
* Updated README.md with new description of the library and altered the 
  example result array to include new flag responses.
* Updated composer.json changing "type" from project to library.


0.1.0 (June 9th 2018)
------------------

* Initial release.
