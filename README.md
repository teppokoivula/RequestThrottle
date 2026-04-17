Request Throttle ProcessWire module
------------------------------------

Request Throttle is a ProcessWire module for throttling requests to named resources based on timestamps and client fingerprints. It can be used to implement rate limiting for things like login attempts, form submissions, password resets, etc.

## Getting started

1. Download or clone this module into your `/site/modules/` directory, or install using Composer (`composer require teppokoivula/request-throttle`).
2. Install the module from the ProcessWire Admin (Modules > Site > Request Throttle).
3. Configure default values for max requests, time window, and fingerprint mode via module settings, or override them per call.

## Usage

```php
// Check if a request is allowed (increments the counter automatically)
$throttle = $modules->get('RequestThrottle');
if (!$throttle->request('login')) {
    // too many requests, deny access
}

// Check without incrementing the counter
if (!$throttle->requestQuietly('login')) {
    // would be throttled
}

// Override defaults per call
$throttle->request('password_reset', 3, 10); // max 3 requests in 10 minutes
```

## License

This project is licensed under the MIT License.
