# madesimple/slim-auth
Authentication and authorisation middleware for Slim framework

## Authentication
A middleware to determine whether the request contains valid authenticated to access the requested route.
Default options for authentication are:
```php
[
    'secure'      => true,
    'relaxed'     => ['localhost', '127.0.0.1'],
    'environment' => ['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'],
    'header'      => 'X-Auth',
    'regex'       => '/(.*)/',
    'cookie'      => 'X-Auth',
    'attribute'   => 'token',
    'logger'      => null,
]
```

When authentication fails the container is checked for an `'notAuthenticatedHandler'`; if there is no such handler then an `NotAuthenticatedException` exception is thrown.

### SimpleTokenAuthentication
To add the simple token authenticator to your Slim app:
```php
$app->add(new SimpleTokenAuthentication($app->getContainer(), [
    // Required
    'validate' => function ($token) { return false; },
]));
```

### JwtAuthentication
To add the JWT authenticator to your Slim app:
```php
$app->add(new JwtAuthentication($app->getContainer(), [
    // Overrides
    'regex' => '/Bearer\s+(.*)$/i',

    // Required
    'secret' => '',
    // Optional (showing default values)
    'algorithm' => ['HS256', 'HS512', 'HS384'],

]));
```

### SimpleApiKeyAuthentication
To add the SimpleApiKeyAuthentication to your Slim app:
```php
$app->add(new SimpleApiKeyAuthentication($app->getContainer(), [
    // Optional (showing default values)
    'payload' => null,
    // Required
    'api_key' => '',
]));
```


## Authorisation
A middleware to determine whether an authenticated request has authorisation to access the requested route.

When Authorisation fails the container is checked for an `'notAuthorisedHandler'`; if there is no such handler then an `NotAuthorisedException` exception is thrown.

_Note_: If you need to access the route from within your app middleware you must set '`determineRouteBeforeAppMiddleware`' to `true` in your configuration otherwise `getAttribute('route')` will return `null`. The route is always available in route middleware.