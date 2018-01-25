# madesimple/slim-auth
[![Build Status](https://travis-ci.org/pdscopes/slim-auth.svg?branch=master)](https://travis-ci.org/pdscopes/slim-auth)

An authentication and authorisation middleware for [Slim 3 framework](https://www.slimframework.com/).

## Authentication
A middleware to determine whether the request contains valid authentication token. The middleware has been designed so that it can easily be extended to:

* handle any type of token retrieval;
* handle any type of validation method; and,
* perform any set of actions if authentication was successful.

To use an Authentication middleware to your Slim application simply:
```php
// Add to all routes:
$app->add(new SimpleTokenAuthentication($app->getContainer(), $options));

// Add to a group of routes:
$app->group($pattern, function () {})
    ->add(new SimpleTokenAuthentication($app->getContainer(), $options));

// Add to a specific route:
$app->get($pattern, $callable)
    ->add(new SimpleTokenAuthentication($app->getContainer(), $options));
```

*Side node*: It is recommended that if you are going to be adding same authentication to more than more groups/routes to put the middleware in `dependencies.php`.


Default options for authentication are:
```php
[
    // boolean - whether to enforce an https connection
    'secure'      => true,
    // array - list of hostnames/IP addresses to ignore the secure flag
    'relaxed'     => ['localhost', '127.0.0.1'],
    // array - list of environment variables to check for the token (set to an empty array to skip)
    'environment' => ['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'],
    // string - the header to check for the token (set to false, null, or '' to skip)
    'header'      => 'X-Auth',
    // string - the regex to match the token ($match[$options['index']] is used as the token)
    'regex'       => '/(.*)/',
    // integer - the regex index to use as the token
    'index'       => 1,
    // string - the cookie to check for the token (set to false, null, or '' to skip)
    'cookie'      => 'X-Auth',
    // string - the identifier for the token in the payload
    'payload'     => null,
    // string - the name to store the token in the Slim container
    'attribute'   => 'token',
    // object - an instance of a Psr\LoggerInterface
    'logger'      => null,
]
```


When authentication fails the Slim container is checked for an `notAuthenticatedHandler`; if there is no such handler then an `NotAuthenticatedException` is thrown. An `notAuthenticatedHandler` should have the following signature:

```php
function (\Slim\Http\Request $request, \Slim\Http\Response $response) {
    // return $response->withStatus(401);
    // return $response->withRedirect('/path/to/sign-in/form');
    // return $response->withJson(['message' => 'Not Authenticated'], 401);
}
```

### SimpleTokenAuthentication
Simple token authentication is an implementation of Authentication which allows the user to provide a callable to validate a token. The callable is passed to Simple token authentication using the option:
```php
[
    // callable - function to validate the token [required]
    'validate' => null,
]
```

The callable should have the following signature:
```php
function ($token) {
    // return bool
}
```

### JwtAuthentication
JWT authentication is an implementation of Authentication which allows the user to use JWT as authentication tokens. JWT authentication overrides the default regex, and adds two extra options:
```php
[
    // string - Overrides the default regex
    'regex' => '/Bearer\s+(.*)$/i',

    // string - JWT secret [required]
    'secret' => '',
    // array - list of JWT algorithms [optional]
    'algorithm' => ['HS256', 'HS512', 'HS384'],

];
```


## Authorisation
A middleware to determine whether an authenticated request has authorisation to access the requested route.

When Authorisation fails the container is checked for an `'notAuthorisedHandler'`; if there is no such handler then an `NotAuthorisedException` exception is thrown.

_Note_: If you need to access the route from within your app middleware you must set '`determineRouteBeforeAppMiddleware`' to `true` in your configuration otherwise `getAttribute('route')` will return `null`. The route is always available in route middleware.