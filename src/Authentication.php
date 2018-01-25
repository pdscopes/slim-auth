<?php

namespace Slim\Middleware;

use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Slim\Http\Request;
use Slim\Http\Response;

/**
 * Class Authentication
 *
 * @package MadeSimple\Slim\Middleware
 * @author
 */
abstract class Authentication
{
    /**
     * @var ContainerInterface
     */
    protected $ci;

    /**
     * @var array
     */
    protected $options = [
        'secure'      => true,
        'relaxed'     => ['localhost', '127.0.0.1'],
        'environment' => ['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'],
        'header'      => 'X-Auth',
        'regex'       => '/(.*)/',
        'index'       => 1,
        'cookie'      => 'X-Auth',
        'payload'     => null,
        'attribute'   => 'token',
        'logger'      => null,
    ];

    /**
     * Middleware constructor.
     *
     * @param ContainerInterface $ci
     * @param array              $options
     */
    public function __construct(ContainerInterface $ci, array $options)
    {
        $this->ci      = $ci;
        $this->options = $options + $this->options;
    }

    /**
     * Controls access to the current route based on the authentication sent with the request.
     * Blocks the request if the authentication token is not valid, otherwise
     * allows the request forward through this middleware.
     *
     * @param Request  $request
     * @param Response $response
     * @param \Closure $next
     *
     * @return mixed
     * @throws \Slim\Middleware\NotAuthenticatedException
     */
    public function __invoke(Request $request, Response $response, $next)
    {
        // Check security
        if (!$this->isSecure($request)) {
            return $this->unauthenticated($request, $response, $next);
        }

        // Fetch to token from the request and store in container
        $token = $this->fetchToken($request);
        $this->ci[$this->options['attribute']] = $token;

        // Validate the token
        if (!$token || $this->validate($token) !== true) {
            return $this->unauthenticated($request, $response, $next);
        }

        return $this->authenticated($request, $response, $next);
    }

    /**
     * Defines the behaviour of the authentication middleware when the request is unauthenticated.
     *
     * @param Request  $request
     * @param Response $response
     * @param callable $next
     *
     * @return Response
     * @throws \Slim\Middleware\NotAuthenticatedException
     */
    public function unauthenticated(Request $request, Response $response, callable $next)
    {
        if (!$this->ci->has('notAuthenticatedHandler')) {
            throw new NotAuthenticatedException('Not Authenticated', 401);
        }

        // Bind anonymous functions to the container
        $callable = $this->ci['notAuthenticatedHandler'];
        if ($callable instanceof \Closure) {
            $callable = $callable->bindTo($this->ci);
        }

        return $callable($request, $response);
    }

    /**
     * Defines the behaviour of the authentication middleware when the request is authenticated.
     *
     * @param Request  $request
     * @param Response $response
     * @param callable $next
     *
     * @return mixed
     */
    public function authenticated(Request $request, Response $response, callable $next)
    {
        $this->log(LogLevel::DEBUG, 'Request Authenticated', [
            'token' => $request->getAttribute($this->options['attribute'])
        ]);
        return $next($request, $response);
    }

    /**
     * Determine whether the request is secure.
     *
     * @param Request $request
     *
     * @return bool
     */
    public function isSecure(Request $request)
    {
        // No need if not set to be secure
        if ($this->options['secure'] === false) {
            return true;
        }
        // If this is a relaxed host
        if (in_array($request->getUri()->getHost(), $this->options['relaxed'])) {
            return true;
        }

        return $request->getUri()->getScheme() === 'https';
    }

    /**
     * Extract the authentication token from the request.
     *
     * @param Request $request
     *
     * @return mixed
     */
    public function fetchToken(Request $request)
    {
        $token = '';

        // If using PHP in CGI mode and non-standard environment
        foreach ((array) $this->options['environment'] as $environment) {
            if (($token = $request->getServerParam($environment, '')) !== '') {
                break;
            }
        }

        // Fall back on the header name from the options array
        if (empty($token) && !empty($this->options['header'])) {
            $headers = $request->getHeader($this->options['header']);
            $token   = $headers[0] ?? '';
        }

        // Fall back on the payload
        if (empty($token) && !empty($this->options['payload'])) {
            $token = $request->getParsedBodyParam($this->options['payload'], '');
        }

        // Finally fall back on cookie
        if (empty($token) && !empty($this->options['cookie'])) {
            $token = $request->getCookieParam($this->options['cookie'], '');
        }

        // Return the token
        if (!empty($token) && preg_match($this->options['regex'], $token, $matches)) {
            return $matches[$this->options['index']];
        } else {
            return '';
        }
    }

    /**
     * @see LogLevel
     * @param string $level
     * @param string $message
     * @param array  $context
     */
    protected function log($level, $message, array $context = [])
    {
        if ($this->options['logger'] && $this->options['logger'] instanceof LoggerInterface) {
            $this->options['logger']->log($level, $message, $context);
        }
    }

    /**
     * Checks the validity of the the given token and MUST return the result.
     *
     * This method MAY also take the opportunity to store information regarding the
     * entity requesting authentication in the container, e.g. a User object.
     *
     * @param mixed $token
     *
     * @return bool True if the token is valid, false otherwise
     */
    public abstract function validate($token);
}