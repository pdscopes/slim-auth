<?php

namespace Slim\Middleware;

use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LogLevel;
use Slim\Exception\HttpUnauthorizedException;

/**
 * Class Authentication
 *
 * @package MadeSimple\Slim\Middleware
 * @author
 */
abstract class Authentication implements MiddlewareInterface
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
     * @param array $options
     */
    public function __construct(ContainerInterface $ci, array $options)
    {
        $this->ci      = $ci;
        $this->options = $options + $this->options;
    }

    /**
     * Process the request by calling `self::process`.
     *
     * @see Authentication::process()
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     * @throws HttpUnauthorizedException
     */
    public function __invoke(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        return $this->process($request, $handler);
    }

    /**
     * Controls access to the current route based on the authentication sent with the request.
     * Blocks the request if the authentication token is not valid, otherwise
     * allows the request forward through this middleware.
     *
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     * @throws HttpUnauthorizedException
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Check security
        if (!$this->isSecure($request)) {
            return $this->unauthenticated($request, $handler);
        }

        // Fetch to token from the request and store in container
        $token = $this->fetchToken($request);
        $this->ci->set($this->options['attribute'], $token);
        $request = $request->withAttribute($this->options['attribute'], $token);

        // Validate the token
        if (!$token || $this->validate($token) !== true) {
            return $this->unauthenticated($request, $handler);
        }

        return $this->authenticated($request, $handler);
    }

    /**
     * Defines the behaviour of the authentication middleware when the request is unauthenticated.
     *
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     * @throws HttpUnauthorizedException
     */
    public function unauthenticated(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!$this->ci->has('notAuthenticatedHandler')) {
            throw new HttpUnauthorizedException($request);
        }

        // Bind anonymous functions to the container
        $callable = $this->ci->get('notAuthenticatedHandler');
        if ($callable instanceof \Closure) {
            $callable = $callable->bindTo($this->ci);
        }

        return $callable($request, $handler);
    }

    /**
     * Defines the behaviour of the authentication middleware when the request is authenticated.
     *
     * @param ServerRequestInterface  $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     */
    public function authenticated(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $this->log(LogLevel::DEBUG, 'Request Authenticated', [
            'token' => $request->getAttribute($this->options['attribute'])
        ]);
        return $handler->handle($request);
    }

    /**
     * Determine whether the request is secure.
     *
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function isSecure(ServerRequestInterface $request): bool
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
     * @param ServerRequestInterface $request
     * @return mixed
     */
    public function fetchToken(ServerRequestInterface $request)
    {
        $token = '';

        // If using PHP in CGI mode and non-standard environment
        foreach ((array) $this->options['environment'] as $environment) {
            if (($token = $request->getServerParams()[$environment] ?? '') !== '') {
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
            $postParams = $request->getParsedBody();
            if (is_array($postParams)) {
                $token = $postParams[$this->options['payload']] ?? '';
            } elseif (is_object($postParams)) {
                $token = $postParams->{$this->options['payload']} ?? '';
            }
        }

        // Finally fall back on cookie
        if (empty($token) && !empty($this->options['cookie'])) {
            $token = $request->getCookieParams()[$this->options['cookie']] ?? '';
        }

        // Return the token
        if (!empty($token) && preg_match($this->options['regex'], $token, $matches)) {
            return $matches[$this->options['index']];
        } else {
            return '';
        }
    }

    /**
     * Get a specific Authentication middleware option.
     *
     * @param string $opt
     * @param mixed|null $default
     * @return mixed|null
     */
    public function getOption(string $opt, $default = null)
    {
        return $this->options[$opt] ?? $default;
    }

    /**
     * Get the Authentication middleware options.
     *
     * @return array
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * @see LogLevel
     * @param string $level
     * @param string $message
     * @param array  $context
     */
    protected function log($level, $message, array $context = []): void
    {
        if ($this->ci->has('logger')) {
            $this->ci->get('logger')->log($level, $message, $context);
        }
    }

    /**
     * Checks the validity of the the given token and MUST return the result.
     *
     * This method MAY also take the opportunity to store information regarding the
     * entity requesting authentication in the container, e.g. a User object.
     *
     * @param mixed $token
     * @return bool True if the token is valid, false otherwise
     */
    public abstract function validate($token): bool;
}
