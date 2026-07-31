<?php

namespace Slim\Middleware;

use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Slim\Exception\HttpUnauthorizedException;

abstract class Authentication implements MiddlewareInterface
{
    protected ?LoggerInterface $logger;
    protected array $options = [
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
        'queryparam'  => null,
    ];

    /**
     * Middleware constructor.
     */
    public function __construct(ContainerInterface $ci, array $options)
    {
        if ($ci->has('logger')) {
            $this->logger = $ci->get('logger');
        } elseif ($ci->has(LoggerInterface::class)) {
            $this->logger = $ci->get(LoggerInterface::class);
        } else {
            $this->logger = null;
        }
        $this->options = $options + $this->options;
    }

    /**
     * Process the request by calling `self::process`.
     *
     * @see Authentication::process()
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
     * @throws HttpUnauthorizedException
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Check security
        if (!$this->isSecure($request)) {
            return $this->unauthenticated($request);
        }

        // Fetch to token from the request and store as a request attribute
        $token = $this->fetchToken($request);
        $request = $request->withAttribute($this->options['attribute'], $token);

        // Validate the token
        if (!$token || $this->validate($token) !== true) {
            return $this->unauthenticated($request);
        }

        return $this->authenticated($request, $handler);
    }

    /**
     * Defines the behaviour of the authentication middleware when the request is unauthenticated.
     *
     * @throws HttpUnauthorizedException
     */
    public function unauthenticated(ServerRequestInterface $request): ResponseInterface
    {
        throw new HttpUnauthorizedException($request);
    }

    /**
     * Defines the behaviour of the authentication middleware when the request is authenticated.
     *
     * This method MAY also take the opportunity to store information regarding the
     * entity requesting authentication in the request, e.g. a User object.
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
     */
    public function fetchToken(ServerRequestInterface $request): string
    {
        $token = '';

        // If using PHP in CGI mode and non-standard environment
        foreach ((array) $this->options['environment'] as $environment) {
            if (($token = $request->getServerParams()[$environment] ?? '') !== '') {
                break;
            }
        }

        // Fall back on the header name from the "options" array
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

        // Finally, fall back on cookie
        if (empty($token) && !empty($this->options['cookie'])) {
            $token = $request->getCookieParams()[$this->options['cookie']] ?? '';
        }

        if (empty($token) && !empty($this->options['queryparam'])) {
            $token = $request->getQueryParams()[$this->options['queryparam']] ?? '';
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
     */
    public function getOption(string $opt, mixed $default = null): mixed
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
     */
    protected function log(string $level, string $message, array $context = []): void
    {
        $this->logger?->log($level, $message, $context);
    }

    /**
     * Checks the validity of the given token and MUST return the result.
     */
    abstract public function validate(mixed $token): bool;
}
