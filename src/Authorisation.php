<?php

namespace Slim\Middleware;

use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LogLevel;
use Slim\Exception\HttpForbiddenException;

abstract class Authorisation implements MiddlewareInterface
{
    /**
     * @var ContainerInterface
     */
    protected $ci;

    /**
     * Middleware constructor.
     *
     * @param ContainerInterface $ci
     */
    public function __construct(ContainerInterface $ci)
    {
        $this->ci = $ci;
    }

    /**
     * Process the request by calling `self::process`.
     *
     * @see Authorisation::process()
     * @param ServerRequestInterface  $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     * @throws HttpForbiddenException
     */
    public function __invoke(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        return $this->process($request, $handler);
    }

    /**
     * Controls access to the current route based on the authorisation rules of the current route.
     * Blocks the request if the authorisation rules are meet, otherwise
     * allows the request forward through this middleware.
     *
     * @param ServerRequestInterface  $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     * @throws HttpForbiddenException
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Determine authorisation
        if (!$this->hasAuthorisation($request)) {
            $this->log(LogLevel::DEBUG, 'Request does not have authorisation');
            return $this->unauthorised($request);
        }

        return $this->authorised($request, $handler);
    }

    /**
     * Defines the behaviour of the authorisation middleware when the request is unauthorised.
     *
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     * @throws HttpForbiddenException
     */
    public function unauthorised(ServerRequestInterface $request): ResponseInterface
    {
        throw new HttpForbiddenException($request);
    }

    /**
     * Defines the behaviour of the authorisation middleware when the request is authorised.
     *
     * @param ServerRequestInterface  $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     */
    public function authorised(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        return $handler->handle($request);
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
     * Determine whether the authenticated request has permissions to access this
     * request with the specified rules.
     *
     * @param ServerRequestInterface $request
     * @return bool
     */
    protected abstract function hasAuthorisation(ServerRequestInterface $request): bool;
}
