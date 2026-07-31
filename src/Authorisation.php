<?php

namespace Slim\Middleware;

use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Slim\Exception\HttpForbiddenException;

abstract class Authorisation implements MiddlewareInterface
{
    protected ?LoggerInterface $logger;

    /**
     * Middleware constructor.
     */
    public function __construct(ContainerInterface $ci)
    {
        if ($ci->has('logger')) {
            $this->logger = $ci->get('logger');
        } elseif ($ci->has(LoggerInterface::class)) {
            $this->logger = $ci->get(LoggerInterface::class);
        } else {
            $this->logger = null;
        }
    }

    /**
     * Process the request by calling `self::process`.
     *
     * @see Authorisation::process()
     * @throws HttpForbiddenException
     */
    public function __invoke(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        return $this->process($request, $handler);
    }

    /**
     * Controls access to the current route based on the authorisation rules of the current route.
     * Blocks the request if the authorisation rules are met, otherwise
     * allows the request forward through this middleware.
     *
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
     * @throws HttpForbiddenException
     */
    public function unauthorised(ServerRequestInterface $request): ResponseInterface
    {
        throw new HttpForbiddenException($request);
    }

    /**
     * Defines the behaviour of the authorisation middleware when the request is authorised.
     */
    public function authorised(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        return $handler->handle($request);
    }

    /**
     * @see LogLevel
     */
    protected function log(string $level, string $message, array $context = []): void
    {
        $this->logger?->log($level, $message, $context);
    }

    /**
     * Determine whether the authenticated request has permissions to access this
     * request with the specified rules.
     */
    abstract protected function hasAuthorisation(ServerRequestInterface $request): bool;
}
