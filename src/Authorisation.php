<?php

namespace Slim\Middleware;

use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Slim\Http\Request;
use Slim\Http\Response;

abstract class Authorisation
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
     * Controls access to the current route based on the authorisation rules of the current route.
     * Blocks the request if the authorisation rules are meet, otherwise
     * allows the request forward through this middleware.
     *
     * @param Request  $request
     * @param Response $response
     * @param \Closure $next
     *
     * @return mixed
     * @throws \Slim\Middleware\NotAuthorisedException
     */
    public function __invoke(Request $request, Response $response, $next)
    {
        // Determine authorisation
        if (!$this->hasAuthorisation($request)) {
            $this->log(LogLevel::DEBUG, 'Request does not have authorisation');
            return $this->unauthorised($request, $response, $next);
        }

        return $this->authorised($request, $response, $next);
    }

    /**
     * Defines the behaviour of the authorisation middleware when the request is unauthorised.
     *
     * @param Request  $request
     * @param Response $response
     * @param callable $next
     *
     * @throws NotAuthorisedException
     * @return Response
     */
    protected function unauthorised(Request $request, Response $response, callable $next)
    {
        if (!$this->ci->has('notAuthorisedHandler')) {
            throw new NotAuthorisedException('Not Authorised', 403);
        }
        return $this->ci['notAuthorisedHandler']($request, $response);
    }

    /**
     * Defines the behaviour of the authorisation middleware when the request is authorised.
     *
     * @param Request  $request
     * @param Response $response
     * @param callable $next
     *
     * @return mixed
     */
    protected function authorised(Request $request, Response $response, callable $next)
    {
        return $next($request, $response);
    }

    /**
     * @see LogLevel
     * @param string $level
     * @param string $message
     * @param array  $context
     */
    protected function log($level, $message, array $context = [])
    {
        if ($this->ci['logger'] && $this->ci['logger'] instanceof LoggerInterface) {
            $this->ci['logger']->log($level, $message, $context);
        }
    }

    /**
     * Determine whether the authenticated request has permissions to access this
     * request with the specified rules.
     *
     * @param Request $request
     * @return bool
     */
    protected abstract function hasAuthorisation(Request $request);
}