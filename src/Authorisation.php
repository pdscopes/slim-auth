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
     */
    public function __invoke(Request $request, Response $response, $next)
    {
        $rules = $this->fetchRules($request);

        // Determine authorisation
        if (!$this->hasAuthorisation($request, $rules)) {
            $this->log(LogLevel::DEBUG, 'Request does not have authorisation', ['rules' => $rules]);
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
     * @return Response
     */
    protected function unauthorised(Request $request, Response $response, callable $next)
    {
        return $response->withStatus(403);
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
     * @param Request $request
     * @return array
     */
    protected function fetchRules(Request $request)
    {
        if ($request->getAttribute('route') === null) {
            return [];
        }

        $rules = $request->getAttribute('route')->getArgument('auth', []);
        if (!is_array($rules)) {
            $rules = explode(',', $rules);
        }

        return $rules;
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
     * @param array $rules
     * @return bool
     */
    protected abstract function hasAuthorisation(Request $request, array $rules);


}