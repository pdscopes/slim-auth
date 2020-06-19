<?php

namespace Slim\Middleware\Authentication;

use Firebase\JWT\JWT;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LogLevel;
use Slim\Middleware\Authentication;

class JwtAuthentication extends Authentication
{
    /**
     * @var object
     */
    protected $decoded;

    /**
     * JwtAuthentication constructor.
     *
     * @param ContainerInterface $ci
     * @param array $options
     */
    public function __construct(ContainerInterface $ci, array $options)
    {
        parent::__construct($ci, $options + [
            'header'    => 'Authorization',
            'regex'     => '/(Bearer\s+)?(.*)$/i',
            'index'     => 2,
            'secret'    => '',
            'algorithm' => ['HS256', 'HS512', 'HS384'],
        ]);
    }

    public function validate($token): bool
    {
        try {
            // Attempt to decode the token
            $token = JWT::decode($token, $this->options['secret'], (array) $this->options['algorithm']);
            // Store the decoded token if successful
            $this->decoded = $token;
            return true;
        } catch (\Exception $exception) {
            $this->log(LogLevel::WARNING, $exception->getMessage(), ['token' => $token]);
            return false;
        }
    }

    public function authenticated(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Override the token stored in the request attributes
        $request = $request->withAttribute($this->options['attribute'], $this->decoded);
        return parent::authenticated($request, $handler);
    }
}
