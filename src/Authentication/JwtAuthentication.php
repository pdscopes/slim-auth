<?php

namespace Slim\Middleware\Authentication;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LogLevel;
use Slim\Middleware\Authentication;

class JwtAuthentication extends Authentication
{
    protected object $decoded;

    /**
     * JwtAuthentication constructor.
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

    public function validate(mixed $token): bool
    {
        try {
            // Attempt to decode the token
            $keys = array_reduce($this->options['algorithm'], function (array $arr, string $alg) {
                return array_merge([$alg => new Key($this->options['secret'], $alg)], $arr);
            }, []);
            $token = JWT::decode($token, $keys);
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
