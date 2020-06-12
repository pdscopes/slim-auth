<?php

namespace Slim\Middleware\Authentication;

use Firebase\JWT\JWT;
use Psr\Container\ContainerInterface;
use Psr\Log\LogLevel;
use Slim\Middleware\Authentication;

class JwtAuthentication extends Authentication
{
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
            // Override the stored token if successful
            $this->ci->set($this->options['attribute'], $token);
            return true;
        } catch (\Exception $exception) {
            $this->log(LogLevel::WARNING, $exception->getMessage(), ['token' => $token]);
            return false;
        }
    }
}
