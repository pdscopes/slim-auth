<?php

namespace Slim\Middleware\Authentication;

use Firebase\JWT\JWT;
use Psr\Container\ContainerInterface;
use Psr\Log\LogLevel;
use Slim\Http\Request;
use Slim\Middleware\Authentication;

class JwtAuthentication extends Authentication
{
    /**
     * JwtAuthentication constructor.
     *
     * @param \Psr\Container\ContainerInterface $ci
     * @param array                             $options
     */
    public function __construct(ContainerInterface $ci, array $options)
    {
        parent::__construct($ci, $options + [
            'header'    => 'Authorization',
            'regex'     => '/Bearer\s+(.*)$/i',
            'secret'    => '',
            'algorithm' => ['HS256', 'HS512', 'HS384'],
        ]);
    }

    /**
     * @InheritDoc
     */
    public function fetchToken(Request $request)
    {
        $token = parent::fetchToken($request);
        if (empty($token)) {
            return $token;
        }

        try {
            return JWT::decode($token, $this->options['secret'], (array) $this->options['algorithm']);
        } catch (\Exception $exception) {
            $this->log(LogLevel::WARNING, $exception->getMessage(), ['token' => $token]);
            return '';
        }
    }

    /**
     * @InheritDoc
     */
    public function validate($token)
    {
        return is_object($token);
    }
}