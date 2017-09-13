<?php

namespace Slim\Middleware\Authentication;

use Firebase\JWT\JWT;
use Psr\Container\ContainerInterface;
use Psr\Log\LogLevel;
use Slim\Http\Request;
use Slim\Middleware\Authentication;

class JwtAuthentication extends Authentication
{
    public function __construct(ContainerInterface $ci, array $options = [])
    {
        parent::__construct($ci, $options);
        $this->options += [
            'regex'     => '/Bearer\s+(.*)$/i',
            'secret'    => '',
            'algorithm' =>  ['HS256', 'HS512', 'HS384'],
        ];
    }

    protected function fetchToken(Request $request)
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

    protected  function validate($token)
    {
        return is_array($token);
    }
}