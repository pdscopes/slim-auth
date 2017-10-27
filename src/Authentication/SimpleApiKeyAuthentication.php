<?php

namespace Slim\Middleware\Authentication;

use Psr\Container\ContainerInterface;
use Slim\Http\Request;
use Slim\Middleware\Authentication;

class SimpleApiKeyAuthentication extends Authentication
{
    /**
     * SimpleApiKeyAuthentication constructor.
     *
     * @param \Psr\Container\ContainerInterface $ci
     * @param array                             $options
     */
    public function __construct(ContainerInterface $ci, array $options)
    {
        parent::__construct($ci, $options);
        $this->options += ['api_key' => null];
        $this->options += ['payload' => null];
    }

    /**
     * @InheritDoc
     */
    public function fetchToken(Request $request)
    {
        $token = parent::fetchToken($request);
        if (!empty($token)) {
            return $token;
        }

        // If allowed fall back on payload value
        return $this->options['payload']
            ? $request->getParsedBodyParam($this->options['payload'], '')
            : '';
    }

    /**
     * @InheritDoc
     */
    public function validate($token)
    {
        return $this->options['api_key'] === $token;
    }
}