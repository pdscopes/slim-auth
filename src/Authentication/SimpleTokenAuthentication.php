<?php

namespace Slim\Middleware\Authentication;

use Psr\Container\ContainerInterface;
use Slim\Middleware\Authentication;

class SimpleTokenAuthentication extends Authentication
{
    protected ContainerInterface $ci;

    /**
     * SimpleTokenAuthentication constructor.
     *
     * @param ContainerInterface $ci
     * @param array $options
     */
    public function __construct(ContainerInterface $ci, array $options)
    {
        parent::__construct($ci, $options + [
            'validate' => null,
        ]);
        $this->ci = $ci;
    }

    public function validate(mixed $token): bool
    {
        if (!is_callable($this->options['validate'])) {
            return false;
        }

        // Bind anonymous functions to the container
        $callable = $this->options['validate'];
        if ($callable instanceof \Closure) {
            $callable = $callable->bindTo($this->ci);
        }

        return $callable($token);
    }
}
