<?php

namespace Slim\Middleware\Authentication;

use Psr\Container\ContainerInterface;
use Slim\Middleware\Authentication;

class SimpleTokenAuthentication extends Authentication
{
    /**
     * SimpleTokenAuthentication constructor.
     *
     * @param \Psr\Container\ContainerInterface $ci
     * @param array                             $options
     */
    public function __construct(ContainerInterface $ci, array $options)
    {
        parent::__construct($ci, $options);
        $this->options += ['validate' => null];
    }

    /**
     * @InheritDoc
     */
    public function validate($token)
    {
        if (!is_callable($this->options['validate'])) {
            return false;
        }

        return $this->options['validate']($token);
    }
}