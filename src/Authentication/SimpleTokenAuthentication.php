<?php

namespace Slim\Middleware\Authentication;

use Slim\Middleware\Authentication;

class SimpleTokenAuthentication extends Authentication
{
    public function __construct(array $options)
    {
        parent::__construct($options);
        $this->options += ['validate' => null];
    }

    protected  function validate($token)
    {
        if (!is_callable($this->options['validate'])) {
            return false;
        }

        return $this->options['validate']($token);
    }
}