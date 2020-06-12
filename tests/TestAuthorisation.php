<?php

namespace MadeSimple\Slim\Middleware\Tests;

use Psr\Container\ContainerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Middleware\Authorisation;

class TestAuthorisation extends Authorisation
{
    /**
     * @var bool
     */
    private $validate;

    public function __construct(ContainerInterface $ci, bool $validate)
    {
        parent::__construct($ci);
        $this->validate = $validate;
    }

    /**
     * @inheritDoc
     */
    protected function hasAuthorisation(ServerRequestInterface $request): bool
    {
        return $this->validate;
    }
}