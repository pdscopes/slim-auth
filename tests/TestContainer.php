<?php

namespace MadeSimple\Slim\Middleware\Tests;

use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;

class TestContainer implements \Psr\Container\ContainerInterface
{
    /**
     * @var array
     */
    private $data;

    /**
     * TestContainer constructor.
     *
     * @param array|null $data
     */
    public function __construct(array $data = null)
    {
        $this->data = $data ?? [];
    }

    /**
     * @inheritDoc
     */
    public function get($id)
    {
        if (!isset($this->data[$id])) {
            throw new TestNotFoundException("{$id} not found in container");
        }
        return $this->data[$id];
    }

    /**
     * @inheritDoc
     */
    public function has($id)
    {
        return isset($this->data[$id]);
    }

    /**
     * @param $id
     * @param $val
     */
    public function set($id, $val)
    {
        $this->data[$id] = $val;
    }
}