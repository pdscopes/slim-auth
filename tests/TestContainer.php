<?php

namespace MadeSimple\Slim\Middleware\Tests;

class TestContainer implements \Psr\Container\ContainerInterface
{
    private array $data;

    /**
     * TestContainer constructor.
     *
     * @param array|null $data
     */
    public function __construct(?array $data = null)
    {
        $this->data = $data ?? [];
    }

    #[\Override]
    public function get(string $id): mixed
    {
        if (!isset($this->data[$id])) {
            throw new TestNotFoundException("{$id} not found in container");
        }
        return $this->data[$id];
    }

    #[\Override]
    public function has(string $id): bool
    {
        return isset($this->data[$id]);
    }

    public function set(string|int $id, mixed $val): void
    {
        $this->data[$id] = $val;
    }
}
