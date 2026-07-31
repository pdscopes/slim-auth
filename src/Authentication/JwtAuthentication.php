<?php

namespace Slim\Middleware\Authentication;

use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LogLevel;
use Slim\Middleware\Authentication;

abstract class JwtAuthentication extends Authentication
{
    protected object $decoded;

    /**
     * JwtAuthentication constructor.
     */
    public function __construct(ContainerInterface $ci, array $options)
    {
        parent::__construct($ci, $options + [
                'header'    => 'Authorization',
                'regex'     => '/(Bearer\s+)?(.*)$/i',
                'index'     => 2,
                'secret'    => '',
                'algorithm' => ['HS256'],
            ]);
        if (empty($this->options['algorithm'])) {
            throw new \InvalidArgumentException('At least one algorithm is required.');
        }
    }

    #[\Override]
    public function authenticated(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Override the token stored in the request attributes
        $request = $request->withAttribute($this->options['attribute'], $this->decoded);
        return parent::authenticated($request, $handler);
    }

    /**
     * Checks the validity of the given token and MUST return the result.
     */
    #[\Override]
    public function validate(mixed $token): bool
    {
        try {
            $this->decoded = $this->decode($token);
            return true;
        } catch (\Exception $exception) {
            $this->log(LogLevel::WARNING, $exception->getMessage(), ['token' => $token]);
            return false;
        }
    }

    /**
     * Given a token, this
     * @throws \InvalidArgumentException If unable to decode the given $token
     */
    abstract protected function decode(mixed $token): object;
}
