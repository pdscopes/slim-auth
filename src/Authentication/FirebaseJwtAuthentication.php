<?php

namespace Slim\Middleware\Authentication;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Psr\Container\ContainerInterface;

class FirebaseJwtAuthentication extends JwtAuthentication
{
    public function __construct(ContainerInterface $ci, array $options)
    {
        parent::__construct($ci, $options);
        if (
            is_array($this->options['secret']) &&
            count($this->options['secret']) !== count($this->options['algorithm']) &&
            array_keys($this->options['secret']) !== array_keys($this->options['algorithm'])
        ) {
            throw new \InvalidArgumentException('Secret have the same keys as algorithm');
        }
    }

    #[\Override]
    protected function decode(mixed $token): object
    {
        $secret = $this->options['secret'];
        $algorithm = $this->options['algorithm'];
        try {
            // If there is a single secret and algorithm, use simplified decode
            if ((!is_array($secret) || count($secret) === 1) && count($algorithm) === 1) {
                $secret = is_array($secret) ? reset($secret) : $secret;
                return JWT::decode($token, new Key($secret, reset($algorithm)));
            }

            // Otherwise, build an associative array of keys with each algorithm
            return JWT::decode($token, $this->buildKeyArray($secret, $algorithm));
        } catch (\InvalidArgumentException $exception) {
            throw $exception;
        } catch (\Exception $exception) {
            throw new \InvalidArgumentException('Unable to decode token', previous: $exception);
        }
    }

    /**
     * @param string|\OpenSSLAsymmetricKey|\OpenSSLCertificate|array $secret
     * @param string[] $algorithm
     * @return Key[]
     */
    protected function buildKeyArray($secret, array $algorithm): array
    {
        if (!is_array($secret)) {
            return array_map(fn (string $alg) => new Key($this->options['secret'], $alg), $algorithm);
        } else {
            return array_map(
                fn (string $secret, string $alg) => new Key($secret, $alg),
                $secret,
                $algorithm,
            );
        }
    }
}
