<?php

namespace MadeSimple\Slim\Middleware\Tests;

use Firebase\JWT\JWT;

trait GeneratesBearerStringTrait
{
    protected string $stdKey = 'this-is-a-secret-key-which-is-long-enough';
    protected string $altKey = 'this-is-a-secret-key-which-is-different';

    protected function generateBearer(?array $payload = null, ?string $key = null, ?string $alg = null): string
    {
        return 'Bearer ' . $this->generateJwt($payload, $key, $alg);
    }

    protected function generateJwt(?array $payload = null, ?string $key = null, ?string $alg = null): string
    {
        $payload ??= ['uuid' => '123'];
        $key ??= $this->stdKey;
        $alg ??= 'HS256';

        return JWT::encode($payload, $key, $alg, $alg);
    }
}
