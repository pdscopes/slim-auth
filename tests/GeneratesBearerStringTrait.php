<?php

namespace MadeSimple\Slim\Middleware\Tests;

use Firebase\JWT\JWT;

trait GeneratesBearerStringTrait
{
    protected string $stdKey = 'this-is-a-standard-secret-key-which-is-long-enough-for-512-bit-alg';
    protected string $altKey = 'this-is-a-alternate-secret-key-which-is-different-for-512-bit-alg';

    protected function generateBearer(
        ?array $payload = null,
        ?string $key = null,
        ?string $alg = null,
        ?string $kid = null,
    ): string {
        return 'Bearer ' . $this->generateJwt($payload, $key, $alg, $kid);
    }

    protected function generateJwt(
        ?array $payload = null,
        ?string $key = null,
        ?string $alg = null,
        ?string $kid = null,
    ): string {
        $payload ??= ['uuid' => '123'];
        $key ??= $this->stdKey;
        $alg ??= 'HS256';

        return JWT::encode($payload, $key, $alg, $kid);
    }
}
