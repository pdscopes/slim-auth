<?php

namespace MadeSimple\Slim\Middleware\Tests\Integration\Authentication;

use MadeSimple\Slim\Middleware\Tests\GeneratesBearerStringTrait;
use MadeSimple\Slim\Middleware\Tests\TestContainer;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpUnauthorizedException;
use Slim\Factory\AppFactory;
use Slim\Middleware\Authentication\JwtAuthentication;
use Slim\Psr7\Factory\ServerRequestFactory;

class SlimJwtAuthenticationTest extends TestCase
{
    use GeneratesBearerStringTrait;

    private \Slim\App $app;
    private ServerRequestInterface $request;

    protected function setUp(): void
    {
        parent::setUp();

        // Set up the request
        $this->request = (new ServerRequestFactory())->createServerRequest('GET', '/');

        // Set up the application
        $this->app = AppFactory::create(null, new TestContainer());
        $this->app->get('/', function (ServerRequestInterface $request, ResponseInterface $response) {
            $request->getAttribute('token');
            $response->getBody()->write($request->getAttribute('token')->uuid);
            return $response->withStatus(200);
        });
    }

    #[Test]
    public function jwtRequestInsecure()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->app->add(new JwtAuthentication($this->app->getContainer(), []));
        $this->app->handle($this->request);
    }

    #[Test]
    public function jwtFetchTokenMissing()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
        ]));
        $this->app->handle($this->request);
    }

    #[Test]
    public function jwtFetchTokenHeaderValid()
    {
        $this->request = $this->request->withHeader('Authorization', $this->generateBearer());
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => $this->stdKey,
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('123', (string) $response->getBody());
    }

    #[Test]
    public function jwtFetchTokenHeaderInvalid()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->request = $this->request->withHeader('Authorization', $this->generateBearer(key: $this->altKey));
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => $this->stdKey,
        ]));
        $this->app->handle($this->request);
    }

    #[Test]
    public function jwtFetchTokenServerParamValid()
    {
        $this->request = (new ServerRequestFactory())->createServerRequest('GET', '/', [
            'HTTP_AUTH' => $this->generateJwt(),
        ]);
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure'      => false,
            'secret'      => $this->stdKey,
            'environment' => ['HTTP_AUTH'],
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('123', (string) $response->getBody());
    }

    #[Test]
    public function jwtFetchTokenServerParamInvalid()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->request = (new ServerRequestFactory())->createServerRequest('GET', '/', [
            'HTTP_AUTH' => $this->generateJwt(key: $this->altKey),
        ]);
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure'      => false,
            'secret'      => $this->stdKey,
            'environment' => ['HTTP_AUTH'],
        ]));
        $this->app->handle($this->request);
    }

    #[Test]
    public function jwtFetchTokenPayloadArrayValid()
    {
        $payload = ['token' => $this->generateJwt()];
        $this->request = $this->request->withParsedBody($payload);

        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure'  => false,
            'secret'  => $this->stdKey,
            'payload' => 'token',
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('123', (string) $response->getBody());
    }

    #[Test]
    public function jwtFetchTokenPayloadObjectValid()
    {
        $payload = new \stdClass();
        $payload->token = $this->generateJwt();
        $this->request = $this->request->withParsedBody($payload);

        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure'  => false,
            'secret'  => $this->stdKey,
            'payload' => 'token',
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('123', (string) $response->getBody());
    }

    #[Test]
    public function jwtFetchTokenPayloadInvalid()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->request = $this->request->withParsedBody(['token' => $this->generateJwt(key: $this->altKey)]);
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => $this->stdKey,
            'payload' => 'token',
        ]));
        $this->app->handle($this->request);
    }

    #[Test]
    public function jwtFetchTokenCookieValid()
    {
        $this->request = $this->request->withCookieParams(['token' => $this->generateJwt()]);
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => $this->stdKey,
            'cookie' => 'token',
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('123', (string) $response->getBody());
    }

    #[Test]
    public function jwtFetchTokenCookieInvalid()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->request = $this->request->withCookieParams(['token' => $this->generateJwt(key: $this->altKey)]);
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => $this->stdKey,
            'cookie' => 'token',
        ]));
        $this->app->handle($this->request);
    }
}
