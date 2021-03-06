<?php

namespace MadeSimple\Slim\Middleware\Tests\Integration\Authentication;

use Firebase\JWT\JWT;
use MadeSimple\Slim\Middleware\Tests\TestContainer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpUnauthorizedException;
use Slim\Factory\AppFactory;
use Slim\Middleware\Authentication\JwtAuthentication;
use Slim\Psr7\Factory\ServerRequestFactory;

class SlimJwtAuthenticationTest extends TestCase
{
    /**
     * @var \Slim\App
     */
    private $app;

    /**
     * @var ServerRequestInterface
     */
    private $request;

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

    public function testJwtRequestInsecure()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->app->add(new JwtAuthentication($this->app->getContainer(), []));
        $this->app->handle($this->request);
    }

    public function testJwtFetchTokenMissing()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
        ]));
        $this->app->handle($this->request);
    }

    public function testJwtFetchTokenHeaderValid()
    {
        $this->request = $this->request->withHeader('Authorization', 'Bearer ' . JWT::encode(['uuid' => '123'], 'secret'));
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => 'secret',
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('123', (string) $response->getBody());
    }

    public function testJwtFetchTokenHeaderInvalid()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->request = $this->request->withHeader('Authorization', 'Bearer ' . JWT::encode(['uuid' => '123'], 'invalid'));
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => 'secret',
        ]));
        $this->app->handle($this->request);
    }

    public function testJwtFetchTokenServerParamValid()
    {
        $this->request = (new ServerRequestFactory())->createServerRequest('GET', '/', [
            'HTTP_AUTH' => JWT::encode(['uuid' => '123'], 'secret'),
        ]);
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure'      => false,
            'secret'      => 'secret',
            'environment' => ['HTTP_AUTH'],
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('123', (string) $response->getBody());
    }

    public function testJwtFetchTokenServerParamInvalid()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->request = (new ServerRequestFactory())->createServerRequest('GET', '/', [
            'HTTP_AUTH' => JWT::encode(['uuid' => '123'], 'invalid'),
        ]);
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure'      => false,
            'secret'      => 'secret',
            'environment' => ['HTTP_AUTH'],
        ]));
        $this->app->handle($this->request);
    }

    public function testJwtFetchTokenPayloadArrayValid()
    {
        $payload = ['token' => JWT::encode(['uuid' => '123'], 'secret')];
        $this->request = $this->request->withParsedBody($payload);

        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure'  => false,
            'secret'  => 'secret',
            'payload' => 'token',
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('123', (string) $response->getBody());
    }

    public function testJwtFetchTokenPayloadObjectValid()
    {
        $payload = new \stdClass();
        $payload->token = JWT::encode(['uuid' => '123'], 'secret');
        $this->request = $this->request->withParsedBody($payload);

        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure'  => false,
            'secret'  => 'secret',
            'payload' => 'token',
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('123', (string) $response->getBody());
    }

    public function testJwtFetchTokenPayloadInvalid()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->request = $this->request->withParsedBody(['token' => JWT::encode(['uuid' => '123'], 'invalid')]);
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => 'secret',
            'payload' => 'token',
        ]));
        $this->app->handle($this->request);
    }

    public function testJwtFetchTokenCookieValid()
    {
        $this->request = $this->request->withCookieParams(['token' => JWT::encode(['uuid' => '123'], 'secret')]);
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => 'secret',
            'cookie' => 'token',
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('123', (string) $response->getBody());
    }

    public function testJwtFetchTokenCookieInvalid()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->request = $this->request->withCookieParams(['token' => JWT::encode(['uuid' => '123'], 'invalid')]);
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => 'secret',
            'cookie' => 'token',
        ]));
        $this->app->handle($this->request);
    }
}