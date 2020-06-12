<?php

namespace MadeSimple\Slim\Middleware\Tests\Integration\Authentication;

use Firebase\JWT\JWT;
use MadeSimple\Slim\Middleware\Tests\TestContainer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;
use Slim\Middleware\Authentication\JwtAuthentication;
use Slim\Middleware\NotAuthenticatedException;
use Slim\Psr7\Factory\ServerRequestFactory;

class SlimJwtAuthenticationTest extends TestCase
{
    /**
     * @var \Slim\App
     */
    private $app;

    /**
     * @var \Psr\Http\Message\ServerRequestInterface
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
            $response->getBody()->write('success');
            return $response->withStatus(200);
        });
    }

    public function testJwtRequestInsecure()
    {
        $this->expectException(NotAuthenticatedException::class);

        $this->app->add(new JwtAuthentication($this->app->getContainer(), []));
        $this->app->handle($this->request);
    }

    public function testJwtFetchTokenMissing()
    {
        $this->expectException(NotAuthenticatedException::class);

        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
        ]));
        $this->app->handle($this->request);
    }

    public function testJwtFetchTokenHeaderValid()
    {
        $this->request = $this->request->withHeader('Authorization', 'Bearer ' . JWT::encode([], 'secret'));
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => 'secret',
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testJwtFetchTokenHeaderInvalid()
    {
        $this->expectException(NotAuthenticatedException::class);

        $this->request = $this->request->withHeader('Authorization', 'Bearer ' . JWT::encode([], 'invalid'));
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => 'secret',
        ]));
        $this->app->handle($this->request);
    }

    public function testJwtFetchTokenServerParamValid()
    {
        $this->request = (new ServerRequestFactory())->createServerRequest('GET', '/', [
            'HTTP_AUTH' => JWT::encode([], 'secret'),
        ]);
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure'      => false,
            'secret'      => 'secret',
            'environment' => ['HTTP_AUTH'],
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testJwtFetchTokenServerParamInvalid()
    {
        $this->expectException(NotAuthenticatedException::class);

        $this->request = (new ServerRequestFactory())->createServerRequest('GET', '/', [
            'HTTP_AUTH' => JWT::encode([], 'invalid'),
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
        $payload = ['token' => JWT::encode([], 'secret')];
        $this->request = $this->request->withParsedBody($payload);

        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure'  => false,
            'secret'  => 'secret',
            'payload' => 'token',
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testJwtFetchTokenPayloadObjectValid()
    {
        $payload = new \stdClass();
        $payload->token = JWT::encode([], 'secret');
        $this->request = $this->request->withParsedBody($payload);

        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure'  => false,
            'secret'  => 'secret',
            'payload' => 'token',
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testJwtFetchTokenPayloadInvalid()
    {
        $this->expectException(NotAuthenticatedException::class);

        $this->request = $this->request->withParsedBody(['token' => JWT::encode([], 'invalid')]);
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => 'secret',
            'payload' => 'token',
        ]));
        $this->app->handle($this->request);
    }

    public function testJwtFetchTokenCookieValid()
    {
        $this->request = $this->request->withCookieParams(['token' => JWT::encode([], 'secret')]);
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => 'secret',
            'cookie' => 'token',
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testJwtFetchTokenCookieInvalid()
    {
        $this->expectException(NotAuthenticatedException::class);

        $this->request = $this->request->withCookieParams(['token' => JWT::encode([], 'invalid')]);
        $this->app->add(new JwtAuthentication($this->app->getContainer(), [
            'secure' => false,
            'secret' => 'secret',
            'cookie' => 'token',
        ]));
        $this->app->handle($this->request);
    }
}