<?php

namespace MadeSimple\Slim\Middleware\Tests\Integration\Authentication;

use MadeSimple\Slim\Middleware\Tests\TestContainer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpUnauthorizedException;
use Slim\Factory\AppFactory;
use Slim\Middleware\Authentication\SimpleTokenAuthentication;
use Slim\Psr7\Factory\ServerRequestFactory;

class SlimSimpleTokenAuthenticationTest extends TestCase
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
            $response->getBody()->write('success');
            return $response->withStatus(200);
        });
    }

    public function testSimpleRequestInsecure()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->app->add(new SimpleTokenAuthentication($this->app->getContainer(), []));
        $this->app->handle($this->request);
    }

    public function testSimpleFetchTokenMissing()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->app->add(new SimpleTokenAuthentication($this->app->getContainer(), [
            'secure' => false,
        ]));
        $this->app->handle($this->request);
    }

    public function testSimpleFetchTokenHeaderValid()
    {
        $this->request = $this->request->withHeader('X-Auth', 'Bearer token');
        $this->app->add(new SimpleTokenAuthentication($this->app->getContainer(), [
            'validate' => function ($token) { return $token === 'Bearer token'; },
            'secure' => false,
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testSimpleFetchTokenHeaderInvalid()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->request = $this->request->withHeader('X-Auth', 'Bearer invalid');
        $this->app->add(new SimpleTokenAuthentication($this->app->getContainer(), [
            'validate' => function ($token) { return $token === 'Bearer token'; },
            'secure' => false,
        ]));
        $this->app->handle($this->request);
    }

    public function testSimpleFetchTokenServerParamValid()
    {
        $this->request = (new ServerRequestFactory())->createServerRequest('GET', '/', [
            'HTTP_AUTH' => 'Bearer token',
        ]);
        $this->app->add(new SimpleTokenAuthentication($this->app->getContainer(), [
            'validate' => function ($token) { return $token === 'Bearer token'; },
            'secure'      => false,
            'environment' => ['HTTP_AUTH'],
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testSimpleFetchTokenServerParamInvalid()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->request = (new ServerRequestFactory())->createServerRequest('GET', '/', [
            'HTTP_AUTH' => 'invalid',
        ]);
        $this->app->add(new SimpleTokenAuthentication($this->app->getContainer(), [
            'validate' => function ($token) { return $token === 'Bearer token'; },
            'secure'      => false,
            'environment' => ['HTTP_AUTH'],
        ]));
        $this->app->handle($this->request);
    }

    public function testSimpleFetchTokenPayloadArrayValid()
    {
        $payload = ['token' => 'Bearer token'];
        $this->request = $this->request->withParsedBody($payload);

        $this->app->add(new SimpleTokenAuthentication($this->app->getContainer(), [
            'validate' => function ($token) { return $token === 'Bearer token'; },
            'secure'  => false,
            'payload' => 'token',
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testSimpleFetchTokenPayloadObjectValid()
    {
        $payload = new \stdClass();
        $payload->token = 'Bearer token';
        $this->request = $this->request->withParsedBody($payload);

        $this->app->add(new SimpleTokenAuthentication($this->app->getContainer(), [
            'validate' => function ($token) { return $token === 'Bearer token'; },
            'secure'  => false,
            'payload' => 'token',
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testSimpleFetchTokenPayloadInvalid()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->request = $this->request->withParsedBody(['token' => 'invalid']);
        $this->app->add(new SimpleTokenAuthentication($this->app->getContainer(), [
            'validate' => function ($token) { return $token === 'Bearer token'; },
            'secure' => false,
            'payload' => 'token',
        ]));
        $this->app->handle($this->request);
    }

    public function testSimpleFetchTokenCookieValid()
    {
        $this->request = $this->request->withCookieParams(['token' => 'Bearer token']);
        $this->app->add(new SimpleTokenAuthentication($this->app->getContainer(), [
            'validate' => function ($token) { return $token === 'Bearer token'; },
            'secure' => false,
            'cookie' => 'token',
        ]));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testSimpleFetchTokenCookieInvalid()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $this->request = $this->request->withCookieParams(['token' => 'invalid']);
        $this->app->add(new SimpleTokenAuthentication($this->app->getContainer(), [
            'validate' => function ($token) { return $token === 'Bearer token'; },
            'secure' => false,
            'cookie' => 'token',
        ]));
        $this->app->handle($this->request);
    }
}