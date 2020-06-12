<?php

namespace MadeSimple\Slim\Middleware\Tests\Integration;

use MadeSimple\Slim\Middleware\Tests\TestAuthorisation;
use MadeSimple\Slim\Middleware\Tests\TestContainer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpForbiddenException;
use Slim\Factory\AppFactory;
use Slim\Psr7\Factory\ServerRequestFactory;

class SlimTestAuthorisationTest extends TestCase
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

    public function testProcessHasAuthorisationTrue()
    {
        $this->app->add(new TestAuthorisation($this->app->getContainer(), true));
        $response = $this->app->handle($this->request);

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testProcessHasAuthorisationFalse()
    {
        $this->expectException(HttpForbiddenException::class);

        $this->app->add(new TestAuthorisation($this->app->getContainer(), false));
        $this->app->handle($this->request);
    }
}