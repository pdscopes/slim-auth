<?php

namespace MadeSimple\Slim\Middleware\Tests\Unit;

use MadeSimple\Slim\Middleware\Tests\TestContainer;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Exception\HttpForbiddenException;
use Slim\Middleware\Authorisation;

class AuthorisationTest extends TestCase
{
    /**
     * @var TestContainer
     */
    protected $ci;

    /**
     * @var ServerRequestInterface|MockObject
     */
    protected $mockRequest;

    /**
     * @var RequestHandlerInterface|MockObject
     */
    protected $mockHandler;

    /**
     * @InheritDoc
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->ci = new TestContainer();
        $this->mockRequest = $this->createMock(ServerRequestInterface::class);
        $this->mockHandler = $this->createMock(RequestHandlerInterface::class);
    }

    /**
     * @param bool $validate
     * @param array $methods
     * @return Authorisation|MockObject
     */
    protected function stubAuthorisation(bool $validate, array $methods = [])
    {
        return $this->getMockForAbstractClass(
            Authorisation::class,
            [$this->ci, $validate],
            '',
            true,
            true,
            true,
            $methods
        );
    }

    /**
     * Test HttpForbiddenException is thrown.
     */
    public function testUnauthorisedThrowsHttpForbiddenException()
    {
        $this->expectException(HttpForbiddenException::class);

        $authorisation = $this->stubAuthorisation(false);
        $authorisation->unauthorised($this->mockRequest);

    }

    /**
     * Test authorised calls RequestHandlerInterface::handle with the ServerRequestInterface object.
     */
    public function testAuthorised()
    {
        $this->mockHandler->expects($this->once())->method('handle')->with($this->mockRequest);

        $authorisation = $this->stubAuthorisation(true);
        $authorisation->authorised($this->mockRequest, $this->mockHandler);
    }
}