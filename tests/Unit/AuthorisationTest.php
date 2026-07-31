<?php

namespace MadeSimple\Slim\Middleware\Tests\Unit;

use MadeSimple\Slim\Middleware\Tests\TestContainer;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Exception\HttpForbiddenException;
use Slim\Middleware\Authorisation;

class AuthorisationTest extends TestCase
{
    protected TestContainer $ci;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->ci = new TestContainer();
    }

    /**
     * @param bool $validate
     * @param array $methods
     * @return Authorisation|Stub
     */
    protected function stubAuthorisation(bool $validate, array $methods = [])
    {
        // Ensure all abstract methods are also included
        $methods = array_values(array_unique(array_merge($methods, ['hasAuthorisation'])));
        // Build the mock object
        return $this->getStubBuilder(Authorisation::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([$this->ci, $validate])
            ->onlyMethods($methods)
            ->getStub();
    }

    /**
     * @param bool $validate
     * @param array $methods
     * @return Authorisation|MockObject
     */
    protected function mockAuthorisation(bool $validate, array $methods = [])
    {
        // Ensure all abstract methods are also included
        $methods = array_values(array_unique(array_merge($methods, ['hasAuthorisation'])));
        // Build the mock object
        return $this->getMockBuilder(Authorisation::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([$this->ci, $validate])
            ->onlyMethods($methods)
            ->getMock();
    }

    /**
     * Test HttpForbiddenException is thrown.
     */
    #[Test]
    public function unauthorisedThrowsHttpForbiddenException()
    {
        $stubRequest = $this->createStub(ServerRequestInterface::class);

        $this->expectException(HttpForbiddenException::class);

        $authorisation = $this->stubAuthorisation(false);
        $authorisation->unauthorised($stubRequest);
    }

    /**
     * Test authorised calls RequestHandlerInterface::handle with the ServerRequestInterface object.
     */
    #[Test]
    public function authorised()
    {
        $stubRequest = $this->createStub(ServerRequestInterface::class);
        $mockHandler = $this->createMock(RequestHandlerInterface::class);

        $mockHandler->expects($this->once())->method('handle')->with($stubRequest);

        $authorisation = $this->stubAuthorisation(true);
        $authorisation->authorised($stubRequest, $mockHandler);
    }
}
