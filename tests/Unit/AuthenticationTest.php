<?php

namespace MadeSimple\Slim\Middleware\Tests\Unit;

use MadeSimple\Slim\Middleware\Tests\TestContainer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Exception\HttpUnauthorizedException;
use Slim\Middleware\Authentication;

class AuthenticationTest extends TestCase
{
    protected TestContainer $ci;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->ci = new TestContainer();
    }

    /**
     * @return Authentication|MockObject
     */
    protected function mockAuthentication(array $options = [], array $methods = [])
    {
        // Ensure all abstract methods are also included
        $methods = array_values(array_unique(array_merge($methods, ['validate'])));
        // Build the mock object
        return $this->getMockBuilder(Authentication::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([$this->ci, $options])
            ->onlyMethods($methods)
            ->getMock();
    }

    /**
     * @return Authentication|Stub
     */
    protected function stubAuthentication(array $options = [], array $methods = [])
    {
        // Ensure all abstract methods are also included
        $methods = array_values(array_unique(array_merge($methods, ['validate'])));
        // Build the mock object
        return $this->getStubBuilder(Authentication::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([$this->ci, $options])
            ->onlyMethods($methods)
            ->getStub();
    }


    /**
     * Test __invoke insecure request.
     */
    #[Test]
    public function invokeInsecure()
    {
        $stubRequest = $this->createStub(ServerRequestInterface::class);
        $stubHandler = $this->createStub(RequestHandlerInterface::class);

        $authentication = $this->mockAuthentication([], ['isSecure', 'unauthenticated']);
        $authentication
            ->expects($this->once())
            ->method('isSecure')
            ->with($stubRequest)
            ->willReturn(false);
        $authentication
            ->expects($this->once())
            ->method('unauthenticated')
            ->with($stubRequest);

        $authentication->__invoke($stubRequest, $stubHandler);
    }

    /**
     * Test invoke a secure request without a token.
     */
    #[Test]
    public function invokeNoToken()
    {
        $mockRequest = $this->createMock(ServerRequestInterface::class);
        $stubHandler = $this->createStub(RequestHandlerInterface::class);

        $authentication = $this->mockAuthentication([
            'attribute' => 'ATTRIBUTE'
        ], ['isSecure', 'fetchToken', 'unauthenticated']);
        $authentication
            ->expects($this->once())
            ->method('isSecure')
            ->with($mockRequest)
            ->willReturn(true);
        $authentication
            ->expects($this->once())
            ->method('fetchToken')
            ->with($mockRequest)
            ->willReturn('');
        $authentication
            ->expects($this->once())
            ->method('unauthenticated')
            ->with($mockRequest);
        $mockRequest
            ->expects($this->once())
            ->method('withAttribute')
            ->with('ATTRIBUTE', '')
            ->willReturnSelf();

        $authentication->__invoke($mockRequest, $stubHandler);
    }

    /**
     * Test invoke a secure request with an invalid token.
     */
    #[Test]
    public function invokeInvalidToken()
    {
        $mockRequest = $this->createMock(ServerRequestInterface::class);
        $stubHandler = $this->createStub(RequestHandlerInterface::class);

        $authentication = $this->mockAuthentication([
            'attribute' => 'ATTRIBUTE'
        ], ['isSecure', 'fetchToken', 'unauthenticated']);
        $authentication
            ->expects($this->once())
            ->method('isSecure')
            ->with($mockRequest)
            ->willReturn(true);
        $authentication
            ->expects($this->once())
            ->method('fetchToken')
            ->with($mockRequest)
            ->willReturn('token');
        $authentication
            ->expects($this->once())
            ->method('validate')
            ->with('token')
            ->willReturn(false);
        $authentication
            ->expects($this->once())
            ->method('unauthenticated')
            ->with($mockRequest);
        $mockRequest
            ->expects($this->once())
            ->method('withAttribute')
            ->with('ATTRIBUTE', 'token')
            ->willReturnSelf();

        $authentication->__invoke($mockRequest, $stubHandler);
    }

    /**
     * Test invoke a secure request with a valid token.
     */
    #[Test]
    public function invokeValidToken()
    {
        $mockRequest = $this->createMock(ServerRequestInterface::class);
        $stubHandler = $this->createStub(RequestHandlerInterface::class);

        $authentication = $this->mockAuthentication([
            'attribute' => 'ATTRIBUTE'
        ], ['isSecure', 'fetchToken', 'authenticated']);
        $authentication
            ->expects($this->once())
            ->method('isSecure')
            ->with($mockRequest)
            ->willReturn(true);
        $authentication
            ->expects($this->once())
            ->method('fetchToken')
            ->with($mockRequest)
            ->willReturn('token');
        $authentication
            ->expects($this->once())
            ->method('validate')
            ->with('token')
            ->willReturn(true);
        $authentication
            ->expects($this->once())
            ->method('authenticated')
            ->with($mockRequest, $stubHandler);
        $mockRequest
            ->expects($this->once())
            ->method('withAttribute')
            ->with('ATTRIBUTE', 'token')
            ->willReturnSelf();


        $authentication->__invoke($mockRequest, $stubHandler);
    }

    /**
     * Test HttpUnauthorizedException is thrown.
     */
    #[Test]
    public function unauthenticatedThrowsHttpUnauthorizedException()
    {
        $stubRequest = $this->createStub(ServerRequestInterface::class);

        $this->expectException(HttpUnauthorizedException::class);

        $authentication = $this->stubAuthentication();
        $authentication->unauthenticated($stubRequest);
    }

    /**
     * Test authenticated calls RequestHandlerInterface::handle with the ServerRequestInterface object.
     */
    #[Test]
    public function authenticated()
    {
        $stubRequest = $this->createStub(ServerRequestInterface::class);
        $mockHandler = $this->createMock(RequestHandlerInterface::class);

        $mockHandler->expects($this->once())->method('handle')->with($stubRequest);

        $authentication = $this->stubAuthentication();
        $authentication->authenticated($stubRequest, $mockHandler);
    }

    /**
     * Test that isSecure returns true when the secure option is false.
     */
    #[Test]
    public function isSecureObeysSecureOption()
    {
        $stubRequest = $this->createStub(ServerRequestInterface::class);

        $authentication = $this->stubAuthentication([
            'secure' => false
        ]);
        $this->assertTrue($authentication->isSecure($stubRequest));
    }

    /**
     * Test that isSecure returns true when URI in relaxed option.
     */
    #[Test]
    public function isSecureObeysRelaxedOption()
    {
        $mockRequest = $this->createMock(ServerRequestInterface::class);

        $mockUri = $this->createMock(UriInterface::class);
        $mockRequest->expects($this->once())->method('getUri')->willReturn($mockUri);
        $mockUri->expects($this->once())->method('getHost')->willReturn('relaxed.domain');

        $authentication = $this->stubAuthentication([
            'relaxed' => ['relaxed.domain']
        ]);
        $this->assertTrue($authentication->isSecure($mockRequest));
    }

    /**
     * Test that isSecure properly checks the request uri scheme.
     * @param $scheme
     * @param $secure
     */
    #[Test]
    #[DataProvider('isSecureChecksUriSchemeProvider')]
    public function isSecureChecksUriScheme($scheme, $secure)
    {
        $mockRequest = $this->createMock(ServerRequestInterface::class);

        $mockUri = $this->createMock(UriInterface::class);
        $mockRequest->expects($this->exactly(2))->method('getUri')->willReturn($mockUri);
        $mockUri->expects($this->once())->method('getHost')->willReturn('production.domain');
        $mockUri->expects($this->once())->method('getScheme')->willReturn($scheme);

        $authentication = $this->stubAuthentication([
            'relaxed' => ['relaxed.domain']
        ]);
        $this->assertEquals($secure, $authentication->isSecure($mockRequest));
    }

    public static function isSecureChecksUriSchemeProvider(): array
    {
        return [
            ['http', false],
            ['https', true],
        ];
    }

    /**
     * Test fetching a token from the environment.
     */
    #[Test]
    public function fetchTokenFromEnvironment()
    {
        $mockRequest = $this->createMock(ServerRequestInterface::class);

        $mockRequest
            ->expects($this->once())
            ->method('getServerParams')
            ->willReturn(['ENVIRONMENT_VARIABLE' => 'token']);

        $authentication = $this->stubAuthentication([
            'environment' => ['ENVIRONMENT_VARIABLE']
        ]);
        $token = $authentication->fetchToken($mockRequest);
        $this->assertEquals('token', $token);
    }

    /**
     * Test fetching a token from a header.
     */
    #[Test]
    public function fetchTokenFromHeader()
    {
        $mockRequest = $this->createMock(ServerRequestInterface::class);

        $mockRequest
            ->expects($this->once())
            ->method('getServerParams')
            ->willReturn([]);
        $mockRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('HEADER_NAME')
            ->willReturn(['token']);

        $authentication = $this->stubAuthentication([
            'environment' => ['ENVIRONMENT_VARIABLE'],
            'header' => 'HEADER_NAME'
        ]);
        $token = $authentication->fetchToken($mockRequest);
        $this->assertEquals('token', $token);
    }

    /**
     * Test fetching a token from a cookie.
     */
    #[Test]
    public function fetchTokenFromCookie()
    {
        $mockRequest = $this->createMock(ServerRequestInterface::class);

        $mockRequest
            ->expects($this->once())
            ->method('getServerParams')
            ->willReturn([]);
        $mockRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('HEADER_NAME')
            ->willReturn([]);
        $mockRequest
            ->expects($this->once())
            ->method('getCookieParams')
            ->willReturn(['COOKIE_NAME' => 'token']);

        $authentication = $this->stubAuthentication([
            'environment' => ['ENVIRONMENT_VARIABLE'],
            'header' => 'HEADER_NAME',
            'cookie' => 'COOKIE_NAME'
        ]);
        $token = $authentication->fetchToken($mockRequest);
        $this->assertEquals('token', $token);
    }

    /**
     * Test fetching a token that is not there.
     */
    #[Test]
    public function fetchTokenNoMatch()
    {
        $mockRequest = $this->createMock(ServerRequestInterface::class);

        $mockRequest
            ->expects($this->once())
            ->method('getServerParams')
            ->willReturn([]);
        $mockRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('HEADER_NAME')
            ->willReturn([]);
        $mockRequest
            ->expects($this->once())
            ->method('getCookieParams')
            ->willReturn([]);

        $authentication = $this->stubAuthentication([
            'environment' => ['ENVIRONMENT_VARIABLE'],
            'header' => 'HEADER_NAME',
            'cookie' => 'COOKIE_NAME'
        ]);
        $token = $authentication->fetchToken($mockRequest);
        $this->assertEquals('', $token);
    }

    /**
     * Test fetching a token that is not there without checking cookies.
     */
    #[Test]
    public function fetchTokenNoMatchWithCookies()
    {
        $mockRequest = $this->createMock(ServerRequestInterface::class);

        $mockRequest
            ->expects($this->once())
            ->method('getServerParams')
            ->willReturn([]);
        $mockRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('HEADER_NAME')
            ->willReturn([]);
        $mockRequest
            ->expects($this->never())
            ->method('getCookieParams');

        $authentication = $this->stubAuthentication([
            'environment' => ['ENVIRONMENT_VARIABLE'],
            'header' => 'HEADER_NAME',
            'cookie' => false
        ]);
        $token = $authentication->fetchToken($mockRequest);
        $this->assertEquals('', $token);
    }

    /**
     * Test retrieving middleware options.
     */
    #[Test]
    public function getOptions()
    {
        $options = [
            'secure'      => true,
            'relaxed'     => ['localhost', '127.0.0.1'],
            'environment' => ['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'],
            'header'      => 'X-Auth',
            'regex'       => '/(.*)/',
            'index'       => 1,
            'cookie'      => 'X-Auth',
            'payload'     => null,
            'attribute'   => 'token',
            'logger'      => null,
            'queryparam'  => null
        ];
        $authentication = $this->stubAuthentication($options);

        $this->assertEquals($options, $authentication->getOptions());
    }

    /**
     * Test retrieving a single option.
     */
    #[Test]
    public function getOption()
    {
        $options = [
            'secure'      => true,
            'relaxed'     => ['localhost', '127.0.0.1'],
            'environment' => ['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'],
            'header'      => 'X-Auth',
            'regex'       => '/(.*)/',
            'index'       => 1,
            'cookie'      => 'X-Auth',
            'payload'     => null,
            'attribute'   => 'token',
            'logger'      => null,
        ];
        $authentication = $this->stubAuthentication($options);

        foreach ($options as $opt => $value) {
            $this->assertEquals($value, $authentication->getOption($opt));
        }
    }
}
