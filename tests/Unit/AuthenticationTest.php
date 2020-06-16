<?php

namespace MadeSimple\Slim\Middleware\Tests\Unit;

use MadeSimple\Slim\Middleware\Tests\TestContainer;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Exception\HttpUnauthorizedException;
use Slim\Middleware\Authentication;

class AuthenticationTest extends TestCase
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
     * @param array $options
     * @param array $methods
     * @return Authentication|MockObject
     */
    protected function stubAuthentication(array $options = [], array $methods = [])
    {
        return $this->getMockForAbstractClass(
            Authentication::class,
            [$this->ci, $options],
            '',
            true,
            true,
            true,
            $methods
        );
    }


    /**
     * Test __invoke insecure request.
     *
     * @throws HttpUnauthorizedException
     */
    public function testInvokeInsecure()
    {
        $authentication = $this->stubAuthentication([], ['isSecure', 'unauthenticated']);
        $authentication
            ->expects($this->once())
            ->method('isSecure')
            ->with($this->mockRequest)
            ->willReturn(false);
        $authentication
            ->expects($this->once())
            ->method('unauthenticated')
            ->with($this->mockRequest);

        $authentication->__invoke($this->mockRequest, $this->mockHandler);
    }

    /**
     * Test invoke secure request without a token.
     *
     * @throws HttpUnauthorizedException
     */
    public function testInvokeNoToken()
    {
        $authentication = $this->stubAuthentication([
            'attribute' => 'ATTRIBUTE'
        ], ['isSecure', 'fetchToken', 'unauthenticated']);
        $authentication
            ->expects($this->once())
            ->method('isSecure')
            ->with($this->mockRequest)
            ->willReturn(true);
        $authentication
            ->expects($this->once())
            ->method('fetchToken')
            ->with($this->mockRequest)
            ->willReturn('');
        $authentication
            ->expects($this->once())
            ->method('unauthenticated')
            ->with($this->mockRequest);
        $this->mockRequest
            ->expects($this->once())
            ->method('withAttribute')
            ->with('ATTRIBUTE', '')
            ->willReturnSelf();

        $authentication->__invoke($this->mockRequest, $this->mockHandler);
    }

    /**
     * Test invoke secure request with an invalid token.
     *
     * @throws HttpUnauthorizedException
     */
    public function testInvokeInvalidToken()
    {
        $authentication = $this->stubAuthentication([
            'attribute' => 'ATTRIBUTE'
        ], ['isSecure', 'fetchToken', 'unauthenticated']);
        $authentication
            ->expects($this->once())
            ->method('isSecure')
            ->with($this->mockRequest)
            ->willReturn(true);
        $authentication
            ->expects($this->once())
            ->method('fetchToken')
            ->with($this->mockRequest)
            ->willReturn('token');
        $authentication
            ->expects($this->once())
            ->method('validate')
            ->with('token')
            ->willReturn(false);
        $authentication
            ->expects($this->once())
            ->method('unauthenticated')
            ->with($this->mockRequest);
        $this->mockRequest
            ->expects($this->once())
            ->method('withAttribute')
            ->with('ATTRIBUTE', 'token')
            ->willReturnSelf();

        $authentication->__invoke($this->mockRequest, $this->mockHandler);
    }

    /**
     * Test invoke secure request with a valid token.
     *
     * @throws HttpUnauthorizedException
     */
    public function testInvokeValidToken()
    {
        $authentication = $this->stubAuthentication([
            'attribute' => 'ATTRIBUTE'
        ], ['isSecure', 'fetchToken', 'authenticated']);
        $authentication
            ->expects($this->once())
            ->method('isSecure')
            ->with($this->mockRequest)
            ->willReturn(true);
        $authentication
            ->expects($this->once())
            ->method('fetchToken')
            ->with($this->mockRequest)
            ->willReturn('token');
        $authentication
            ->expects($this->once())
            ->method('validate')
            ->with('token')
            ->willReturn(true);
        $authentication
            ->expects($this->once())
            ->method('authenticated')
            ->with($this->mockRequest, $this->mockHandler);
        $this->mockRequest
            ->expects($this->once())
            ->method('withAttribute')
            ->with('ATTRIBUTE', 'token')
            ->willReturnSelf();


        $authentication->__invoke($this->mockRequest, $this->mockHandler);
    }

    /**
     * Test HttpUnauthorizedException is thrown.
     */
    public function testUnauthenticatedThrowsHttpUnauthorizedException()
    {
        $this->expectException(HttpUnauthorizedException::class);

        $authentication = $this->stubAuthentication();
        $authentication->unauthenticated($this->mockRequest);
    }

    /**
     * Test authenticated calls RequestHandlerInterface::handle with the ServerRequestInterface object.
     */
    public function testAuthenticated()
    {
        $this->mockHandler->expects($this->once())->method('handle')->with($this->mockRequest);

        $authentication = $this->stubAuthentication();
        $authentication->authenticated($this->mockRequest, $this->mockHandler);
    }

    /**
     * Test that isSecure returns true when secure option is false.
     */
    public function testIsSecureObeysSecureOption()
    {
        $authentication = $this->stubAuthentication([
            'secure' => false
        ]);
        $this->assertTrue($authentication->isSecure($this->mockRequest));
    }

    /**
     * Test that isSecure returns true when URI in relaxed option.
     */
    public function testIsSecureObeysRelaxedOption()
    {
        $mockUri = $this->createMock(UriInterface::class);
        $this->mockRequest->expects($this->once())->method('getUri')->willReturn($mockUri);
        $mockUri->expects($this->once())->method('getHost')->willReturn('relaxed.domain');

        $authentication = $this->stubAuthentication([
            'relaxed' => ['relaxed.domain']
        ]);
        $this->assertTrue($authentication->isSecure($this->mockRequest));
    }

    /**
     * Test that isSecure properly checks request uri scheme.
     * @param $scheme
     * @param $secure
     * @dataProvider isSecureChecksUriSchemeProvider
     */
    public function testIsSecureChecksUriScheme($scheme, $secure)
    {
        $mockUri = $this->createMock(UriInterface::class);
        $this->mockRequest->expects($this->exactly(2))->method('getUri')->willReturn($mockUri);
        $mockUri->expects($this->once())->method('getHost')->willReturn('production.domain');
        $mockUri->expects($this->once())->method('getScheme')->willReturn($scheme);

        $authentication = $this->stubAuthentication([
            'relaxed' => ['relaxed.domain']
        ]);
        $this->assertEquals($secure, $authentication->isSecure($this->mockRequest));
    }
    public function isSecureChecksUriSchemeProvider()
    {
        return [
            ['http', false],
            ['https', true],
        ];
    }

    /**
     * Test fetching a token from the environment.
     */
    public function testFetchTokenFromEnvironment()
    {
        $this->mockRequest
            ->expects($this->once())
            ->method('getServerParams')
            ->willReturn(['ENVIRONMENT_VARIABLE' => 'token']);

        $authentication = $this->stubAuthentication([
            'environment' => ['ENVIRONMENT_VARIABLE']
        ]);
        $token = $authentication->fetchToken($this->mockRequest);
        $this->assertEquals('token', $token);
    }

    /**
     * Test fetching a token from a header.
     */
    public function testFetchTokenFromHeader()
    {
        $this->mockRequest
            ->expects($this->once())
            ->method('getServerParams')
            ->willReturn([]);
        $this->mockRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('HEADER_NAME')
            ->willReturn(['token']);

        $authentication = $this->stubAuthentication([
            'environment' => ['ENVIRONMENT_VARIABLE'],
            'header' => 'HEADER_NAME'
        ]);
        $token = $authentication->fetchToken($this->mockRequest);
        $this->assertEquals('token', $token);
    }

    /**
     * Test fetching a token from a cookie.
     */
    public function testFetchTokenFromCookie()
    {
        $this->mockRequest
            ->expects($this->once())
            ->method('getServerParams')
            ->willReturn([]);
        $this->mockRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('HEADER_NAME')
            ->willReturn([]);
        $this->mockRequest
            ->expects($this->once())
            ->method('getCookieParams')
            ->willReturn(['COOKIE_NAME' => 'token']);

        $authentication = $this->stubAuthentication([
            'environment' => ['ENVIRONMENT_VARIABLE'],
            'header' => 'HEADER_NAME',
            'cookie' => 'COOKIE_NAME'
        ]);
        $token = $authentication->fetchToken($this->mockRequest);
        $this->assertEquals('token', $token);
    }

    /**
     * Test fetching a token that is not there.
     */
    public function testFetchTokenNoMatch()
    {
        $this->mockRequest
            ->expects($this->once())
            ->method('getServerParams')
            ->willReturn([]);
        $this->mockRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('HEADER_NAME')
            ->willReturn([]);
        $this->mockRequest
            ->expects($this->once())
            ->method('getCookieParams')
            ->willReturn([]);

        $authentication = $this->stubAuthentication([
            'environment' => ['ENVIRONMENT_VARIABLE'],
            'header' => 'HEADER_NAME',
            'cookie' => 'COOKIE_NAME'
        ]);
        $token = $authentication->fetchToken($this->mockRequest);
        $this->assertEquals('', $token);
    }

    /**
     * Test fetching a token that is not there without checking cookies.
     */
    public function testFetchTokenNoMatchWithCookies()
    {
        $this->mockRequest
            ->expects($this->once())
            ->method('getServerParams')
            ->willReturn([]);
        $this->mockRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('HEADER_NAME')
            ->willReturn([]);
        $this->mockRequest
            ->expects($this->never())
            ->method('getCookieParams');

        $authentication = $this->stubAuthentication([
            'environment' => ['ENVIRONMENT_VARIABLE'],
            'header' => 'HEADER_NAME',
            'cookie' => false
        ]);
        $token = $authentication->fetchToken($this->mockRequest);
        $this->assertEquals('', $token);
    }

    /**
     * Test retrieving middleware options.
     */
    public function testGetOptions()
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

        $this->assertEquals($options, $authentication->getOptions());
    }

    /**
     * Test retrieving a single option.
     */
    public function testGetOption()
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
