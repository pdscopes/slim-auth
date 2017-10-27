<?php

namespace MadeSimple\Slim\Middleware\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Slim\Http\Request;
use Slim\Http\Response;
use Slim\Http\Uri;
use Slim\Middleware\Authentication;

class AuthenticationTest extends TestCase
{
    /**
     * @var \Psr\Container\ContainerInterface
     */
    protected $ci;

    /**
     * @var \Slim\Http\Request|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $mockRequest;

    /**
     * @var \Slim\Http\Response|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $mockResponse;

    /**
     * @var callable
     */
    protected $mockNext;

    /**
     * @InheritDoc
     */
    protected function setUp()
    {
        parent::setUp();

        $this->ci = new \Slim\Container();
        $this->mockRequest  = $this->getMockBuilder(Request::class)->disableOriginalConstructor()->getMock();
        $this->mockResponse = $this->getMockBuilder(Response::class)->disableOriginalConstructor()->getMock();
        $this->mockNext     = function () {};
    }

    /**
     * @param array $options
     * @param array $methods
     * @return \Slim\Middleware\Authentication|\PHPUnit_Framework_MockObject_MockObject
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
            ->with($this->mockRequest, $this->mockResponse, $this->mockNext);

        $authentication->__invoke($this->mockRequest, $this->mockResponse, $this->mockNext);
    }

    /**
     * Test invoke secure request without a token.
     */
    public function testInvokeNoToken()
    {
        $authentication = $this->stubAuthentication([], ['isSecure', 'fetchToken', 'unauthenticated']);
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
            ->with($this->mockRequest, $this->mockResponse, $this->mockNext);

        $authentication->__invoke($this->mockRequest, $this->mockResponse, $this->mockNext);
    }

    /**
     * Test invoke secure request with an invalid token.
     */
    public function testInvokeInvalidToken()
    {
        $authentication = $this->stubAuthentication([], ['isSecure', 'fetchToken', 'unauthenticated']);
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
            ->with($this->mockRequest, $this->mockResponse, $this->mockNext);

        $authentication->__invoke($this->mockRequest, $this->mockResponse, $this->mockNext);
    }

    /**
     * Test invoke secure request with a valid token.
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
            ->with($this->mockRequest, $this->mockResponse, $this->mockNext);

        $this->mockRequest
            ->expects($this->once())
            ->method('withAttribute')
            ->with('ATTRIBUTE', 'token')
            ->willReturnSelf();

        $authentication->__invoke($this->mockRequest, $this->mockResponse, $this->mockNext);
    }

    /**
     * Test NotAuthenticatedException is thrown if 'notAuthenticatedHandler' is not present.
     * @expectedException \Slim\Middleware\NotAuthenticatedException
     */
    public function testUnauthenticatedThrowsNotAuthenticatedException()
    {
        $authentication = $this->stubAuthentication();
        $authentication->unauthenticated($this->mockRequest, $this->mockResponse, $this->mockNext);
    }

    /**
     * Test 'notAuthenticatedHandler is called when present.
     */
    public function testUnauthenticatedCallsNotAuthenticatedHandler()
    {
        $this->mockRequest->expects($this->once())->method('getMethod');
        $this->mockResponse->expects($this->once())->method('getStatusCode');

        $this->ci['notAuthenticatedHandler'] = function () {
            return function($request, $response) { $request->getMethod(); $response->getStatusCode(); };
        };

        $authentication = $this->stubAuthentication();
        $authentication->unauthenticated($this->mockRequest, $this->mockResponse, $this->mockNext);
    }

    /**
     * Test authenticated passes request and response to the callable next.
     */
    public function testAuthenticated()
    {
        $this->mockRequest->expects($this->once())->method('getMethod');
        $this->mockResponse->expects($this->once())->method('getStatusCode');
        $next = function($request, $response) { $request->getMethod(); $response->getStatusCode(); };

        $authentication = $this->stubAuthentication();
        $authentication->authenticated($this->mockRequest, $this->mockResponse, $next);
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
        $mockUri = $this->createMock(Uri::class);
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
        $mockUri = $this->createMock(Uri::class);
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
            ->method('getServerParam')
            ->with('ENVIRONMENT_VARIABLE')
            ->willReturn('token');

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
            ->method('getServerParam')
            ->with('ENVIRONMENT_VARIABLE')
            ->willReturn('');
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
            ->method('getServerParam')
            ->with('ENVIRONMENT_VARIABLE')
            ->willReturn('');
        $this->mockRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('HEADER_NAME')
            ->willReturn([]);
        $this->mockRequest
            ->expects($this->once())
            ->method('getCookieParam')
            ->willReturn('token');

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
            ->method('getServerParam')
            ->with('ENVIRONMENT_VARIABLE')
            ->willReturn('');
        $this->mockRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('HEADER_NAME')
            ->willReturn([]);
        $this->mockRequest
            ->expects($this->once())
            ->method('getCookieParam')
            ->willReturn('');

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
            ->method('getServerParam')
            ->with('ENVIRONMENT_VARIABLE')
            ->willReturn('');
        $this->mockRequest
            ->expects($this->once())
            ->method('getHeader')
            ->with('HEADER_NAME')
            ->willReturn([]);
        $this->mockRequest
            ->expects($this->never())
            ->method('getCookieParam');

        $authentication = $this->stubAuthentication([
            'environment' => ['ENVIRONMENT_VARIABLE'],
            'header' => 'HEADER_NAME',
            'cookie' => false
        ]);
        $token = $authentication->fetchToken($this->mockRequest);
        $this->assertEquals('', $token);
    }
}