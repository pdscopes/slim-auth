<?php

namespace MadeSimple\Slim\Middleware\Tests\Unit\Authentication;

use Firebase\JWT\JWT;
use MadeSimple\Slim\Middleware\Tests\TestContainer;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Middleware\Authentication\JwtAuthentication;

class JwtAuthenticationTest extends TestCase
{
    /**
     * @var ContainerInterface
     */
    protected $ci;

    /**
     * @InheritDoc
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->ci = new TestContainer();
    }

    /**
     * Test that construct without options has all default values.
     */
    public function testConstructWithoutOptions()
    {
        $auth = new JwtAuthentication($this->ci, []);

        $this->assertEquals([
            'secure'      => true,
            'relaxed'     => ['localhost', '127.0.0.1'],
            'environment' => ['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'],
            'header'      => 'Authorization',
            'regex'       => '/(Bearer\s+)?(.*)$/i',
            'index'       => 2,
            'cookie'      => 'X-Auth',
            'payload'     => null,
            'attribute'   => 'token',
            'logger'      => null,
            'secret'      => '',
            'algorithm'   => ['HS256', 'HS512', 'HS384'],
        ], $auth->getOptions());
    }

    /**
     * Test that construct with options overrides the default values.
     * @param string $option
     * @param mixed  $value
     * @dataProvider constructWithOptionsProvider
     */
    public function testConstructWithOptions($option, $value)
    {
        $auth = new JwtAuthentication($this->ci, [$option => $value]);

        $expected = [
            'secure'      => true,
            'relaxed'     => ['localhost', '127.0.0.1'],
            'environment' => ['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'],
            'header'      => 'Authorization',
            'regex'       => '/(Bearer\s+)?(.*)$/i',
            'index'       => 2,
            'cookie'      => 'X-Auth',
            'payload'     => null,
            'attribute'   => 'token',
            'logger'      => null,
            'secret'      => null,
            'algorithm'   => ['HS256', 'HS512', 'HS384'],
        ];
        $expected[$option] = $value;

        $this->assertEquals($expected, $auth->getOptions());
    }
    public function constructWithOptionsProvider()
    {
        return [
            ['secure', false],
            ['relaxed', ['relaxed.com']],
            ['environment', ['ENVIRONMENT_VARIABLE']],
            ['header', 'x-header'],
            ['regex', 'regex pattern'],
            ['index', 5],
            ['cookie', 'cookie name'],
            ['attribute', 'attribute name'],
            ['logger', new \stdClass],
            ['secret', 'JWT SECRET'],
            ['algorithm', ['ALGORITHM 1', 'ALGORITHM 2']],
        ];
    }

    /**
     * Test fetching a valid JWT.
     */
    public function testFetchTokenValid()
    {
        $token = '123';
        $auth    = new JwtAuthentication($this->ci, []);

        /** @var ServerRequestInterface|MockObject $mockRequest */
        $mockRequest = $this->getMockBuilder(ServerRequestInterface::class)->disableOriginalConstructor()->getMock();
        $mockRequest
            ->expects($this->once())->method('getHeader')->with('Authorization')->willReturn(['Bearer ' . $token]);

        $this->assertEquals($token, $auth->fetchToken($mockRequest));
    }

    /**
     * Test validating a valid JWT.
     */
    public function testValidate()
    {
        $encoded = JWT::encode(['data' => 'value'], 'secret', 'HS256');

        $auth = new JwtAuthentication($this->ci, [
            'environment' => [],
            'secret'      => 'secret',
            'algorithm'   => ['HS256'],
        ]);

        $this->assertTrue($auth->validate($encoded));
    }

    /**
     * Test validating an invalid JWT.
     */
    public function testValidateInvalid()
    {
        $encoded = 'invalid-token';

        $auth = new JwtAuthentication($this->ci, [
            'environment' => [],
            'secret'      => 'secret',
            'algorithm'   => ['HS256'],
        ]);

        $this->assertFalse($auth->validate($encoded));
    }
}
