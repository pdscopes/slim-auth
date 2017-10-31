<?php

namespace MadeSimple\Slim\Middleware\Tests\Unit\Authentication;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use Slim\Http\Request;
use Slim\Middleware\Authentication\JwtAuthentication;

class JwtAuthenticationTest extends TestCase
{
    /**
     * @var \Psr\Container\ContainerInterface
     */
    protected $ci;

    /**
     * @InheritDoc
     */
    protected function setUp()
    {
        parent::setUp();

        $this->ci = new \Slim\Container();
    }

    /**
     * Test that construct without options has all default values.
     */
    public function testConstructWithoutOptions()
    {
        $auth = new JwtAuthentication($this->ci, []);

        $reflection = new \ReflectionClass($auth);
        $options    = $reflection->getProperty('options');
        $options->setAccessible(true);

        $this->assertEquals([
            'secure'      => true,
            'relaxed'     => ['localhost', '127.0.0.1'],
            'environment' => ['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'],
            'header'      => 'Authorization',
            'regex'       => '/Bearer\s+(.*)$/i',
            'cookie'      => 'X-Auth',
            'payload'     => null,
            'attribute'   => 'token',
            'logger'      => null,
            'secret'      => '',
            'algorithm'   => ['HS256', 'HS512', 'HS384'],
        ], $options->getValue($auth));
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
            'regex'       => '/Bearer\s+(.*)$/i',
            'cookie'      => 'X-Auth',
            'payload'     => null,
            'attribute'   => 'token',
            'logger'      => null,
            'secret'      => null,
            'algorithm'   => ['HS256', 'HS512', 'HS384'],
        ];
        $expected[$option] = $value;

        $reflection = new \reflectionclass($auth);
        $options    = $reflection->getproperty('options');
        $options->setaccessible(true);

        $this->assertEquals($expected, $options->getValue($auth));
    }
    public function constructWithOptionsProvider()
    {
        return [
            ['secure', false],
            ['relaxed', ['relaxed.com']],
            ['environment', ['ENVIRONMENT_VARIABLE']],
            ['header', 'x-header'],
            ['regex', 'regex pattern'],
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
        $encoded = JWT::encode(['data' => 'value'], 'secret', 'HS256');
        $token   = 'Bearer ' . $encoded;
        $auth    = new JwtAuthentication($this->ci, [
            'environment' => [],
            'secret'      => 'secret',
            'algorithm'   => ['HS256'],
        ]);

        $mockRequest = $this->getMockBuilder(Request::class)->disableOriginalConstructor()->getMock();
        $mockRequest
            ->expects($this->once())->method('getHeader')->with('Authorization')->willReturn([$token]);

        $this->assertEquals(JWT::decode($encoded, 'secret', ['HS256']), $auth->fetchToken($mockRequest));
    }

    /**
     * Test fetching an invalid JWT.
     */
    public function testFetchTokenInvalid()
    {
        $encoded = 'invalid token';
        $token   = 'Bearer ' . $encoded;
        $auth    = new JwtAuthentication($this->ci, [
            'environment' => [],
            'secret'      => 'secret',
            'algorithm'   => ['HS256'],
        ]);

        $mockRequest = $this->getMockBuilder(Request::class)->disableOriginalConstructor()->getMock();
        $mockRequest
            ->expects($this->once())->method('getHeader')->with('Authorization')->willReturn([$token]);

        $this->assertEquals('', $auth->fetchToken($mockRequest));
    }

    /**
     * Test validating an already parsed JWT.
     */
    public function testValidate()
    {
        $auth = new JwtAuthentication($this->ci, []);

        $this->assertTrue($auth->validate(new \stdClass));
        $this->assertFalse($auth->validate(''));
    }
}