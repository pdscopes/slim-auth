<?php

namespace MadeSimple\Slim\Middleware\Tests\Unit\Authentication;

use MadeSimple\Slim\Middleware\Tests\GeneratesBearerStringTrait;
use MadeSimple\Slim\Middleware\Tests\TestContainer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\DataProviderExternal;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Middleware\Authentication\JwtAuthentication;

class JwtAuthenticationTest extends TestCase
{
    use GeneratesBearerStringTrait;

    protected ContainerInterface $ci;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->ci = new TestContainer();
    }

    /**
     * Test that a class construction without options has all default values.
     */
    #[Test]
    public function constructWithoutOptions()
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
            'queryparam'  => null,
        ], $auth->getOptions());
    }

    /**
     * Test that construct with options overrides the default values.
     */
    #[Test]
    #[DataProvider('constructWithOptionsProvider')]
    public function constructWithOptions(string $option, mixed $value)
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
            'secret'      => '',
            'algorithm'   => ['HS256', 'HS512', 'HS384'],
            'queryparam'  => null,
        ];
        $expected[$option] = $value;

        $this->assertEquals($expected, $auth->getOptions());
    }

    public static function constructWithOptionsProvider(): array
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
            ['logger', new \stdClass()],
            ['secret', 'JWT SECRET'],
            ['algorithm', ['ALGORITHM 1', 'ALGORITHM 2']],
        ];
    }

    /**
     * Test fetching a valid JWT.
     */
    #[Test]
    public function fetchTokenValid()
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
    #[Test]
    public function validate()
    {
        $encoded = $this->generateJwt(alg: 'HS256');

        $auth = new JwtAuthentication($this->ci, [
            'environment' => [],
            'secret'      => $this->stdKey,
            'algorithm'   => ['HS256'],
        ]);

        $this->assertTrue($auth->validate($encoded));
    }

    /**
     * Test validating an invalid JWT.
     */
    #[Test]
    public function validateInvalid()
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
