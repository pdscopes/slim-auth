<?php

namespace MadeSimple\Slim\Middleware\Tests\Unit\Authentication;

use MadeSimple\Slim\Middleware\Tests\TestContainer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Slim\Middleware\Authentication\SimpleTokenAuthentication;

class SimpleTokenAuthenticationTest extends TestCase
{
    protected ContainerInterface $ci;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->ci = new TestContainer();
    }

    /**
     * Test that the class construction without options has all default values.
     */
    #[Test]
    public function constructWithoutOptions()
    {
        $auth = new SimpleTokenAuthentication($this->ci, []);

        $this->assertEquals([
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
            'validate'    => null,
            'queryparam'  => null
        ], $auth->getOptions());
    }

    /**
     * Test that construct with options overrides the default values.
     */
    #[Test]
    #[DataProvider('constructWithOptionsProvider')]
    public function constructWithOptions(string $option, mixed $value)
    {
        $auth = new SimpleTokenAuthentication($this->ci, [$option => $value]);

        $expected = [
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
            'validate'    => null,
            'queryparam'  => null
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
            ['validate', fn () => true],
        ];
    }

    /**
     * Test that "validate" defaults to false.
     */
    #[Test]
    public function validateNotSet()
    {
        $auth = new SimpleTokenAuthentication($this->ci, []);

        $this->assertFalse($auth->validate('token'));
    }

    /**
     * Test that "validate" uses the callable provided.
     */
    #[Test]
    public function validateWithCallable()
    {
        $auth = new SimpleTokenAuthentication($this->ci, [
            'validate' => function ($token) {
                return $token === 'token';
            },
        ]);

        $this->assertTrue($auth->validate('token'));
        $this->assertFalse($auth->validate('noket'));
    }

    /**
     * Test that validate properly binds the Slim container to the callable provided.
     */
    #[Test]
    public function validateWithCallableBindsContainer()
    {
        $this->ci->set('api_key', 'token');
        $auth = new SimpleTokenAuthentication($this->ci, [
            'validate' => function ($token) {
                /** @var ContainerInterface $this */
                return $token === $this->get('api_key');
            },
        ]);

        $this->assertTrue($auth->validate('token'));
    }
}
