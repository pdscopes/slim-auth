<?php

namespace MadeSimple\Slim\Middleware\Tests\Unit\Authentication;

use MadeSimple\Slim\Middleware\Tests\TestContainer;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Slim\Middleware\Authentication\SimpleTokenAuthentication;

class SimpleTokenAuthenticationTest extends TestCase
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
            ['validate', function () {}],
        ];
    }

    /**
     * Test that validate defaults to false.
     */
    public function testValidateNotSet()
    {
        $auth = new SimpleTokenAuthentication($this->ci, []);

        $this->assertFalse($auth->validate('token'));
    }

    /**
     * Test that validate uses the callable provided.
     */
    public function testValidateWithCallable()
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
    public function testValidateWithCallableBindsContainer()
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
