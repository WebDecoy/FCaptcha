<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class ContactTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('services.fcaptcha.origin', 'https://captcha.example');
        config()->set('services.fcaptcha.site_key', 'laravel-demo');
        config()->set('services.fcaptcha.verify_secret', 'test-verification-secret');
        config()->set('services.fcaptcha.expected_hostname', '127.0.0.1');
    }

    public function test_valid_token_accepts_submission(): void
    {
        Http::fake(['captcha.example/*' => Http::response([
            'success' => true,
            'hostname' => '127.0.0.1',
            'action' => 'contact',
        ])]);

        $this->post('/', ['message' => 'Example', 'fcaptcha_token' => 'signed-token'])
            ->assertOk()
            ->assertSee('Sample accepted');

        Http::assertSent(fn ($request) => $request->url() === 'https://captcha.example/turnstile/v0/siteverify'
            && $request['secret'] === 'test-verification-secret'
            && $request['response'] === 'signed-token'
        );
    }

    public function test_replayed_token_is_rejected(): void
    {
        Http::fakeSequence()
            ->push(['success' => true, 'hostname' => '127.0.0.1', 'action' => 'contact'])
            ->push(['success' => false, 'error-codes' => ['invalid-input-response']]);

        $payload = ['message' => 'Example', 'fcaptcha_token' => 'single-use-token'];
        $this->post('/', $payload)->assertOk();
        $this->from('/')->post('/', $payload)
            ->assertRedirect('/')
            ->assertSessionHasErrors('fcaptcha_token');
    }

    public function test_missing_token_never_calls_verifier(): void
    {
        Http::fake();

        $this->from('/')->post('/', ['message' => 'Example'])
            ->assertRedirect('/')
            ->assertSessionHasErrors('fcaptcha_token');

        Http::assertNothingSent();
    }

    public function test_wrong_hostname_or_action_is_rejected(): void
    {
        foreach ([
            ['success' => true, 'hostname' => 'other.example', 'action' => 'contact'],
            ['success' => true, 'hostname' => '127.0.0.1', 'action' => 'login'],
        ] as $result) {
            Http::fake(['captcha.example/*' => Http::response($result)]);
            $this->from('/')->post('/', ['message' => 'Example', 'fcaptcha_token' => 'token'])
                ->assertRedirect('/')
                ->assertSessionHasErrors('fcaptcha_token');
        }
    }

    public function test_verifier_failure_fails_closed(): void
    {
        Http::fake(['captcha.example/*' => Http::response('upstream error', 500)]);

        $this->post('/', ['message' => 'Example', 'fcaptcha_token' => 'token'])
            ->assertStatus(503);
    }

    public function test_secret_is_not_rendered(): void
    {
        $this->get('/')
            ->assertOk()
            ->assertDontSee('test-verification-secret')
            ->assertSee('https://captcha.example/fcaptcha.js', false);
    }
}
