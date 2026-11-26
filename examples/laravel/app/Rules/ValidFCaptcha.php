<?php

namespace App\Rules;

use App\Exceptions\VerificationUnavailable;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

class ValidFCaptcha implements ValidationRule
{
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $secret = config('services.fcaptcha.verify_secret');

        if (! is_string($secret) || $secret === '') {
            throw new VerificationUnavailable('FCAPTCHA_VERIFY_SECRET is not configured.');
        }

        try {
            $response = Http::asForm()
                ->timeout(5)
                ->withoutRedirecting()
                ->post(config('services.fcaptcha.origin').'/turnstile/v0/siteverify', [
                    'secret' => $secret,
                    'response' => $value,
                ]);
        } catch (ConnectionException $exception) {
            throw new VerificationUnavailable('FCaptcha verification is unavailable.', 0, $exception);
        }

        $result = $response->json();
        if (! $response->successful() || ! is_array($result) || ! is_bool($result['success'] ?? null)) {
            throw new VerificationUnavailable('FCaptcha returned an invalid response.');
        }

        if ($result['success'] !== true
            || ($result['hostname'] ?? null) !== config('services.fcaptcha.expected_hostname')
            || ($result['action'] ?? null) !== 'contact') {
            $fail('Verification failed. Please try again.');
        }
    }
}
