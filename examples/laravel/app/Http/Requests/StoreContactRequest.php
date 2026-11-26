<?php

namespace App\Http\Requests;

use App\Rules\ValidFCaptcha;
use Illuminate\Foundation\Http\FormRequest;

class StoreContactRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'message' => ['required', 'string', 'max:2000'],
            'fcaptcha_token' => ['bail', 'required', 'string', 'max:8192', new ValidFCaptcha],
        ];
    }
}
