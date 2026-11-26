<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreContactRequest;
use Illuminate\Contracts\View\View;

class ContactController extends Controller
{
    public function create(): View
    {
        return view('contact');
    }

    public function store(StoreContactRequest $request): View
    {
        $request->validated();

        // Perform the protected action here. This example stores and sends nothing.
        return view('accepted');
    }
}
