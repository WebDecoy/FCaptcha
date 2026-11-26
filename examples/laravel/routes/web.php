<?php

use App\Http\Controllers\ContactController;
use Illuminate\Support\Facades\Route;

Route::get('/', [ContactController::class, 'create'])->name('contact.create');
Route::post('/', [ContactController::class, 'store'])->name('contact.store');
