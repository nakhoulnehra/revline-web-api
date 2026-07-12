<?php

use App\Http\Controllers\Auth\AuthenticatedSessionController;
use App\Http\Controllers\Auth\RegisteredUserController;
use Illuminate\Support\Facades\Route;

Route::post('/register', RegisteredUserController::class)
    ->middleware('throttle:registration')
    ->name('register');

Route::post('/login', AuthenticatedSessionController::class)
    ->name('login');
