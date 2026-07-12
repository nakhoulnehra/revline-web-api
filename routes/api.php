<?php

use App\Http\Controllers\Auth\AuthenticatedSessionController;
use App\Http\Controllers\Auth\CurrentUserController;
use App\Http\Controllers\Auth\LogoutController;
use App\Http\Controllers\Auth\RegisteredUserController;
use Illuminate\Support\Facades\Route;

Route::post('/register', RegisteredUserController::class)
    ->middleware('throttle:registration')
    ->name('register');

Route::post('/login', AuthenticatedSessionController::class)
    ->name('login');

Route::middleware('auth:sanctum')->group(function () {
    Route::get('/user', CurrentUserController::class)
        ->name('user');

    Route::post('/logout', LogoutController::class)
        ->name('logout');
});
