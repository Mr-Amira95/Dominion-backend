<?php

use App\Http\Controllers\SteamAuthController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::prefix('auth/steam')->name('steam.')->group(function () {
    Route::get('/', [SteamAuthController::class, 'redirect'])->name('login');
    Route::get('/callback', [SteamAuthController::class, 'callback'])->name('callback');
});
