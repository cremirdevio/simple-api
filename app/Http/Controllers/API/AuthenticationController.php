<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthenticationController extends Controller
{
    public function login(Request $request)
    {
        $validated = $request->validate([
            'username' => 'required|email|max:255',
            'password' => 'required|min:8',
        ]);

        $user = \App\Models\User::where('username', $request->username)->first();

        if (is_null($user)) {
            abort(400, 'You don\'t have an account with us');
        }

        $user->tokens()->delete();

        if (! $user || ! Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        return $user->createToken($request->username)->plainTextToken;
    }
}
