<?php

namespace App\Http\Controllers\API;

use App\Actions\Fortify\CreateNewUser;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\ValidationException;

class AuthenticationController extends Controller
{
    public function login(Request $request)
    {
        $validated = $request->validate([
            'username' => ['required', 'string', 'max:255'],
            'password' => ['required', 'string', 'min:8'],
        ]);

        $user = \App\Models\User::where('username', $request->username)->first();

        if (is_null($user)) {
            abort(404, 'You don\'t have an account with us');
        }

        $user->tokens()->delete();

        if (! $user || ! Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $token = $user->createToken($request->username)->plainTextToken;

        return response()->json([
            "message" => "Login Successful",
            "authToken" => $token
        ]);
    }

    public function logout()
    {
        $user = auth()->user();
        $user->tokens()->delete();
        return response()->json([
            "message" => "Logged out successfully"
        ], 200);
    }

    public function register(Request $request)
    {
        $user = (new CreateNewUser)->create($request->all());

        return response()->json([], 204);
    }
}
