<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\{
    User
};
use Validator;
use Hash;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $rules = array(
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|unique:users,email',
            'password' => 'required|string|min:6|confirmed',
        );

        $cek = Validator::make($request->all(),$rules);

        if($cek->fails()){
            $errorString = implode(",",$cek->messages()->all());
            return response()->json([
                'message' => $errorString
            ], 422);
        }else{
            $user = User::create([
                'name' => $request->name,
                'password' => bcrypt($request->password),
                'email' => $request->email,
            ]);
            $user->assignRole('user');
            $role = "user";
            if ($user) {
                $token = $user->createToken('token-name')->plainTextToken;

                return response()->json([
                    'status' => 'Success',
                    'role' => $role,
                    'user' => $user,
                    'token' => $token,
                    'message' => 'Berhail Membuat Akun'
                ], 200);
            }else{
                return response()->json([
                    'status' => 'Failed',
                    'message' => 'Gagal'
                ], 422);
            }
        }
    }

    public function login(Request $request)
    {
        $rules = array(
            'email' => 'required|string|email',
            'password' => 'required|string|min:8'
        );

        $cek = Validator::make($request->all(),$rules);

        if($cek->fails()){
            $errorString = implode(",",$cek->messages()->all());
            return response()->json([
                'message' => $errorString
            ], 422);
        }else{
            $user = User::where('email',$request->email)->first();

            if (!$user || !Hash::check($request->password, $user->password)) {
                return response()->json([
                    'message' => 'Unaouthorized'
                ], 401);
            }
            
            $token = $user->createToken('token-name')->plainTextToken;
            $roles = $user->getRoleNames();
          
            return response()->json([
                'status'   => 'Success',
                'message'     => 'Berhasil Login',
                'user'        => $user,
                'role'        => $roles,
                'token'       => $token
            ], 200);
        }
    }
}
