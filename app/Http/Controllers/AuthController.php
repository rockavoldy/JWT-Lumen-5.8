<?php

namespace App\Http\Controllers;

use Validator;
use App\Student;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Firebase\JWT\ExpiredException;
use Illuminate\Support\Facades\Hash;
use Laravel\Lumen\Routing\Controller as BaseController;

class AuthController extends BaseController
{
    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request
     */
    private $request;
    /**
     * Create a new controller instance.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }
    /**
     * Create a new token.
     * 
     * @param  \App\Student   $user
     * @return string
     */
    protected function jwt(Student $user)
    {
        $payload = [
            'iss' => "akhmadid-jwt", // Issuer of the token
            'sub' => $user->id, // Subject of the token
            'iat' => time(), // Time when JWT was issued. 
            'exp' => time() + 60 * 60 // Expiration time
        ];

        // As you can see we are passing `JWT_SECRET` as the second parameter that will 
        // be used to decode the token in the future.
        return JWT::encode($payload, env('JWT_SECRET'));
    }
    /**
     * Authenticate a user and return the token if the provided credentials are correct.
     * 
     * @param  \App\Student   $user 
     * @return mixed
     */
    public function authenticate(Student $user)
    {
        $this->validate($this->request, [
            'email'     => 'required|email',
            'password'  => 'required'
        ]);
        // cari email
        $user = Student::where('email', $this->request->input('email'))->first();
        if (!$user) {
            // jika email tidak ada
            return response()->json([
                'status' => 400,
                'error' => 'Email tidak ada.'
            ], 400);
        }
        // cek password setelah email benar ada dalam database
        if (Hash::check($this->request->input('password'), $user->password)) {
            return response()->json([
                'status' => 200,
                'token' => $this->jwt($user)
            ], 200);
        }

        return response()->json([
            'status' => 400,
            'error' => 'Email atau password salah.'
        ], 400);
    }

    public function register(Request $request)
    {
        // validasi form post
        $this->validate($request, [
            'name' => 'required',
            'nim' => 'bail|required|unique:students,nim',
            'email' => 'bail|required|email|unique:students,email',
            'password' => 'required',
            'confirm_password' => 'required|same:password'
        ], [
            'required' => 'Kolom :attribute harus ada.',
            'email' => ':input bukan format email yang valid.',
            'unique' => 'Akun dengan :attribute: :input sudah ada, gunakan lupa password untuk set ulang password anda.',
            'same' => 'Password tidak sama, mohon untuk dicek kembali.'
        ]);

        // jika validasi berhasil
        $user = Student::create([
            'name' => $request->name,
            'nim' => $request->nim,
            'email' => $request->email,
            'password' => password_hash($request->password, PASSWORD_BCRYPT)
        ]);

        // jika berhasil registrasi
        if ($user) {
            return response()->json([
                'status' => 200,
                'message' => 'Berhasil membuat akun baru.',
                'token' => $this->jwt($user)
            ], 200);
        }

        // gagal registrasi
        return response()->json([
            'status' => 400,
            'error' => 'Gagal membuat akun baru.'
        ], 400);
    }
}
