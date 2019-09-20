<?php

namespace App\Http\Controllers;

use App\Otp;
use App\Users;
use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Mail;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Laravel\Lumen\Routing\Controller as BaseController;
use Blocktrail\CryptoJSAES\CryptoJSAES;
use LogicException;

class UserController extends BaseController
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    { }
    /*
    |--------------------------------------------------------------------------
    | Api สมัครสมาชิก
    |--------------------------------------------------------------------------
     */
    public function register(Request $request)
    {
        // validator
        $validator = Validator::make($request->all(), [
            'first_name' => 'required',
            'last_name' => 'required',
            'mobile' => 'required',
            'password' => 'required',
            'confirm_password' => 'required',
            'email' => 'required',
            'username' => 'required',
            'sub_email' => ''
        ]);

        //validator Phone
        $validator_phone = Validator::make($request->all(), [
            'mobile' => 'required|digits_between:9,10',
        ]);

        //validator password
        $validator_pass = Validator::make($request->all(), [
            'password' => 'required|min:8|max:20',
            'confirm_password' => 'required',
        ]);

        //validator unique
        $validator_unique = Validator::make($request->all(), [
            'email' => 'required|email|unique:users',
            'username' => 'required|unique:users',
        ]);

        if ($validator->fails()) {
            $errors = $validator->errors();
            return $this->responseRequestError('error', $errors);
        }

        if ($validator_unique->fails()) {
            $errors_u = $validator_unique->errors();
            return $this->responseRequestError('same_data', $errors_u);
        }
        //validator password
        if ($validator_pass->fails()) {
            $errors_p = $validator_pass->errors();
            return $this->responseRequestError('not_rule_pass', $errors_p);
        }

        //validator Phone
        if ($validator_phone->fails()) {
            $errors_ph = $validator_phone->errors();
            return $this->responseRequestError('not_rule_phone', $errors_ph);
        }

        if ($request->password == $request->confirm_password) {


            $user = new Users();
            $user->first_name = $request->first_name;
            $user->last_name = $request->last_name;
            $user->email = $request->email;
            $user->mobile = $request->mobile;
            $user->username = $request->username;
            $user->password = Hash::make($request->password);
            $user->activate_key = encrypt($request->email);
            $user->subscribe_email = $request->sub_email;

            if ($user->save()) {

                $token = $this->jwt($user);
                $user['token'] = $token;

                $template_html = 'mail.activate_user';

                $template_data = [
                    'url_activate' => url('http://localhost/sms_mkt/activated.php?key=' . encrypt($request->email) . '&user=' . $request->username),

                ];

                Mail::send($template_html, $template_data, function ($msg) use ($user) {
                    $msg->subject('ยืนยันตัวตน === Activate');
                    $msg->to([$user->email]);
                    $msg->from('dviver100@gmail.com', 'ClickNext');
                });
                return $this->responseRequestSuccess($user);
            } else {
                return $this->responseRequestError('error');
            }
        } else {
            return $this->responseRequestError('pass_not_same');
        }
    }
    /*
    |--------------------------------------------------------------------------
    | Api เข้าสู่ระบบ
    |--------------------------------------------------------------------------
     */
    public function login(Request $request)
    {
        // validator
        $validator = Validator::make($request->all(), [
            'username' => 'required',
            'password' => 'required',
        ]);
        if ($validator->fails()) {
            $errors = $validator->errors();
            return $this->responseRequestError($errors);
        }

        $user = Users::where('username', $request->username)->first();

        if ($user) {

            if (Hash::check($request->password, $user->password)) {

                if ($user['is_active'] == true) {

                    $token = $this->jwt($user);
                    $user->token = $token;
                    $user->last_login_date = Carbon::now();
                    $user->save();
                    return $this->responseRequestSuccess($user);
                } else {
                    return $this->responseRequestError('no_activate', $user);
                }
            } else {
                return $this->responseRequestError('wrong_pass');
            }
        } else {
            return $this->responseRequestError('wrong_pass');
        }
    }
    /*
    |--------------------------------------------------------------------------
    | Api ลืม password
    |--------------------------------------------------------------------------
     */
    public function ForgotPassword(Request $request)
    {
        // validator
        $validator = Validator::make($request->all(), [
            'username' => 'required',
        ]);
        if ($validator->fails()) {
            $errors = $validator->errors();
            return $this->responseRequestError($errors);
        }

        $user = Users::where('username', $request->username)->first();

        if ($user) {

            //if actived
            if ($user = Users::where('username', $request->username)->where('is_active', true)->first()) {

                $template_html = 'mail.forgot_password';

                // Create OTP
                $genREF = $this->strRandom_ref();
                $genOTP = $this->strRandom_otp();

                $template_data = [

                    'ref' => $genREF,
                    'otp' => $genOTP
                ];
                $otp = new Otp();
                $otp->username = $request->username;
                $otp->ref = $genREF;
                $otp->otp = $genOTP;

                if ($otp->save()) {
                    Mail::send($template_html, $template_data, function ($msg) use ($user) {
                        $msg->subject('ลืมรหัสผ่าน === Forgot');
                        $msg->to([$user->email]);
                        $msg->from('dviver100@gmail.com', 'ClickNext');
                    });

                    $info = [
                        'email' => encrypt($user->email),
                        'username' => encrypt($user->username),
                        'ref' => encrypt($otp->ref)
                    ];

                    return $this->responseRequestSuccess($info);
                }
            } else {
                //not active
                return $this->responseRequestError('no_activate');
            }
        } else {
            return $this->responseRequestError('error');
        }
    }
    /*
    |--------------------------------------------------------------------------
    | Activate again
    |--------------------------------------------------------------------------
     */
    public function againActivate(Request $request)
    {
        $template_html = 'mail.activate_user';

        $template_data = [
            'url_activate' => url('http://localhost/sms_mkt/activated.php?key=' . encrypt($request->email) . '&user=' . $request->username),

        ];

        $user = new Users();
        $user->email = $request->email;

        Mail::send($template_html, $template_data, function ($msg) use ($user) {
            $msg->subject('ยืนยันตัวตน === Activate');
            $msg->to([$user->email]);
            $msg->from('dviver100@gmail.com', 'ClickNext');
        });
        return $this->responseRequestSuccess('Success!');
    }
    /*
    |--------------------------------------------------------------------------
    | OTP again
    |--------------------------------------------------------------------------
     */
    public function againOTP(Request $request)
    {
        $template_html = 'mail.forgot_password';

        // Create OTP
        $genREF = $this->strRandom_ref();
        $genOTP = $this->strRandom_otp();

        $user = Users::where('username', decrypt($request->username))->first();

        $template_data = [

            'ref' => $genREF,
            'otp' => $genOTP
        ];
        $otp = new Otp();
        $otp->username = decrypt($request->username);
        $otp->ref = $genREF;
        $otp->otp = $genOTP;

        if ($otp->save()) {
            Mail::send($template_html, $template_data, function ($msg) use ($user) {
                $msg->subject('ลืมรหัสผ่าน === Forgot');
                $msg->to([$user->email]);
                $msg->from('dviver100@gmail.com', 'ClickNext');
            });

            $info = [
                'email' => encrypt($user->email),
                'username' => encrypt($user->username),
                'ref' => encrypt($otp->ref)
            ];

            return $this->responseRequestSuccess($info);
        }
    }
    /*
    |--------------------------------------------------------------------------
    | receiveOTP
    |--------------------------------------------------------------------------
     */
    public function receiveOTP(Request $request)
    {
        $validate = Validator::make($request->all(), [

            'ref' => 'required',
            'otp' => 'required'
        ]);

        if ($validate->fails()) {
            throw new LogicException($validate->errors()->first());
        }

        $userOTP = Otp::where('otp', $request->otp)->where('ref', decrypt($request->ref))->first();

        if ($userOTP) {

            return $this->responseRequestSuccess('Success!');
        } else {
            return $this->responseRequestError('error');
        }
    }
    /*
    |--------------------------------------------------------------------------
    | Api new password ใหม่
    |--------------------------------------------------------------------------
     */
    public function newPassword(Request $request)
    {
        try {
            $validate = Validator::make($request->all(), [
                'username' => 'required',
                'password' => 'required|min:8|max:20',
                'confirm_password' => 'required'
            ]);
            if ($validate->fails()) {

                return $this->responseRequestError('error');
            }

            if ($user = Users::where('username', decrypt($request->username))->first()) {

                if ($request->password == $request->confirm_password) {


                    $user->password = Hash::make($request->password);

                    if ($user->save()) {

                        return $this->responseRequestSuccess('Success!');
                    }
                } else {

                    return $this->responseRequestError('pass_not_same');
                }
            } else {
                return $this->responseRequestError('error');
            }
        } catch (DecryptException $e) {
            return 'ไม่พบข้อมูล';
        }
    }
    /*
    |--------------------------------------------------------------------------
    | Api Activated Key
    |--------------------------------------------------------------------------
     */
    public function ActivateKey(Request $request)
    {
        try {
            $validate = Validator::make($request->all(), [
                'key' => 'required',
                'user' => 'required',
            ]);
            if ($validate->fails()) {
                throw new LogicException($validate->errors()->first());
            }

            $user = Users::where('username', $request->user)->first();

            if (decrypt($request->key) == $user->email) {
                $user->is_active = true;

                if ($user->save()) {

                    return $this->responseRequestSuccess('Success!');
                }
            }
        } catch (DecryptException $e) {
            return 'ไม่พบข้อมูล';
        }
    }
    /*
    |--------------------------------------------------------------------------
    | ตัวเข้ารหัส JWT
    |--------------------------------------------------------------------------
     */
    protected function jwt($user)
    {
        $payload = [
            'iss' => "lumen-jwt", // Issuer of the token
            'sub' => $user->id, // Subject of the token
            'iat' => time(), // Time when JWT was issued.
            'exp' => time() + env('JWT_EXPIRE_HOUR') * 60 * 60, // Expiration time
        ];
        return JWT::encode($payload, env('JWT_SECRET'));
    }
    /*
    |--------------------------------------------------------------------------
    | response เมื่อข้อมูลส่งถูกต้อง
    |--------------------------------------------------------------------------
     */
    protected function responseRequestSuccess($ret)
    {
        return response()->json(['status' => 'success', 'data' => $ret], 200)
            ->header('Access-Control-Allow-Origin', '*')
            ->header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    }
    /*
    |--------------------------------------------------------------------------
    | response เมื่อข้อมูลมีการผิดพลาด
    |--------------------------------------------------------------------------
     */
    protected function responseRequestError($status = '', $ret = '', $message = 'Bad request', $statusCode = 200)
    {
        return response()->json(['status' => $status, 'data' => $ret, 'error' => $message], $statusCode)
            ->header('Access-Control-Allow-Origin', '*')
            ->header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    }
    /*
    |--------------------------------------------------------------------------
    | function สำหรับ Random String
    |--------------------------------------------------------------------------
     */
    protected function strRandom_ref($length = 6)
    {
        return substr(str_shuffle('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, $length);
    }
    /*
    |--------------------------------------------------------------------------
    | function สำหรับ Random OTP
    |--------------------------------------------------------------------------
     */
    protected function strRandom_otp($length = 6)
    {
        return substr(str_shuffle('0123456789'), 0, $length);
    }
    /*
    |--------------------------------------------------------------------------
    | function สำหรับ encrypt
    |--------------------------------------------------------------------------
     */
    protected function encrypt($key)
    {
        $passphrase = "my passphrase";

        return CryptoJSAES::encrypt($key, $passphrase);
    }
    /*
    |--------------------------------------------------------------------------
    | function สำหรับ decrypt
    |--------------------------------------------------------------------------
     */
    protected function decrypt($key)
    {
        $passphrase = "my passphrase";

        return CryptoJSAES::decrypt($key, $passphrase);
    }

    public function MakeData(Request $request)
    {
        header("Access-Control-Allow-Origin: *");
        header("Access-Control-Allow-Methods: GET");
        header("Access-Control-Allow-Headers: Origin, Methods, Content-Type");
        return response()->json([
            'data' => $request->auth
        ]);
    }
}
