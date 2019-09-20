<?php

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

$router->group(['prefix' => 'api/v1'], function ($router) {
    // Users
    $router->post('user/register', 'UserController@register');
    $router->post('user/login', ['uses' => 'UserController@login']);
    $router->post('user/forgot_password', 'UserController@ForgotPassword');
    $router->post('user/new_password', 'UserController@newPassword');
    $router->post('receiveotp', 'UserController@receiveOTP');
    $router->post('activate', 'UserController@ActivateKey');
    $router->post('againactivate', 'UserController@againActivate');
    $router->post('againotp', 'UserController@againOTP');
});

$router->get('/get', 'UserController@decrypt');

$router->group(['prefix' => 'api/v1', 'middleware' => 'jwt.auth'], function ($router) {
    $router->post('test', 'UserController@MakeData');
});
