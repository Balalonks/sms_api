<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Users extends Model
{
    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $table = 'users';
    protected $fillable = [
        'id', 'username', 'password', 'email', 'first_name', 'last_name', 'email', 'mobile', 'subscribe_email', 'activate_key', 'token'
    ];
    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var array
     */
    protected $hidden = ['password'];

    protected $dates = ['is_logout', 'last_login_date', 'created_date', 'updated_date'];
}
