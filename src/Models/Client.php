<?php

namespace BlessingSkin\AuthService\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class Client extends Model
{
    /**
     * 与模型关联的数据表
     *
     * @var string
     */
    protected $table = 'oauth_clients';

    /**
     * 可批量赋值的属性
     *
     * @var array
     */
    protected $fillable = [
        'user_id',
        'name',
        'redirect_uri',
    ];

    /**
     * 模型的启动方法
     *
     * @return void
     */
    protected static function boot()
    {
        parent::boot();

        static::creating(function ($client) {
            $client->client_id = Str::random(40);
            $client->client_secret = Str::random(100);
        });
    }

    /**
     * 获取拥有此客户端的用户
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * 获取此客户端的授权码
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function authCodes()
    {
        return $this->hasMany(AuthCode::class);
    }

    /**
     * 获取此客户端的访问令牌
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function tokens()
    {
        return $this->hasMany(Token::class);
    }
}
