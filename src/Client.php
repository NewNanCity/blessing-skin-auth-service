<?php

namespace BlessingSkin\OAuth;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

/**
 * OAuth 客户端模型
 *
 * 此模型表示一个 OAuth 客户端应用，包含客户端 ID、密钥和重定向 URI 等信息
 * 客户端由管理员创建和管理，属于整个网站
 */
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
        'name',
        'redirect_uri',
        'description',
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

    // 移除了 user() 方法，因为客户端不再属于特定用户

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
