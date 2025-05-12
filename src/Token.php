<?php

namespace BlessingSkin\OAuth;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;

/**
 * OAuth 访问令牌模型
 *
 * 此模型表示 OAuth 授权流程中的访问令牌
 * 访问令牌用于访问受保护的资源，如用户信息
 * 访问令牌有过期时间，过期后需要使用刷新令牌获取新的访问令牌
 */
class Token extends Model
{
    /**
     * 与模型关联的数据表
     *
     * @var string
     */
    protected $table = 'oauth_access_tokens';

    /**
     * 可批量赋值的属性
     *
     * @var array
     */
    protected $fillable = [
        'id',
        'user_id',
        'client_id',
        'scopes',
        'revoked',
        'expires_at',
    ];

    /**
     * 应该被转换成原生类型的属性
     *
     * @var array
     */
    protected $casts = [
        'revoked' => 'bool',
    ];

    /**
     * 应该被转换成日期的属性
     *
     * @var array
     */
    protected $dates = [
        'expires_at',
    ];

    /**
     * 获取拥有此令牌的用户
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * 获取此令牌关联的客户端
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function client()
    {
        return $this->belongsTo(Client::class);
    }

    /**
     * 获取此令牌的刷新令牌
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function refreshTokens()
    {
        return $this->hasMany(RefreshToken::class, 'access_token_id');
    }
}
