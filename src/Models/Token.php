<?php

namespace BlessingSkin\OAuth\Models;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;

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
