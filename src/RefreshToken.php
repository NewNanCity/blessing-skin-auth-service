<?php

namespace BlessingSkin\OAuth;

use Illuminate\Database\Eloquent\Model;

/**
 * OAuth 刷新令牌模型
 *
 * 此模型表示 OAuth 授权流程中的刷新令牌
 * 刷新令牌用于在访问令牌过期后获取新的访问令牌
 * 刷新令牌的有效期通常比访问令牌长
 */
class RefreshToken extends Model
{
    /**
     * 与模型关联的数据表
     *
     * @var string
     */
    protected $table = 'oauth_refresh_tokens';

    /**
     * 指示模型是否应该被打上时间戳
     *
     * @var bool
     */
    public $timestamps = false;

    /**
     * 可批量赋值的属性
     *
     * @var array
     */
    protected $fillable = [
        'id',
        'access_token_id',
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
     * 获取此刷新令牌关联的访问令牌
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function accessToken()
    {
        return $this->belongsTo(Token::class);
    }
}
