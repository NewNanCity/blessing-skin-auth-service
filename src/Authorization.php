<?php

namespace BlessingSkin\OAuth;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;

/**
 * OAuth 用户授权模型
 * 
 * 此模型表示用户对 OAuth 客户端的授权
 * 当用户授权一个客户端时，会创建一条授权记录
 * 用户可以随时撤销授权
 */
class Authorization extends Model
{
    /**
     * 与模型关联的数据表
     *
     * @var string
     */
    protected $table = 'oauth_authorizations';

    /**
     * 可批量赋值的属性
     *
     * @var array
     */
    protected $fillable = [
        'user_id',
        'client_id',
    ];

    /**
     * 获取拥有此授权的用户
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * 获取此授权关联的客户端
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function client()
    {
        return $this->belongsTo(Client::class);
    }
}
