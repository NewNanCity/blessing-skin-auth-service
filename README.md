# BlessingSkin Auth 服务

这个插件为 BlessingSkin 添加了 OAuth 2.0、OpenID Connect (OIDC) 和 SAML 2.0 服务提供者功能，允许第三方应用通过 OAuth 协议获取用户授权并访问用户信息，通过 OIDC 协议验证用户身份，或通过 SAML 协议实现单点登录。

## 功能特点

- 支持 OAuth 2.0 的所有授权模式：
  - 授权码模式（Authorization Code Grant）
  - 隐式授权模式（Implicit Grant）
  - 客户端凭证模式（Client Credentials Grant）
  - 资源所有者密码凭证模式（Resource Owner Password Credentials Grant）
  - 刷新令牌模式（Refresh Token Grant）
- 支持 OpenID Connect (OIDC) 标准
- 支持 SAML 2.0 单点登录
- 使用 JWT (JSON Web Token) 作为访问令牌和 ID 令牌
- 提供用户信息 API 端点
- 管理员可以创建和管理 OAuth 应用
- 用户可以查看和管理自己授权过的应用

## 安装方法

1. 下载此插件的 ZIP 压缩包
2. 将压缩包上传到 BlessingSkin 的 `plugins` 目录下
3. 解压压缩包
4. 在 BlessingSkin 的管理面板中启用插件

## 使用方法

### 管理员

1. 登录到 BlessingSkin 管理面板
2. 点击 "OAuth 应用管理" 菜单
3. 点击 "创建应用" 按钮
4. 填写应用名称、重定向 URI 和应用描述
5. 提交后，您将获得客户端 ID 和客户端密钥
6. 您可以随时编辑或删除应用

### 用户

1. 登录到 BlessingSkin
2. 在用户中心点击 "应用授权管理" 菜单
3. 查看您已授权的应用列表
4. 如需撤销授权，点击对应应用旁的 "撤销授权" 按钮

### 开发者

#### 申请应用

1. 联系皮肤站管理员申请创建 OAuth 应用
2. 提供应用名称、重定向 URI 和应用描述
3. 获取客户端 ID 和客户端密钥

#### OAuth/OIDC 端点

- 授权端点：`/oauth/authorize`
- 令牌端点：`/oauth/token`
- 用户信息端点：`/oauth/userinfo`
- OIDC 配置端点：`/.well-known/openid-configuration`
- JWKS 端点：`/oauth/jwks`

#### SAML 端点

- SAML 元数据端点：`/saml/metadata`
- SAML 登录端点：`/saml/login`
- SAML 断言消费服务（ACS）端点：`/saml/acs`
- SAML 单点登出（SLO）端点：`/saml/slo`

#### 授权流程

##### 授权码模式（Authorization Code Grant）

1. 引导用户访问授权页面：
```
https://你的皮肤站地址/oauth/authorize?client_id=CLIENT_ID&redirect_uri=REDIRECT_URI&response_type=code&state=STATE&scope=profile
```

2. 用户授权后，服务器会重定向到您的 `redirect_uri`，并附带授权码：
```
https://你的应用地址/callback?code=AUTHORIZATION_CODE&state=STATE
```

3. 使用授权码获取访问令牌：
```http
POST /oauth/token HTTP/1.1
Host: 你的皮肤站地址
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&code=AUTHORIZATION_CODE&redirect_uri=REDIRECT_URI
```

##### 隐式授权模式（Implicit Grant）

1. 引导用户访问授权页面，使用 `response_type=token`：
```
https://你的皮肤站地址/oauth/authorize?client_id=CLIENT_ID&redirect_uri=REDIRECT_URI&response_type=token&state=STATE&scope=profile
```

2. 用户授权后，服务器会重定向到您的 `redirect_uri`，并在URL片段中附带访问令牌：
```
https://你的应用地址/callback#access_token=ACCESS_TOKEN&token_type=Bearer&expires_in=3600&state=STATE
```

##### 客户端凭证模式（Client Credentials Grant）

```http
POST /oauth/token HTTP/1.1
Host: 你的皮肤站地址
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&scope=profile
```

##### 资源所有者密码凭证模式（Resource Owner Password Credentials Grant）

```http
POST /oauth/token HTTP/1.1
Host: 你的皮肤站地址
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&username=USER_EMAIL&password=USER_PASSWORD&scope=profile
```

##### 刷新令牌模式（Refresh Token Grant）

```http
POST /oauth/token HTTP/1.1
Host: 你的皮肤站地址
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&refresh_token=REFRESH_TOKEN
```

##### 使用访问令牌获取用户信息

```http
GET /oauth/userinfo HTTP/1.1
Host: 你的皮肤站地址
Authorization: Bearer ACCESS_TOKEN
```

#### 用户信息响应

```json
{
  "id": 123,
  "email": "user@example.com",
  "nickname": "用户昵称",
  "score": 100,
  "avatar": "avatar_url",
  "permission": 1,
  "verified": true,
  "register_at": "2023-01-01T00:00:00+00:00"
}
```

## 配置选项

管理员可以在插件配置页面设置以下选项：

- **访问令牌有效期**：访问令牌的有效期，单位为分钟，默认为 60 分钟
- **刷新令牌有效期**：刷新令牌的有效期，单位为天，默认为 30 天

## 安全性

- 所有 OAuth 应用由管理员创建和管理，确保只有可信的应用才能使用 OAuth 服务
- 用户可以随时查看和撤销授权，保持对自己账户的控制
- 访问令牌有限的有效期，过期后需要使用刷新令牌获取新的访问令牌
- 所有令牌都存储在数据库中，可以被撤销

## 许可证

MIT License
