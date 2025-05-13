/**
 * BlessingSkin OAuth 插件配置页面脚本
 */
blessing.event.on('mounted', () => {
  // 生成新的JWT密钥
  document.querySelector('.btn-generate-key')?.addEventListener('click', async function() {
    if (!confirm(blessing.i18n.general.confirm)) return;

    const button = this;
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = `${blessing.i18n.general.processing}...`;

    try {
      const response = await blessing.fetch.post('api/admin/oauth/keys');

      if (response.code === 0) {
        blessing.notify.toast.success(response.message);
      } else {
        blessing.notify.toast.error(response.message);
      }
    } catch (error) {
      blessing.notify.toast.error(blessing.i18n.general.networkError);
    } finally {
      button.disabled = false;
      button.textContent = originalText;
    }
  });

  // 清理过期和已撤销的令牌
  document.querySelector('.btn-cleanup-tokens')?.addEventListener('click', async function() {
    if (!confirm(blessing.i18n.general.confirm)) return;

    const button = this;
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = `${blessing.i18n.general.processing}...`;

    try {
      const response = await blessing.fetch.post('api/admin/oauth/cleanup');

      if (response.code === 0) {
        blessing.notify.toast.success(response.message);

        // 显示详细统计信息
        if (response.data) {
          let details = '';
          for (let key in response.data) {
            if (key !== 'total') {
              details += key.replace(/_/g, ' ') + ': ' + response.data[key] + '<br>';
            }
          }
          if (details) {
            blessing.notify.toast.info(details, {
              title: blessing.i18n['blessing-skin-auth-service'].config.jwt.cleanupDetails,
              timeOut: 10000
            });
          }
        }
      } else {
        blessing.notify.toast.error(response.message);
      }
    } catch (error) {
      blessing.notify.toast.error(blessing.i18n.general.networkError);
    } finally {
      button.disabled = false;
      button.textContent = originalText;
    }
  });



  // 生成SAML证书
  document.querySelector('.btn-generate-saml-cert')?.addEventListener('click', async function() {
    if (!confirm(blessing.i18n.general.confirm)) return;

    const button = this;
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = `${blessing.i18n.general.processing}...`;

    try {
      const response = await blessing.fetch.post('api/admin/oauth/saml-certificate');

      if (response.code === 0) {
        blessing.notify.toast.success(response.message);
        // 刷新页面以显示新证书
        setTimeout(() => window.location.reload(), 1500);
      } else {
        blessing.notify.toast.error(response.message);
      }
    } catch (error) {
      blessing.notify.toast.error(blessing.i18n.general.networkError);
    } finally {
      button.disabled = false;
      button.textContent = originalText;
    }
  });

  // 生成新密钥后刷新页面以显示新密钥
  document.querySelector('.btn-generate-key')?.addEventListener('click', function() {
    if (this.getAttribute('data-clicked') === 'true') {
      return;
    }

    this.setAttribute('data-clicked', 'true');
    setTimeout(() => {
      window.location.reload();
    }, 1500);
  });
});
