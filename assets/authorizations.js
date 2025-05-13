/**
 * BlessingSkin OAuth 用户授权管理页面脚本
 */
blessing.event.on('mounted', () => {
  // 撤销授权
  document.querySelectorAll('.revoke-authorization').forEach(button => {
    button.addEventListener('click', async function() {
      const id = this.dataset.id;
      
      if (!confirm(blessing.i18n['blessing-skin-auth-service'].user.confirmRevoke)) return;
      
      try {
        const response = await blessing.fetch.delete(`user/oauth/authorizations/${id}`);
        
        if (response.code === 0) {
          blessing.notify.toast.success(response.message);
          setTimeout(() => window.location.reload(), 1000);
        } else {
          blessing.notify.toast.error(response.message);
        }
      } catch (error) {
        blessing.notify.toast.error(blessing.i18n.general.networkError);
      }
    });
  });
});
