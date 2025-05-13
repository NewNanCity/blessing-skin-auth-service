/**
 * BlessingSkin OAuth 客户端管理页面脚本
 */
blessing.event.on('mounted', () => {
  // 切换密钥显示/隐藏
  document.querySelectorAll('.toggle-secret').forEach(button => {
    button.addEventListener('click', function() {
      const field = this.closest('.input-group').querySelector('.secret-field');
      const icon = this.querySelector('i');
      
      if (field.type === 'password') {
        field.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      } else {
        field.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      }
    });
  });
  
  // 创建客户端
  document.getElementById('create-client-submit')?.addEventListener('click', async function() {
    const form = document.getElementById('create-client-form');
    const formData = new FormData(form);
    const data = {};
    
    for (const [key, value] of formData.entries()) {
      data[key] = value;
    }
    
    try {
      const response = await blessing.fetch.post('admin/oauth/clients', data);
      
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
  
  // 打开编辑模态框
  document.querySelectorAll('.edit-client').forEach(button => {
    button.addEventListener('click', function() {
      const id = this.dataset.id;
      const name = this.dataset.name;
      const redirect = this.dataset.redirect;
      const description = this.dataset.description;
      
      document.getElementById('edit-client-id').value = id;
      document.getElementById('edit-client-name').value = name;
      document.getElementById('edit-redirect-uri').value = redirect;
      document.getElementById('edit-description').value = description;
      
      // 使用Bootstrap的modal方法打开模态框
      $('#edit-client-modal').modal('show');
    });
  });
  
  // 编辑客户端
  document.getElementById('edit-client-submit')?.addEventListener('click', async function() {
    const id = document.getElementById('edit-client-id').value;
    const form = document.getElementById('edit-client-form');
    const formData = new FormData(form);
    const data = {};
    
    for (const [key, value] of formData.entries()) {
      data[key] = value;
    }
    
    try {
      const response = await blessing.fetch.put(`admin/oauth/clients/${id}`, data);
      
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
  
  // 删除客户端
  document.querySelectorAll('.delete-client').forEach(button => {
    button.addEventListener('click', async function() {
      const id = this.dataset.id;
      
      if (!confirm(blessing.i18n['blessing-skin-auth-service'].admin.confirmDelete)) return;
      
      try {
        const response = await blessing.fetch.delete(`admin/oauth/clients/${id}`);
        
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
