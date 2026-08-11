export const toast = {
  success: (msg) => showToast(msg, 'success'),
  error: (msg) => showToast(msg, 'error'),
  info: (msg) => showToast(msg, 'info')
};

function showToast(msg, type) {
  let container = document.getElementById('pentrixa-toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'pentrixa-toast-container';
    Object.assign(container.style, {
      position: 'fixed',
      bottom: '24px',
      right: '24px',
      display: 'flex',
      flexDirection: 'column',
      gap: '12px',
      zIndex: 9999,
      pointerEvents: 'none'
    });
    document.body.appendChild(container);
  }

  const el = document.createElement('div');
  
  const colors = {
    success: { bg: 'rgba(34, 197, 94, 0.15)', border: 'rgba(34, 197, 94, 0.3)', text: '#22c55e', icon: 'M5 13l4 4L19 7' },
    error: { bg: 'rgba(239, 68, 68, 0.15)', border: 'rgba(239, 68, 68, 0.3)', text: '#ef4444', icon: 'M6 18L18 6M6 6l12 12' },
    info: { bg: 'rgba(6, 182, 212, 0.15)', border: 'rgba(6, 182, 212, 0.3)', text: '#06b6d4', icon: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z' }
  };
  
  const theme = colors[type] || colors.info;

  Object.assign(el.style, {
    background: 'rgba(10, 14, 18, 0.95)',
    backdropFilter: 'blur(12px)',
    border: `1px solid ${theme.border}`,
    borderRadius: '12px',
    padding: '14px 20px',
    color: '#fff',
    fontSize: '14px',
    fontWeight: '500',
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4)',
    transform: 'translateX(120%)',
    transition: 'transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275), opacity 0.3s',
    opacity: '0',
    pointerEvents: 'auto',
    fontFamily: 'system-ui, -apple-system, sans-serif'
  });

  el.innerHTML = `
    <div style="width: 24px; height: 24px; border-radius: 50%; background: ${theme.bg}; color: ${theme.text}; display: flex; align-items: center; justify-content: center; flex-shrink: 0">
      <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="${theme.icon}"></path>
      </svg>
    </div>
    <span>${msg}</span>
  `;

  container.appendChild(el);

  requestAnimationFrame(() => {
    el.style.transform = 'translateX(0)';
    el.style.opacity = '1';
  });

  setTimeout(() => {
    el.style.transform = 'translateX(120%)';
    el.style.opacity = '0';
    setTimeout(() => {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, 400);
  }, 4000);
}
