function showNotification(message = '') {
  const notification = document.querySelector('.notification');
  if (notification) {
    notification.textContent = message;
    notification.style.display = 'block';

    setTimeout(() => {
      notification.classList.add('show');
    }, 100);

    setTimeout(() => {
      notification.classList.remove('show');
      setTimeout(() => {
        notification.style.display = 'none';
      }, 400);
    }, 2000);
  }
}