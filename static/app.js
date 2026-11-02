document.addEventListener('submit', (event) => {
  const form = event.target.closest('.confirm-form');
  if (form && !window.confirm(form.dataset.confirm || 'Continue?')) event.preventDefault();
});
