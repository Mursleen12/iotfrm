document.addEventListener('DOMContentLoaded', function () {
    const uploadForm = document.querySelector('form[action="/upload"]');
    if (uploadForm) {
        uploadForm.addEventListener('submit', function () {
            const submitButton = uploadForm.querySelector('button[type="submit"]');
            submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Analyzing...';
            submitButton.disabled = true;
        });
    }
});