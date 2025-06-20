document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const response = await fetch(e.target.action, {
        method: 'POST',
        body: formData,
    });
    if (response.ok) {
        window.location.href = '/otp';
    } else {
        const data = await response.json();
        document.querySelector('.error').textContent = data.message || 'Registration failed';
    }
});