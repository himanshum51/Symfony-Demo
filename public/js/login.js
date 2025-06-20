document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const response = await fetch(e.target.action, {
        method: 'POST',
        body: formData,
    });
    if (response.ok) {
        const data = await response.json();
        // Store access token in memory
        window.accessToken = data.token;
        // Refresh token is in HTTP-only cookie
        window.location.href = '/home';
    } else {
        const data = await response.json();
        document.querySelector('.error').textContent = data.message || 'Login failed';
    }
});