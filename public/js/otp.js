document.getElementById('otpForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const response = await fetch(e.target.action, {
        method: 'POST',
        body: formData,
    });
    if (response.ok) {
        window.location.href = '/login';
    } else {
        const data = await response.json();
        document.querySelector('.error').textContent = data.message || 'Invalid OTP';
    }
});

// OTP timer
let timeLeft = 120; // 2 minutes in seconds
const timerElement = document.getElementById('timer');
const interval = setInterval(() => {
    const minutes = Math.floor(timeLeft / 60);
    const seconds = timeLeft % 60;
    timerElement.textContent = `Time remaining: ${minutes}:${seconds.toString().padStart(2, '0')}`;
    timeLeft--;
    if (timeLeft < 0) {
        clearInterval(interval);
        timerElement.textContent = 'OTP has expired. Please resend.';
    }
}, 1000);