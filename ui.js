// ui.js - Custom JavaScript for AppSec RL Agent Demo
console.log("AppSec RL Agent UI loaded.");

function initUI() {
    // Optional: Add a glitch effect on hover to the main title
    const title = document.querySelector('.glitch');
    if (title) {
        title.addEventListener('mouseover', () => {
            title.style.textShadow = '0 0 20px #bc13fe, 0 0 30px #00f3ff';
        });
        title.addEventListener('mouseout', () => {
            title.style.textShadow = '0 0 10px #00f3ff';
        });
    }

    // Add a pulsing effect to the primary evaluate button
    const evalBtns = document.querySelectorAll('button.primary');
    evalBtns.forEach(btn => {
        btn.addEventListener('mousedown', () => {
            btn.style.transform = 'scale(0.95)';
        });
        btn.addEventListener('mouseup', () => {
            btn.style.transform = 'scale(1.02)';
        });
    });
}

// Ensure the script runs after Gradio elements are mounted
setTimeout(initUI, 1000);
