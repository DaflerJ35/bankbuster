document.addEventListener('DOMContentLoaded', () => {
    const canvas = document.getElementById('matrixCanvas');
    if (!canvas) {
        console.error('Matrix canvas not found');
        return;
    }
    const ctx = canvas.getContext('2d');

    let w = canvas.width = window.innerWidth;
    let h = canvas.height = window.innerHeight;
    let cols = Math.floor(w / 20) + 1;
    let ypos = Array(cols).fill(0);

    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, w, h);

    function matrix() {
        ctx.fillStyle = 'rgba(0,0,0,.05)';
        ctx.fillRect(0, 0, w, h);

        ctx.fillStyle = '#00ff88'; // Green color for the matrix text
        ctx.font = '15pt monospace';

        ypos.forEach((y, ind) => {
            const text = String.fromCharCode(Math.random() * 128);
            const x = ind * 20;
            ctx.fillText(text, x, y);
            if (y > 100 + Math.random() * 10000) {
                ypos[ind] = 0;
            } else {
                ypos[ind] = y + 20;
            }
        });
    }

    let interval = setInterval(matrix, 50);

    window.addEventListener('resize', () => {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
        cols = Math.floor(w / 20) + 1;
        ypos = Array(cols).fill(0);
        ctx.fillStyle = '#000';
        ctx.fillRect(0, 0, w, h);
        // No need to clear and restart interval, matrix function will adapt
    });
});