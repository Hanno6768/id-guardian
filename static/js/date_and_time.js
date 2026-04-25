(function () {
    const clockEl = document.getElementById('Clock');
    const dateEl = document.getElementById('Date');

    if (!clockEl && !dateEl) return;

    const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

    function tick() {

        const now = new Date();

        if (clockEl) {

            const hh = String(now.getHours()).padStart(2, '0');
            const mm = String(now.getMinutes()).padStart(2, '0')

            clockEl.textContent = `${hh}:${mm}`;
        }

        if (dateEl) {
            dateEl.textContent = `${DAYS[now.getDay()]}, ${now.getDate()}, ${MONTHS[now.getMonth()]} ${now.getFullYear()}`;
        }

    }

    tick();
    setInterval(tick, 1000);
})();