(function () {

    const textarea = document.getElementById('cMessage');
    const counter = document.getElementById('msgCounter');

    if (textarea && counter) {
        const maxLen = textarea.getAttribute('maxlength') || 2000;

        textarea.addEventListener('input', (e) => {
            const len = e.target.value.length;
            counter.textContent =  `${len} / ${maxLen}`;
            counter.className = 'text-end mt-1 hs-counter';
            if (len >= maxLen * 0.9) counter.classList.add('warn');
            if (len >= maxLen) counter.classList.add('over');
    
        });
    }

})();