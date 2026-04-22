// Highlight active TOC link on scroll
(function () {
    const sections = document.querySelectorAll('.policy-content section[id]');
    const links    = document.querySelectorAll('.toc-link');
 
    const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                links.forEach(l => l.classList.remove('active'));
                const active = document.querySelector(`.toc-link[href="#${entry.target.id}"]`);
                if (active) active.classList.add('active');
            }
        });
    }, { rootMargin: '-20% 0px -70% 0px' });
 
    sections.forEach(s => observer.observe(s));
})();