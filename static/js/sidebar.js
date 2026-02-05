document.addEventListener('DOMContentLoaded', function() {

    // get elements
    const sidebar = document.getElementById('sidebar');
    const toggleBtn = document.querySelector('.sidebar-toggle-btn');
    const overlay = document.getElementById('sidebarOverlay');

    // check if elements sre there
    if (!sidebar || !toggleBtn) {
        return;
    }

    // function to check the screen size
    function isMobile() {
        return window.innerWidth < 992;
    }

    //Initial load state
    const savedState = localStorage.getItem('sidebarCollapsed');

    if (isMobile()) {
        sidebar.classList.remove('collapsed')
        sidebar.classList.remove('mobile-open')
    } else {
        if (savedState === 'true') {
            sidebar.classList.add('collapsed');
        } else {
            sidebar.classList.remove('collapsed')
        }
    }

    //toggle function
    function handleToggle() {
        if (isMobile()) {
            sidebar.classList.toggle('mobile-open');
            sidebar.classList.remove('collapsed')
            if (overlay) overlay.classList.toggle('active');
        } else {
            sidebar.classList.toggle('collapsed');
            localStorage.setItem('sidebarCollapsed', sidebar.classList.contains('collapsed'));
        }
    }

    // add event listener to the toggle button
    toggleBtn.addEventListener('click', function(event) {
        event.stopPropagation();
        handleToggle();
    });

    // window resize
    window.addEventListener('resize', function() {

        if (isMobile()) {

            sidebar.classList.remove('collapsed');

        } else {

            sidebar.classList.remove('mobile-open')
            if (overlay) overlay.classList.remove('active');
            const savedState = this.localStorage.getItem('sidebarCollapsed');
            
            if (savedState === 'true') sidebar.classList.add('collapsed')

        }
    });

});