(function () {
    // toggle tabs
    document.querySelectorAll('.sa-tab').forEach(tab => {
        tab.addEventListener('click', (e)=> {

            // Remove active class from all tabs
            document.querySelectorAll('.sa-tab').forEach(t => t.classList.remove('active'));

            // Add active class to clicked tab
            tab.classList.add('active'); 

            const target = e.currentTarget.dataset.tab;
            document.querySelectorAll('.sa-tab-panel').forEach(panel => {
                panel.classList.add('d-none');
            });

            const targetPanel = document.getElementById('panel-' + target);
            if (targetPanel) targetPanel.classList.remove('d-none');

            
        });
    });

    // table filter
    const logFilter = document.getElementById('logFilter');    
    const tableBody = document.getElementById('logTableBody');
    const logEmpty = document.getElementById('logEmpty');
    
    function applyLogFilter() {
        if (!logFilter || !tableBody) return;

        const value = logFilter.value;
        const rows = tableBody.querySelectorAll('tr');
        let visible = 0;

        rows.forEach(row => {
            const match = value === 'all' || row.dataset.category === value;
            row.style.display = match ? '' : 'none';
            if (match) visible++;
        });

        if (logEmpty) logEmpty.classList.toggle('d-none', visible > 0);
    }

    if (logFilter) logFilter.addEventListener('change', applyLogFilter);

})();