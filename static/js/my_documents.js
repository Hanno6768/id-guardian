(function () {

    const docMap = {};
    try {
        const raw = document.getElementById('doc-data').textContent;
        JSON.parse(raw).forEach(doc => {
            docMap[doc.id] = doc;
        });
    } catch (e) {
        console.error('Could not parse doc data:', e);
    }

    const searchInput = document.getElementById('searchInput');
    const filterBtns = document.querySelectorAll('.filter-group .btn');
    const docGrid = document.getElementById('docGrid');
    const countBadge = document.getElementById('countBadge');
    const modalEl = document.getElementById('docModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalPreview = document.getElementById('modalPreview');
    const modalStatus = document.getElementById('modalStatusLabel');
    const modalIssued = document.getElementById('modalIssuedLabel');
    const qrImage = document.getElementById('qrImage');
    const btnDoc = document.getElementById('btnDoc');
    const btnQR = document.getElementById('btnQR');
    const panelDoc = document.getElementById('panelDoc');
    const panelQR = document.getElementById('panelQR');

    let activeFilter = 'all';

    function getCards() {
        return[...docGrid.querySelectorAll('[data-status]')];
    }

    function applyFilters() {
        const query = searchInput.value.trim().toLowerCase();
        const cards = getCards();
        let visible = 0;

        cards.forEach(card => {
            const name = (card.dataset.name || '').toLowerCase();
            const status = (card.dataset.status || '').toLowerCase();

            const matchesSearch = !query || name.includes(query);
            const matchesFilter = activeFilter === 'all' || status === activeFilter;    

            const show = matchesSearch && matchesFilter;
            card.style.display = show ? '' : 'none';
            if (show) visible++;
        });

        // Update Badge
        countBadge.textContent = visible;

        // Empty state
        let emptyState = docGrid.querySelector('.empty-state-row');
        if (visible === 0) {
            if (!emptyState) {
                emptyState = document.createElement('div');
                emptyState.className = 'col-12 text-center py-5 text-secondary empty-state-row';
                emptyState.innerHTML = "<i class='bx bx-search-alt d-block mb-2' style='font-size:2rem'></i>No documents match your search.";
                docGrid.appendChild(emptyState);
            }
            emptyState.style.display = '';
        } else if (emptyState) {
            emptyState.style.display = 'none';
        }
    }

    searchInput.addEventListener('input', applyFilters);

    filterBtns.forEach(btn => {
        btn.addEventListener('click', function () {
            filterBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            activeFilter = this.dataset.filter;
            applyFilters();
        });
    });

    function showTab(tab) {
        if (tab === 'doc') {
            panelDoc.style.display = '';
            panelQR.style.display = 'none';
            btnDoc.classList.add('active');
            btnQR.classList.remove('active');
        } else {
            panelDoc.style.display = 'none';
            panelQR.style.display = '';
            btnDoc.classList.remove('active');
            btnQR.classList.add('active');
        }
    }

    btnDoc.addEventListener('click', () => showTab('doc'));
    btnQR.addEventListener('click', () => showTab('qr'));

    function renderDocPreview(doc) {
        if (!doc.file_url) {
            return `
            <div class="d-flex flex-column align-items-center justify-content-center" gap-2 py-5 text-muted w-100">
                <i class='bx bx-file-blank' style="font-size:3rem;"></i>
                <span style="font-size:0.9rem;">No file available to view</span>
            </div>`;
        }  

        const ext = doc.file_url.split('.').pop().toLowerCase();

        if (ext === 'pdf') {
            return `<iframe src="${doc.file_url}" width="100%" height="320" frameborder="0" style="border-radius:6px;"></iframe>`;

        }

        return `<img src="${doc.file_url}" alt="${doc.name}" style=max-width:100%; max-height:320px; object-fit:contain; border-radius:6px;">`;
    }

    function openModal(docId) {
        const doc = docMap[docId];
        if (!doc) return;

        showTab('doc');

        modalTitle.textContent = doc.name;
        modalTitle.style = "font-size:1.25rem; font-weight:500; text-align:left;";

        modalPreview.innerHTML = renderDocPreview(doc);

        qrImage.src = doc.qr_code || '';

        modalStatus.textContent = doc.status.charAt(0).toUpperCase() + doc.status.slice(1);
        modalIssued.textContent = doc.issued || '-';
    }

    modalEl.addEventListener('show.bs.modal', function (event) {
        const triggerBtn = event.relatedTarget;
        const docId = triggerBtn ? parseInt(triggerBtn.dataset.id, 10) : null;
        if (docId) openModal(docId);
    });

    modalEl.addEventListener('hidden.bs.modal', function () {
        modalPreview.innerHTML = '';
        qrImage.src = '';
        showTab('doc');
    })
    

})();