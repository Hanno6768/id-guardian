(function() {

    const zone = document.getElementById('uploadZone');
    const fileInput = document.getElementById('fileInput');
    const zoneDefault = document.getElementById('zoneDefault');
    const zonePreview = document.getElementById('zonePreview');
    const previewName = document.getElementById('previewName');
    const previewSize = document.getElementById('previewSize');
    const previewIcon = document.getElementById('previewIcon');
    const btnRemove = document.getElementById('btnRemoveFile');
    const chkDeclare = document.getElementById('chkDeclare');
    const btnSubmit = document.getElementById('btnSubmit');
    const notesArea = document.getElementById('uploadNotes');    
    const notesCtr = document.getElementById('notesCounter');
    
    // helpers
    const MAX_BYTES = 5 * 1024 * 1024; // 5MB

    const isPdf = (filename) => {
        return filename.toLowerCase().endsWith('.pdf');
    }

    const formatBytes = (bytes) => {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    // update submit button
    const updateSubmit = () => {

        const hasFile = zone.classList.contains('has-file');
        const declared = chkDeclare && chkDeclare.checked;
        btnSubmit.disabled = !(hasFile && declared);

    }

    //show file preview
    const showPreview = (file) => {
        previewName.textContent = file.name;
        previewSize.textContent = formatBytes(file.size);
        if (isPdf(file.name)) {
            previewIcon.className = 'upload-preview-icon pdf-icon';
            previewIcon.innerHTML = "<i class='bx bxs-file-pdf'></i>";
        } else {
            previewIcon.className = 'upload-preview-icon';
            previewIcon.innerHTML = "<i class='bx bx-image'></i>";
        }

        zoneDefault.classList.add('d-none');
        zonePreview.classList.remove('d-none');
        zone.classList.add('has-file');
        zone.classList.remove('has-error');

        updateSubmit();
    }

    // clear file preview
    const clearFile = () => {
        fileInput.value = '';
        zoneDefault.classList.remove('d-none');
        zonePreview.classList.add('d-none');
        zone.classList.remove('has-file', 'has-error');
        
        updateSubmit();
    }

    // validate file
    const validateFile = (file) => {

        if (!file) return;
        const allowed = ['image/jpeg', 'image/png', 'application/pdf'];
        const errEl = document.getElementById('fileError');

        if (!allowed.includes(file.type)) {
            zone.classList.add('has-error');
            if (errEl) {
                errEl.textContent = 'Invalid file type. Only JPG, PNG, and PDF are allowed.';
                errEl.style.display = 'block';    
            }
            fileInput.value = '';
            return;
        }

        if (file.size > MAX_BYTES) {
            zone.classList.add('has-error');
            if (errEl) {
                errEl.textContent = 'File is too large. Maximum size is 5MB.';
                errEl.style.display = 'block';
            }
            fileInput.value = '';
            return;
        }

        if (errEl) errEl.style.display = 'none';
        showPreview(file);
    }

    // grab 1st file if more than 1 file is uploaded
    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            if (e.target.files[0]) validateFile(e.target.files[0]);
        });
    }

    if (btnRemove) {
        btnRemove.addEventListener('click', (e) => {
            e.preventDefault();
            clearFile();
        });
    }

    // drag & drop
    if (zone) {

        zone.addEventListener('dragover', (e) => {
            // prevent browser from opening the file
            e.preventDefault();

            if (!zone.classList.contains('has-file')) {
                zone.classList.add('dragover');
            }
        });

        zone.addEventListener('dragleave', (e) => {
            zone.classList.remove('dragover');
        });

        zone.addEventListener('drop', (e) => {

            e.preventDefault();
            zone.classList.remove('dragover');

            // ignore if file already uploaded
            if (zone.classList.contains('has-file')) return;

            const file = e.dataTransfer.files[0];
            if (file) {
                const dt = new DataTransfer();
                dt.items.add(file);
                fileInput.files = dt.files;
                validateFile(file);
            }
        });
    }

    // declaration checkbox
    if (chkDeclare) {
        chkDeclare.addEventListener('change', updateSubmit);
    }

    // notes area counter
    if (notesArea && notesCtr) {
        const maxChars = notesArea.getAttribute('maxlength') || 400;
        notesArea.addEventListener('input', (e) => {
            const len = e.target.value.length;
            notesCtr.textContent = `${len}/${maxChars}`;
            notesCtr.className = 'upload-char-counter';
            if (len >= maxChars * 0.9) notesCtr.classList.add('warn');
            if (len >= maxChars) notesCtr.classList.add('over');
        });
    }

    const form = document.getElementById('uploadForm');
    if (form) {
        form.addEventListener('submit', (e) => {
            if (!zone.classList.contains('has-file')) {
                e.preventDefault();
                e.stopPropagation();
                zone.classList.add('has-error');
                const errEl = document.getElementById('fileError');
                if (errEl) {
                    errEl.textContent = 'Please upload a file before submitting.';
                    errEl.style.display = 'block';
                }
            }

            if (!form.checkValidity()) {
                e.preventDefault();
                e.stopPropagation();
                form.classList.add('was-validated');
            }
            
        });
    }

})();