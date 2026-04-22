(function () {
 
    // ── Category button selection ─────────────────────────────────────────────
    document.querySelectorAll('.category-btn').forEach(btn => {
        btn.addEventListener('click', function () {
            document.querySelectorAll('.category-btn').forEach(b => b.classList.remove('selected'));
            this.classList.add('selected');
            this.querySelector('input[type="radio"]').checked = true;
        });
    });
 
    // ── Character counters ───────────────────────────────────────────────────
    function bindCounter(inputId, counterId, max) {
        const input   = document.getElementById(inputId);
        const counter = document.getElementById(counterId);
        if (!input || !counter) return;
 
        input.addEventListener('input', () => {
            const len = input.value.length;
            counter.textContent = `${len} / ${max}`;
            counter.className = 'char-counter';
            if (len >= max * 0.9) counter.classList.add('warn');
            if (len >= max)       counter.classList.add('over');
        });
    }
 
    bindCounter('bugTitle',       'titleCounter', 120);
    bindCounter('bugDescription', 'descCounter',  2000);
    bindCounter('bugSteps',       'stepsCounter', 1000);
 
    // ── File upload ──────────────────────────────────────────────────────────
    const uploadArea    = document.getElementById('uploadArea');
    const fileInput     = document.getElementById('bugAttachment');
    const uploadPreview = document.getElementById('uploadPreview');
    const uploadName    = document.getElementById('uploadName');
    const uploadRemove  = document.getElementById('uploadRemove');
 
    function showFile(file) {
        uploadName.textContent = file.name;
        uploadPreview.classList.add('show');
    }
 
    function clearFile() {
        fileInput.value = '';
        uploadPreview.classList.remove('show');
        uploadName.textContent = '';
    }
 
    fileInput.addEventListener('change', () => {
        if (fileInput.files[0]) showFile(fileInput.files[0]);
    });
 
    uploadArea.addEventListener('dragover', e => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
 
    uploadArea.addEventListener('dragleave', () => uploadArea.classList.remove('dragover'));
 
    uploadArea.addEventListener('drop', e => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file) {
            // Assign to the input for form submission
            const dt = new DataTransfer();
            dt.items.add(file);
            fileInput.files = dt.files;
            showFile(file);
        }
    });
 
    uploadRemove.addEventListener('click', clearFile);
 
    // ── Form submission ──────────────────────────────────────────────────────
    const form        = document.getElementById('bugReportForm');
    const formInner   = document.getElementById('formInner');
    const successState = document.getElementById('successState');
    const refCode     = document.getElementById('refCode');
 
    form.addEventListener('submit', function (e) {
        e.preventDefault();
 
        // Validate category
        const selectedCategory = document.querySelector('.category-btn.selected');
        const categoryError    = document.getElementById('categoryError');
        if (!selectedCategory) {
            categoryError.textContent = 'Please select a bug category.';
            categoryError.style.display = 'block';
            return;
        } else {
            categoryError.style.display = 'none';
        }
 
        // Basic HTML5 validation
        if (!form.checkValidity()) {
            form.classList.add('was-validated');
            return;
        }
 
        // Generate a reference code
        const ref = 'BUG-' + Date.now().toString().slice(-6);
        refCode.textContent = ref;
 
        // Show success state
        formInner.classList.add('hidden');
        successState.classList.add('show');
 
        // Scroll to top of card
        document.querySelector('.bugs-form-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
 
    // ── Report another ───────────────────────────────────────────────────────
    document.getElementById('reportAnother').addEventListener('click', function () {
        form.reset();
        form.classList.remove('was-validated');
        document.querySelectorAll('.category-btn').forEach(b => b.classList.remove('selected'));
        clearFile();
        ['titleCounter','descCounter','stepsCounter'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = el.textContent.replace(/^\d+/, '0');
        });
        formInner.classList.remove('hidden');
        successState.classList.remove('show');
    });
 
})();