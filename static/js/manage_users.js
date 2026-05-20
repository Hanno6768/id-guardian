(function () {
    //toggle tabs 
    document.querySelectorAll('.mu-tab').forEach(tab => {
        tab.addEventListener('click', (e)=> {

            // Remove active class from all tabs
            document.querySelectorAll('.mu-tab').forEach(t => t.classList.remove('active'));

            // Add active class to clicked tab
            tab.classList.add('active'); 

            const target = e.currentTarget.dataset.tab;
            document.querySelectorAll('.mu-panel').forEach(panel => {
                panel.classList.add('d-none');
            });

            const targetPanel = document.getElementById('panel-' + target);
            if (targetPanel) targetPanel.classList.remove('d-none');

            
        });
    });

    // searchbar
    const searchVerified  = document.getElementById('searchVerified');    
    const roleFilter = document.getElementById('roleFilter');
    const verifiedEmpty = document.getElementById('verifiedEmpty');
    const verifiedTable = document.getElementById('verifiedTable');

    // filter verified users
    const filterVerified = () => {
        const query = searchVerified ? searchVerified.value.trim().toLowerCase() : '';
        const role = roleFilter ? roleFilter.value : '';
        const rows = verifiedTable ? verifiedTable.querySelectorAll('tbody tr') : [];

        let visible = 0;

        rows.forEach(row => {
            // see if match found
            const matchSearch = !query || (row.dataset.name || '').includes(query) ||
                                (row.dataset.username || '').includes(query) ||
                                (row.dataset.email || '').includes(query);

            const matchRole = role === 'all' || row.dataset.role === role;

            if (matchSearch && matchRole) {
                row.style.display = '';
                visible++;
            }   else {
                row.style.display = 'none';
            }

            if (verifiedEmpty) {
                verifiedEmpty.classList.toggle('d-none', visible > 0);
            }
        });
    }

    if (searchVerified) searchVerified.addEventListener('input', filterVerified);
    if (roleFilter) roleFilter.addEventListener('change', filterVerified);

    const searchPending = document.getElementById('searchPending');
    const pendingEmpty = document.getElementById('pendingEmpty');
    const pendingTable = document.getElementById('pendingTable');

    // filter pending users
    const filterPending = () => {
        const query = searchPending ? searchPending.value.trim().toLowerCase() : '';
        const rows = pendingTable ? pendingTable.querySelectorAll('tbody tr') : [];
        let visible = 0;

        rows.forEach(row => {
            const matchSearch = !query || (row.dataset.name || '').includes(query) ||
                                (row.dataset.email || '').includes(query);

            if (matchSearch) {
                row.style.display = '';
                visible++;
            }   else {
                row.style.display = 'none';
            }

            if (pendingEmpty) {
                pendingEmpty.classList.toggle('d-none', visible > 0);
            }

        });
    }

    if (searchPending) searchPending.addEventListener('input', filterPending);

    const editModalEl = document.getElementById('editModal');
    const userForm = document.getElementById('userForm');
    const formTitle = document.getElementById('editModalTitle');
    const formSub = document.getElementById('editModalSub');
    const formIcon = document.getElementById('editModalIcon');
    const formSubmitBtn = document.getElementById('formSubmitBtn');
    const formSubmitLbl = document.getElementById('formSubmitLabel');
    const passwordField = document.getElementById('passwordField');
    const formPassword = document.getElementById('formPassword');    
    const createNotice = document.getElementById('createNotice');    
    const formUserId = document.getElementById('formUserId');    

    // open modal in create user mode
    const btnNewUser = document.getElementById('btnNewUser');
    if (btnNewUser && editModalEl) {
        btnNewUser.addEventListener('click', () => {
            setModalMode('create');
            clearForm();
            bootstrap.Modal.getOrCreateInstance(editModalEl).show();
        });
    }
    
    // open modal in edit user mode
    if (editModalEl) {
        editModalEl.addEventListener('show.bs.modal', (e) => {
            const btn = e.relatedTarget;

            if (!btn || !btn.classList.contains('mu-btn-edit')) return;

            setModalMode('edit');

            // prefill form
            formUserId.value = btn.dataset.id || '';
            setField('formFullName', btn.dataset.name || '');
            setField('formUsername', btn.dataset.username || '');
            setField('formEmail', btn.dataset.email || '');
            setField('formPhone', btn.dataset.phone || '');
            setField('formRole', btn.dataset.role || '');
        });

        // remove the was-validated class on modal hide
        editModalEl.addEventListener('hidden.bs.modal', () => {
            if (userForm) {
                userForm.classList.remove('was-validated');
                userForm.reset();
            }
        });
    }

    const setModalMode = (mode) => {
        if (mode === 'create') {
            if (formTitle) formTitle.textContent = 'Create New User';           
            if (formSub) formSub.textContent = 'Fill in the details to create a new user.';           
            if (formIcon) formIcon.innerHTML = "<i class='bx bx-user-plus'></i>";        
            if (formSubmitLbl) formSubmitLbl.textContent = 'Create User';            
            if (formSubmitBtn) formSubmitBtn.innerHTML = "<i class='bx bx-user-plus'></i> <span id='formSubmitLabel'>Create User</span>";           
            if (passwordField) passwordField.style.display = '';            
            if (formPassword) formPassword.required = true;
            if (createNotice) createNotice.style.display = '';            
            if (formUserId) formUserId.value = '';                
        } else {
            if (formTitle) formTitle.textContent = 'Edit User';           
            if (formSub) formSub.textContent = 'Update role or contact details.';           
            if (formIcon) formIcon.innerHTML = "<i class='bx bx-edit'></i>"; 
            if (formSubmitBtn) formSubmitBtn.innerHTML = "<i class='bx bx-save'></i> <span>Save Changes</span>"; 
            if (passwordField) passwordField.style.display = 'none';            
            if (formPassword) formPassword.required = false;
            if (createNotice) createNotice.style.display = 'none';                           
        }
    }

    setField = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.value = value;
    }

    const clearForm = () => {
        if (userForm) userForm.reset();
    }

    const natIdInput = document.getElementById('formNationalId');
    if (natIdInput) {
        natIdInput.addEventListener('input', (e) => {
            // Remove non-digit characters
            e.target.value = e.target.value.replace(/\D/g, '').slice(0, 11);
        });
    }

    if (userForm) {
        userForm.addEventListener('submit', (e) => {
            const natId = document.getElementById('formNationalId');
            if (natId && natId.closest('[style*="display"]') === null) {
                if (!/^\d{11}$/.test(natId.value)) {
                    natId.setCustomValidity('National ID must be exactly 11 digits.');
                } else {
                    natId.setCustomValidity('');
                }
            }

            if (!userForm.checkValidity()) {
                e.preventDefault();
                e.stopPropagation();
            }

            userForm.classList.add('was-validated');

        });
    }

    const deleteModalEl = document.getElementById('deleteModal');
    const deleteUserName = document.getElementById('deleteUserName');
    const deleteUserId = document.getElementById('deleteUserId'); 

    if (deleteModalEl) {
        deleteModalEl.addEventListener('show.bs.modal', (e) => {
            const btn = e.relatedTarget;
            if (!btn) return;

            if (deleteUserName) deleteUserName.textContent = btn.dataset.name || 'this user';
            if (deleteUserId) deleteUserId.value = btn.dataset.id || '';
        });
    }

})();