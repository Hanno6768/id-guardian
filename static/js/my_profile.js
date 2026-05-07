(function () {

    // calculate user age
    (function () {
        const ageElement = document.getElementById('computedAge');
        const birthdateElement = document.getElementById('userBirthdate');

        // exit if no age element 
        if (ageElement && birthdateElement) {

            const birthdateText = birthdateElement.textContent.trim();

            if (birthdateText !== '-') {

                // check the date format
                const dob = new Date(birthdateText);

                if (isNaN(dob.getTime())) {
                    ageElement.textContent = '-';
                    return;
                }

                // calculate birthdate roughly
                const today = new Date();
                let age = today.getFullYear() - dob.getFullYear();

                // check if birthdate happened this year else subtract 1
                const monthDiff = today.getMonth() - dob.getMonth();

                if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < dob.getDate())) {
                    age--;
                }

                ageElement.textContent = age > 0 ? age + ' years' : '-';


            } else {
                ageElement.textContent = '-';
                return;
            }

        }


    })();

    (function () {
        const btnEdit = document.getElementById('btnEditContact');
        const btnCancel = document.getElementById('btnCancelContact');
        const form = document.getElementById('formContact');
        const actions = document.getElementById('contactActions');

        if (!btnEdit || !form) return;

        const fields = Array.from(form.querySelectorAll('.profile-input'));

        // create a save slot to restore the original values if user presses cancel
        let snapshot = {};

        function enterEditMode() {
            snapshot = {}
            fields.forEach(function (f) {
                snapshot[f.id || f.name] = f.value;
                f.disabled = false;
            });
            if (actions) actions.style.display = "flex";
            btnEdit.classList.add('active');
            btnEdit.innerHTML = "<i class='bx bx-x'></i> Cancel";
            btnEdit.onclick = exitEditMode;
        }

        function exitEditMode() {
            fields.forEach(function (f) {
                const key = f.id || f.name;

                if (key in snapshot) {
                    f.value = snapshot[key]
                }

                f.disabled = true;
                f.classList.remove('input-error', 'input-success');
            });

            if (actions) actions.style.display = "none";
            btnEdit.classList.remove('active');
            btnEdit.innerHTML = "<i class='bx bx-edit'></i> Edit";
            btnEdit.onclick = enterEditMode;
        }

        btnEdit.onclick = enterEditMode;
        if (btnCancel) btnCancel.onclick = exitEditMode;

    })();

    // Password section
    (function () {
        const btnEdit = document.getElementById('btnEditPassword');
        const btnCancel = document.getElementById('btnCancelPassword');
        const formPw = document.getElementById('formPassword');
        const collapsed = document.getElementById('PasswordCollapsed');
        const btnSave = document.getElementById('btnSavePassword');
        const newPwInput = document.getElementById('newPassword');
        const confInput = document.getElementById('confirmPassword');
        const matchHint = document.getElementById('pwMatchHint');

        if (!btnEdit || !formPw) return;

        function openPwForm() {
            if (collapsed) collapsed.style.display = 'none';
            formPw.style.display = 'block';
            btnEdit.classList.add('active');
            btnEdit.innerHTML = "<i class='bx bx-x'></i> Cancel";
            btnEdit.onclick = closePwForm;

        }

        function closePwForm() {
            if (collapsed) collapsed.style.display = '';
            formPw.style.display = 'none';
            formPw.reset();
            resetMatch();
            if (btnSave) btnSave.disabled = true;
            btnEdit.classList.remove('active');
            btnEdit.innerHTML = "<i class='bx bx-lock-open-alt'></i> Change";
            btnEdit.onclick = openPwForm;

        }

        btnEdit.onclick = openPwForm;
        if (btnCancel) btnCancel.onclick = closePwForm;

        function resetMatch() {
            if (!matchHint) return;
            matchHint.textContent = '';
            matchHint.className = 'pw-match-hint';
        }

        function checkMatch() {
            if (!matchHint || !newPwInput || !confInput) return;
            const newVAl = newPwInput.value;
            const confVal = confInput.value;

            if (!confVal) { resetMatch(); return }

            if (newVAl === confVal) {
                matchHint.textContent = '✓ Passwords match';
                matchHint.className = 'pw-match-hint match';
            } else {
                matchHint.textContent = '✗ Passwords do not match';
                matchHint.className = 'pw-match-hint no-match'
            }
        }

        function updateSaveBtn() {
            if (!btnSave) return;

            const currentVal = document.getElementById('currentPassword');
            const allFilled = (currentVal && currentVal.value.trim()) && (newPwInput && newPwInput.value.trim()) && (confInput && confInput.value.trim());
            const matching = newPwInput && confInput && (newPwInput.value === confInput.value);
            const longEnough = newPwInput && newPwInput.value.length >= 6;

            btnSave.disabled = !(allFilled && matching && longEnough)

        }

        if (newPwInput) {
            newPwInput.addEventListener('input', function () {
                checkMatch();
                updateSaveBtn();
            });
        }

        if (confInput) {
            confInput.addEventListener('input', function () {
                checkMatch();
                updateSaveBtn();
            });
        }

        const currentPw = document.getElementById('currentPassword');
        if (currentPw) {
            currentPw.addEventListener('input', updateSaveBtn);
        }

    })();

    // show/hide password toggle
    document.querySelectorAll('.btn-toggle-pw').forEach(function (btn) {
        btn.addEventListener('click', function () {
            const input = document.getElementById(this.dataset.target);
            if(!input) return;

            if (input.type === 'password') {
                input.type = 'text';
                this.innerHTML = "<i class='bx bx-hide'></i>";
            } else {
                input.type = 'password';
                this.innerHTML = "<i class='bx bx-show'></i>";
            }
        })
    })


})();