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
})();