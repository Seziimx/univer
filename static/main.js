document.addEventListener('DOMContentLoaded', () => {
    const container = document.querySelector('.container');
    const registerBtn = document.querySelectorAll('.register-btn'); // Select all register buttons
    const loginBtn = document.querySelectorAll('.login-btn'); // Select all login buttons

    registerBtn.forEach(btn => {
        btn.addEventListener('click', () => {
            container.classList.add('active'); // Add 'active' class to show the registration form
        });
    });

    loginBtn.forEach(btn => {
        btn.addEventListener('click', () => {
            container.classList.remove('active'); // Remove 'active' class to show the login form
        });
    });

    // Real-Time Filtering
    const filterType = document.getElementById('filter-type');
    const filterStatus = document.getElementById('filter-status');
    const filterQuery = document.getElementById('filter-query');
    const requestList = document.getElementById('request-list');
    const applyFiltersButton = document.getElementById('apply-filters');
    const noRequests = document.getElementById('no-requests');

    if (filterType && filterStatus && filterQuery && requestList && applyFiltersButton) {
        function applyFilters(event) {
            const isButtonClick = event?.target === applyFiltersButton;

            // Get filter values
            const type = filterType.value.trim().toLowerCase();
            const status = filterStatus.value.trim().toLowerCase();
            const query = isButtonClick ? filterQuery.value.trim().toLowerCase() : '';

            const cards = requestList.querySelectorAll('.card');
            let hasVisibleCards = false;

            cards.forEach(card => {
                const cardType = card.getAttribute('data-type').trim().toLowerCase();
                const cardStatus = card.getAttribute('data-status').trim().toLowerCase();
                const cardDescription = card.getAttribute('data-description').trim().toLowerCase();
                const cardUsername = card.getAttribute('data-username').trim().toLowerCase();
                const cardFullName = card.getAttribute('data-fullname').trim().toLowerCase();

                // Check if the card matches the filters
                const matchesType = !type || cardType === type;
                const matchesStatus = !status || cardStatus === status;
                const matchesQuery = !isButtonClick || cardDescription.includes(query) || cardUsername.includes(query) || cardFullName.includes(query);

                if (matchesType && matchesStatus && matchesQuery) {
                    card.style.display = 'block';
                    hasVisibleCards = true;
                } else {
                    card.style.display = 'none';
                }
            });

            // Show or hide the placeholder message
            noRequests.style.display = hasVisibleCards ? 'none' : 'block';
        }

        // Attach event listeners
        filterType.addEventListener('change', applyFilters); // Filter immediately on type change
        filterStatus.addEventListener('change', applyFilters); // Filter immediately on status change
        applyFiltersButton.addEventListener('click', applyFilters); // Filter on button click for search query
    }

    // Handle user deletion
    document.querySelectorAll('.delete-user-btn').forEach(button => {
        button.addEventListener('click', (event) => {
            event.preventDefault(); // Prevent form submission
            const userId = button.getAttribute('data-user-id');
            fetch(`/delete_user/${userId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
            })
            .then(response => {
                if (response.ok) {
                    // Remove the user from the DOM
                    const userElement = document.getElementById(`user-${userId}`);
                    if (userElement) {
                        userElement.remove();
                    }
                } else {
                    // Attempt to parse JSON error message
                    response.json().then(data => {
                        alert(data.error || 'Не удалось удалить пользователя.');
                    }).catch(() => {
                        alert('Произошла ошибка на сервере.');
                    });
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Произошла ошибка при удалении пользователя.');
            });
        });
    });

    // Theme toggle functionality
    const themeToggleCheckbox = document.getElementById('theme-toggle-checkbox');
    const currentTheme = localStorage.getItem('theme');

    // Apply the saved theme on page load
    if (currentTheme === 'dark') {
        document.body.classList.add('dark-mode');
        if (themeToggleCheckbox) themeToggleCheckbox.checked = true;
    }

    // Toggle theme on checkbox change
    if (themeToggleCheckbox) {
        themeToggleCheckbox.addEventListener('change', () => {
            if (themeToggleCheckbox.checked) {
                document.body.classList.add('dark-mode');
                localStorage.setItem('theme', 'dark');
            } else {
                document.body.classList.remove('dark-mode');
                localStorage.setItem('theme', 'light');
            }
        });
    }
});










document.addEventListener('DOMContentLoaded', () => {
    // Только если ширина экрана ≤ 480px
    if (window.innerWidth <= 480) {
        const loginBtn = document.querySelector('.login-btn');
        const registerBtn = document.querySelector('.register-btn');
        const loginForm = document.querySelector('.form-box.login');
        const registerForm = document.querySelector('.form-box.register');

        // Показать логин по умолчанию
        loginForm?.classList.add('show');
        registerForm?.classList.remove('show');

        // Обработчики
        loginBtn?.addEventListener('click', () => {
            loginForm?.classList.add('show');
            registerForm?.classList.remove('show');
        });

        registerBtn?.addEventListener('click', () => {
            registerForm?.classList.add('show');
            loginForm?.classList.remove('show');
        });
    }
});