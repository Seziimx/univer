document.addEventListener('DOMContentLoaded', () => {
    const filterType = document.getElementById('filter-type');
    const filterStatus = document.getElementById('filter-status');
    const filterQuery = document.getElementById('filter-query');
    const requestList = document.getElementById('request-list');
    const applyFiltersButton = document.getElementById('apply-filters');

    if (filterType && filterStatus && filterQuery && applyFiltersButton) {
        let currentQuery = ''; // Store the current search query

        function filterRequests() {
            const type = filterType.value.toLowerCase();
            const status = filterStatus.value.toLowerCase();
            const query = currentQuery.toLowerCase(); // Use the stored query

            const cards = requestList.querySelectorAll('.card');
            let hasVisibleCards = false;

            cards.forEach(card => {
                const cardType = card.getAttribute('data-type').toLowerCase();
                const cardStatus = card.getAttribute('data-status').toLowerCase();
                const cardDescription = card.getAttribute('data-description').toLowerCase();
                const cardUsername = card.getAttribute('data-username').toLowerCase();
                const cardFullName = card.getAttribute('data-fullname').toLowerCase();

                // Check if the card matches the filters
                const matchesType = !type || cardType === type;
                const matchesStatus = !status || cardStatus === status;
                const matchesQuery = !query || cardDescription.includes(query) || cardUsername.includes(query) || cardFullName.includes(query);

                if (matchesType && matchesStatus && matchesQuery) {
                    card.style.display = 'block';
                    hasVisibleCards = true;
                } else {
                    card.style.display = 'none';
                }
            });

            // Show or hide the placeholder message
            const noRequests = document.getElementById('no-requests');
            if (hasVisibleCards) {
                noRequests.style.display = 'none';
            } else {
                noRequests.style.display = 'block';
            }
        }

        // Filter immediately when "Тип" or "Статус" dropdowns change
        filterType.addEventListener('change', filterRequests);
        filterStatus.addEventListener('change', filterRequests);

        // Update the query and filter when the "Применить" button is clicked
        applyFiltersButton.addEventListener('click', () => {
            currentQuery = filterQuery.value; // Update the stored query
            filterRequests(); // Apply all filters
        });
    }
});
