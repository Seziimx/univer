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

document.querySelectorAll('.update-status').forEach(button => {
    button.addEventListener('click', async (event) => {
        const card = event.target.closest('.card');
        const zayavkaId = card.dataset.id;
        const newStatus = event.target.dataset.status;

        try {
            const response = await fetch('/api/update_status', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ id: zayavkaId, status: newStatus })
            });

            const result = await response.json();
            if (result.success) {
                // Update the status in the DOM
                card.querySelector('.status').textContent = result.status;
            } else {
                alert(result.error || 'Ошибка при обновлении статуса');
            }
        } catch (error) {
            console.error('Error updating status:', error);
            alert('Ошибка при соединении с сервером');
        }
    });
});

document.getElementById('filter-submit').addEventListener('click', async () => {
    const type = document.getElementById('filter-type').value;
    const status = document.getElementById('filter-status').value;
    const query = document.getElementById('filter-query').value;

    try {
        const response = await fetch('/admin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ type, status, query })
        });

        const result = await response.json();
        if (response.ok) {
            const container = document.getElementById('requests-container');
            container.innerHTML = ''; // Clear existing requests

            result.zayavki.forEach(z => {
                const card = document.createElement('div');
                card.className = `card ${z.urgent ? 'urgent' : ''}`;
                card.dataset.id = z.id;
                card.innerHTML = `
                    <h3>${z.type}</h3>
                    <p>${z.description}</p>
                    <p><strong>Дата:</strong> ${z.created_at}</p>
                    <p><strong>Статус:</strong> <span class="status">${z.status}</span></p>
                    <p><strong>Файл:</strong> ${
                        z.file
                            ? `<a href="/uploads/${z.file}" target="_blank">Скачать</a>`
                            : 'Нет файла'
                    }</p>
                    <div style="display: flex; gap: 10px; margin-top: 10px;">
                        <button class="btn styled-btn update-status" data-status="Сделано" style="background: #1cc88a;">Сделано</button>
                        <button class="btn styled-btn update-status" data-status="Отклонено" style="background: #e74a3b;">Отклонено</button>
                    </div>
                `;
                container.appendChild(card);
            });
        } else {
            alert(result.error || 'Ошибка при фильтрации заявок');
        }
    } catch (error) {
        console.error('Error fetching filtered requests:', error);
        alert('Ошибка при соединении с сервером');
    }
});