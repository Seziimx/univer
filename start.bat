@echo off
echo [✔] Создание виртуального окружения...
python -3.11 -m venv venv

echo [✔] Активация окружения...
call venv\Scripts\activate

echo [✔] Установка зависимостей...
pip install --upgrade pip
pip install -r requirements.txt

echo [✔] Запуск приложения...
python app.py

echo.
pause

