from flask import Flask
from aiogram import Bot, Dispatcher, types
from aiogram.utils import executor
import os
from dotenv import load_dotenv  # Для загрузки переменных окружения

# Загружаем переменные из .env файла
load_dotenv()

# Получаем токен бота из переменной окружения
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

# Проверяем, что токен загружен
if not TELEGRAM_BOT_TOKEN:
    raise ValueError("TELEGRAM_BOT_TOKEN не найден. Проверьте файл .env")

# Инициализация Flask и Aiogram
app = Flask(__name__)
bot = Bot(token=TELEGRAM_BOT_TOKEN)
dp = Dispatcher(bot)

# Функция для отправки приветственного сообщения
async def send_welcome_message(user_id):
    welcome_message = "Добро пожаловать в систему! 🎉"
    await bot.send_message(user_id, welcome_message)

# Хэндлер для команды /start
@dp.message_handler(commands=['start'])
async def start(message: types.Message):
    user_id = message.from_user.id
    # Отправляем приветственное сообщение
    await send_welcome_message(user_id)

# Запуск Aiogram в отдельном потоке
def run_aiogram():
    executor.start_polling(dp, skip_updates=True)

# Запуск Flask приложения
@app.route('/')
def index():
    return "Flask App is running!"

if __name__ == '__main__':
    from threading import Thread
    # Запуск Aiogram в отдельном потоке
    aiogram_thread = Thread(target=run_aiogram)
    aiogram_thread.start()
    
    # Запуск Flask приложения
    app.run(debug=True, use_reloader=False)
