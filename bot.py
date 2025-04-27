from aiogram import Bot, Dispatcher, types
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.utils import executor
import os
from models import db, User, Zayavka # Предположим, что у вас есть база данных с моделями

# Убедитесь, что у вас есть ваш Telegram Token
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

bot = Bot(token=TELEGRAM_BOT_TOKEN)
dp = Dispatcher(bot)

# Создание кнопок для администратора
def admin_buttons():
    buttons = [
        InlineKeyboardButton("Просмотреть заявки", callback_data="view_requests"),
        InlineKeyboardButton("Сформировать отчёты", callback_data="generate_reports")
    ]
    return InlineKeyboardMarkup(row_width=1).add(*buttons)

# Функция отправки сообщения с кнопками
async def send_welcome_message(user_id, role):
    if role == 'admin':
        welcome_message = (
            "Добро пожаловать, администратор! 👨‍💻\n"
            "Вы можете:\n"
            "1️⃣ Просмотреть все заявки.\n"
            "2️⃣ Сформировать отчёты.\n"
        )
        buttons = admin_buttons()
    
    # Отправляем сообщение с кнопками
    await bot.send_message(user_id, welcome_message, reply_markup=buttons)

# Хэндлер на команду /start
@dp.message_handler(commands=['start'])
async def start(message: types.Message):
    user_id = message.from_user.id
    role = 'admin'  # Устанавливаем роль как 'admin', так как мы убрали сотрудников

    # Отправляем приветственное сообщение с кнопками
    await send_welcome_message(user_id, role)

# Обработчик нажатия кнопок
@dp.callback_query_handler(lambda c: c.data)
async def process_callback_button(callback_query: types.CallbackQuery):
    user_id = callback_query.from_user.id
    callback_data = callback_query.data

    # Обрабатываем разные типы кнопок
    if callback_data == "view_requests":
        # Просмотр заявок для админа
        requests = db_session.query(Zayavka).all()  # Предположим, что Zayavka - модель заявки
        response = "Список всех заявок:\n"
        for req in requests:
            response += f"🆔 {req.id}, Тип: {req.type}, Статус: {req.status}\n"
        await bot.send_message(user_id, response)

    elif callback_data == "generate_reports":
        # Логика генерации отчётов
        await bot.send_message(user_id, "Отчёты ещё не реализованы.")

if __name__ == '__main__':
    executor.start_polling(dp, skip_updates=True)
    db_session.global_init("sqlite:///your_database.db")  # Инициализация базы данных
    db_session.create_all()  # Создание всех таблиц, если они не существуют