import telebot

def send_telegram_message(message):
    # Membuat objek bot
    token = 'CHATBOT_TOKEN'
    chat_id = 'CHATID_BOT_TELEGRAM'
    bot = telebot.TeleBot(token)

    try:
        # Mengirim pesan
        bot.send_message(chat_id, message)
        print("Pesan berhasil dikirim!")
    except Exception as e:
        print(f"Terjadi kesalahan: {e}")

# Contoh penggunaan fungsi
if __name__ == "__main__":

    MESSAGE = 'TEST MESSAGE'
    
    send_telegram_message(MESSAGE)
