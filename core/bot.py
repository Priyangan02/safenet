import telebot

def send_telegram_message(message):
    # Membuat objek bot
    token = '7348981254:AAF2_e38Oe0Zo2x8xEldtLqXTipP9pZyp1k'
    chat_id = '1406910249'
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
