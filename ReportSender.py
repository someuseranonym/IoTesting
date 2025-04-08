import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email_password import password
class ReportSender():
    def __init__(self):
        pass

    def send_email_with_attachment(self, sender_email, sender_password, recipient_email, file_path):
        # Настройка SMTP-сервера (для Mail.ru)
        smtp_server = "smtp.mail.ru"
        smtp_port = 587

        # Создание сообщения
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = "Файл 1.xls"

        # Текст письма (опционально)
        body = "Привет! В приложении находится файл 1.xls."
        msg.attach(MIMEText(body, 'plain'))

        # Прикрепление файла
        with open(file_path, "rb") as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename={file_path.split("/")[-1]}')
            msg.attach(part)

        # Отправка письма
        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()  # Шифрование TLS
            server.login(sender_email, sender_password)
            print('logged')
            server.sendmail(sender_email, recipient_email, msg.as_string())
            print("Письмо успешно отправлено!")
        except Exception as e:
            print(f"Ошибка при отправке: {e}")
        finally:
            server.quit()

sender_email = "someuseranonym@mail.ru"  # Замените на вашу почту
sender_password = password # Пароль или App Password (для Gmail)
recipient_email = "pochta"  # Почта получателя
file_path = "pass to file"  # Полный путь к файлу
sender = ReportSender()
sender.send_email_with_attachment(sender_email, sender_password, recipient_email, file_path)