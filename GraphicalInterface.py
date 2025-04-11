import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from tkinter import *
from tkinter import messagebox
from tkinter import ttk


class GraphicalInterface:
    def __init__(self, window):
        self.window = window
        self.window.title("NetManager")
        self.window.geometry("1366x768")
        self.window.resizable(False, False)
        self.window['background'] = '#FFFFF0'
        self.canvas = self.prepare_first_screen()
        self.table_shown = False
        self.next_button1 = None
        self.table_devices = None
        self.table_shown2 = False
        self.vulns_table = None
        self.data = []
        self.data2 = ''

    def create_rounded_rect(self, canvas, x1, y1, x2, y2, radius, **kwargs):
        points = [x1 + radius, y1,
                  x1 + radius, y1,
                  x2 - radius, y1,
                  x2 - radius, y1,
                  x2, y1,
                  x2, y1 + radius,
                  x2, y1 + radius,
                  x2, y2 - radius,
                  x2, y2 - radius,
                  x2, y2,
                  x2 - radius, y2,
                  x2 - radius, y2,
                  x1 + radius, y2,
                  x1 + radius, y2,
                  x1, y2,
                  x1, y2 - radius,
                  x1, y2 - radius,
                  x1, y1 + radius,
                  x1, y1 + radius,
                  x1, y1]
        return canvas.create_polygon(points, **kwargs, smooth=True, tags='button')

    def prepare_first_screen(self):
        canvas = Canvas(self.window, width=700, height=600, highlightthickness=0, bg="#FFFFF0")
        self.create_rounded_rect(canvas, 300, 279, 1066, 489, 50, fill='#5D4BD8')
        text = canvas.create_text(683, 384, font="Oswald 64", text='Просканировать\n          сеть', fill='#FFFFFF',
                                  tags='button')
        return canvas

    def create_next1_btn(self):
        button_width = 200
        button_height = 50
        self.next_button1 = Canvas(self.window, width=button_width, height=button_height, highlightthickness=0,
                                   bg="#FFFFF0")
        self.create_rounded_rect(self.next_button1, 0, 0, button_width, button_height, 25, fill='#5D4BD8')
        text = self.next_button1.create_text(button_width // 2, button_height // 2, font="Oswald 32", text='Дальше',
                                             fill='#FFFFFF', tags='button')

    def show_table(self, initial_data):
        if self.table_shown:
            return
        self.table_shown = True
        for widget in self.window.winfo_children():
            if widget != self.canvas:
                widget.destroy()

        self.data = []
        columns = ("ip", "mac", "тип")
        self.data = [{"ip": item["ip"], "mac": item["mac"], "тип": item["type"]} for item in initial_data]
        self.options = ["Камера", "Лампа", "Розетка", "Термостат", "Принтер", "Датчик", "Выключатель", "Счётчик",
                        "Замок", "Пропустить устройство"]

        self.table_devices = Frame(self.window, bg="#FFFFF0")
        self.table_devices.pack(pady=10, padx=10, fill="both", expand=True)

        header_width_ip = 10
        header_width_mac = 20
        header_width_type = 30

        header_label_ip = Label(self.table_devices, text=columns[0], width=header_width_ip, font="Oswald 32",
                                fg="white", bg="#5D4BD8")
        header_label_ip.grid(row=0, column=0, sticky="nsew")

        header_label_mac = Label(self.table_devices, text=columns[1], width=header_width_mac, font="Oswald 32",
                                 fg="white", bg="#5D4BD8")
        header_label_mac.grid(row=0, column=1, sticky="nsew")

        header_label_type = Label(self.table_devices, text=columns[2], width=header_width_type, font="Oswald 32",
                                  fg="white", bg="#5D4BD8")
        header_label_type.grid(row=0, column=2, sticky="nsew")

        for row_index, item in enumerate(self.data):
            ip_width = 10
            mac_width = 20
            type_width = 30

            ip_label = Label(self.table_devices, text=item["ip"], width=ip_width, font="Oswald 20", bg="#FFFFF0")
            ip_label.grid(row=row_index + 1, column=0, sticky="nsew")

            mac_label = Label(self.table_devices, text=item["mac"], width=mac_width, font="Oswald 20", bg="#FFFFF0")
            mac_label.grid(row=row_index + 1, column=1, sticky="nsew")

            current_option = StringVar(self.window)
            current_option.set(item['тип'])
            dropdown = OptionMenu(self.table_devices, current_option, *self.options,
                                  command=lambda value, row=row_index: self.on_dropdown_changed(row, value))
            dropdown.config(width=type_width, font="Oswald 20", background="#E0FFFF", activebackground="#87CEFA")
            dropdown["menu"].config(bg="#87CEFA", font=("Oswald", 14))
            dropdown.grid(row=row_index + 1, column=2, sticky="nsew")

    def on_dropdown_changed(self, row, selected_value):
        self.data[row]["тип"] = selected_value

    class ReportSender:
        def __init__(self):
            pass

        def send_email_with_attachment(self, sender_email, sender_password, recipient_email, file_path):
            smtp_server = "smtp.mail.ru"
            smtp_port = 587

            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = recipient_email
            msg['Subject'] = "Отчет об уязвимостях"

            body = "Привет! В приложении находится отчет об обнаруженных уязвимостях."
            msg.attach(MIMEText(body, 'plain'))

            with open(file_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={file_path.split("/")[-1]}')
                msg.attach(part)

            try:
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.starttls()
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, recipient_email, msg.as_string())
                messagebox.showinfo("Успех", "Письмо с отчетом успешно отправлено!")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка при отправке: {e}")
            finally:
                server.quit()

    def export_and_send_data(self):
        try:
            import xlwt
            from datetime import datetime
            from email_password import password

            columns = ("№", "IP", "MAC", "Тип", "Уязвимость", "Описание", "Угрозы", "Методы")

            wb = xlwt.Workbook()
            ws = wb.add_sheet('Уязвимости')

            for col_index, col_name in enumerate(columns):
                ws.write(0, col_index, col_name)

            for row_index, item in enumerate(self.data):
                for col_index, col_name in enumerate(columns):
                    ws.write(row_index + 1, col_index, str(item[col_name]))

            filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xls"
            wb.save(filename)

            sender = self.ReportSender()
            sender.send_email_with_attachment(
                sender_email="someuseranonym@mail.ru",
                sender_password=password,
                recipient_email="recipient@example.com",
                file_path=filename
            )

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при экспорте/отправке: {str(e)}")

    def show_vulns_table(self, mac_vulnerabilities):
        """Creates a table with email form before sending"""
        if self.table_shown2:
            return
        self.table_shown2 = True

        # Clear existing widgets
        for widget in self.window.winfo_children():
            if widget != self.canvas:
                widget.destroy()

        # Prepare data
        columns = ("№", "IP", "MAC", "Type", "Vulnerability", "Description", "Threats", "Methods")
        self.data = []
        counter = 1

        for mac, vulnerabilities in mac_vulnerabilities.items():
            unique_vulns = {}
            for vuln in vulnerabilities:
                if vuln.name not in unique_vulns:
                    unique_vulns[vuln.name] = vuln

            for vuln in unique_vulns.values():
                self.data.append({
                    "№": counter,
                    "IP": vuln.ip,
                    "MAC": mac,
                    "Type": vuln.type,
                    "Vulnerability": vuln.name,
                    "Description": vuln.desc,
                    "Threats": vuln.threats,
                    "Methods": vuln.methods
                })
                counter += 1

        # Main container
        main_container = Frame(self.window, bg="#FFFFF0")
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Table container
        table_container = Frame(main_container, bg="#FFFFF0")
        table_container.pack(fill="both", expand=True)

        # Canvas and scrollbar
        canvas = Canvas(table_container, bg="#FFFFF0", highlightthickness=0)
        scrollbar = Scrollbar(table_container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all"))

        canvas.pack(side="left", fill="both", expand=True, padx=(0, 15))
        scrollbar.pack(side="right", fill="y", padx=(0, 5))

        # Table frame
        table_frame = Frame(canvas, bg="#FFFFF0")
        canvas.create_window((0, 0), window=table_frame, anchor="nw")

        # Column widths
        col_widths = {
            "№": 5, "IP": 15, "MAC": 20, "Type": 15,
            "Vulnerability": 25, "Description": 40,
            "Threats": 25, "Methods": 20
        }

        # Headers
        for col_index, col_name in enumerate(columns):
            Label(
                table_frame,
                text=col_name,
                width=col_widths[col_name],
                font=("Oswald", 10, "bold"),
                fg="white",
                bg="#5D4BD8",
                anchor="center",
                padx=5,
                pady=5
            ).grid(row=0, column=col_index, sticky="nsew")

        # Rows
        for row_index, item in enumerate(self.data):
            row_bg = "#FFFFF0" if row_index % 2 == 0 else "#F5F5DC"
        for col_index, col_name in enumerate(columns):
            Label(
                table_frame,
                text=str(item[col_name]),
                width=col_widths[col_name],
                font=("Oswald", 9),
                bg=row_bg,
                anchor="nw",
                justify="left",
                wraplength=col_widths[col_name] * 8,
                padx=5,
                pady=2
            ).grid(row=row_index + 1, column=col_index, sticky="nsew")

        # Grid config
        for i in range(len(columns)):
            table_frame.grid_columnconfigure(i, weight=1)

            # Scrolling

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # Export button - now shows email form
        Button(
            main_container,
            text="Export and Send Report",
            command=self.show_email_form,
            bg="#5D4BD8",
            fg="white",
            font=("Oswald", 12),
            padx=20,
            pady=10
        ).pack(pady=20, ipadx=30)

        self.window.update_idletasks()

    def show_email_form(self):
        """Shows email input form"""
        self.email_window = Toplevel(self.window)
        self.email_window.title("Enter Recipient Email")
        self.email_window.geometry("400x200")
        self.email_window.resizable(False, False)
        self.email_window['background'] = '#FFFFF0'

        Label(
            self.email_window,
            text="Recipient Email Address:",
            font=("Oswald", 12),
            bg="#FFFFF0"
        ).pack(pady=20)

        self.email_entry = Entry(
            self.email_window,
            font=("Oswald", 12),
            width=30
        )
        self.email_entry.pack(pady=10)

        Button(
            self.email_window,
            text="Send Report",
            command=self.send_report_with_email,
            bg="#5D4BD8",
            fg="white",
            font=("Oswald", 12),
            padx=15,
            pady=5
        ).pack(pady=10)

    def send_report_with_email(self):
        """Handles report sending with email from form"""
        recipient_email = self.email_entry.get()

        if not recipient_email or '@' not in recipient_email:
            messagebox.showerror("Error", "Please enter a valid email address")
            return

        try:
            import xlwt
            from datetime import datetime
            from email_password import password

            columns = ("№", "IP", "MAC", "Type", "Vulnerability", "Description", "Threats", "Methods")

            wb = xlwt.Workbook()
            ws = wb.add_sheet('Vulnerabilities')

            # Write headers
            for col_index, col_name in enumerate(columns):
                ws.write(0, col_index, col_name)

            # Write data
            for row_index, item in enumerate(self.data):
                for col_index, col_name in enumerate(columns):
                    ws.write(row_index + 1, col_index, str(item[col_name]))

            filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xls"
            wb.save(filename)

            # Send email
            sender = self.ReportSender()
            sender.send_email_with_attachment(
                sender_email="someuseranonym@mail.ru",
                sender_password=password,
                recipient_email=recipient_email,
                file_path=filename
            )

            self.email_window.destroy()
            messagebox.showinfo("Success", "Report sent successfully!")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to send report: {str(e)}")

    class ReportSender:
        """Handles email sending functionality"""

        def __init__(self):
            pass

        def send_email_with_attachment(self, sender_email, sender_password, recipient_email, file_path):
            smtp_server = "smtp.mail.ru"
            smtp_port = 587

            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = recipient_email
            msg['Subject'] = "Vulnerability Report"

            body = "Please find attached the vulnerability report."
            msg.attach(MIMEText(body, 'plain'))

            with open(file_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={file_path.split("/")[-1]}')
                msg.attach(part)

            try:
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.starttls()
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, recipient_email, msg.as_string())
            finally:
                server.quit()