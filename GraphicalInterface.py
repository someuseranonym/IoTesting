from tkinter import *
from tkinter import messagebox
from tkinter import ttk


class GraphicalInterface:
    def __init__(self, window):
        self.window = window
        self.window.title("NetManager")
        self.window.geometry("1366x768")
        self.window.resizable(False, False)
        # large_icon = PhotoImage(file="icon.png")
        # self.window.iconphoto(False, large_icon) # Removed, assuming icon.png isn't available
        self.window['background'] = '#FFCDA9'
        self.canvas = self.prepare_first_screen()
        self.table_shown = False
        self.next_button1 = None
        self.table_devices = None
        self.table_shown2 = False
        self.vulns_table = None
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

    '''def key(self, event):
        print("pressed", repr(event.char))'''

    def prepare_first_screen(self):
        canvas = Canvas(self.window, width=700, height=600, highlightthickness=0, bg="#FFCDA9")
        self.create_rounded_rect(canvas, 9, 300, 670, 510, 50, fill='#5E85CB')
        text = canvas.create_text(340, 390, font="Arial 64", text='Просканировать\nсеть', fill='#FFFFFF', tags='button')
        return canvas

    def show_table(self, initial_data):
        """Shows a table with editable dropdowns."""
        if self.table_shown:
            return
        self.table_shown = True
        for widget in self.window.winfo_children():
            if widget != self.canvas:
                widget.destroy()

        self.data = []
        print(initial_data)
        columns = ("ip", "mac", "тип")
        self.data = [{"ip": item["ip"], "mac": item["mac"], "тип": item["type"]} for item in initial_data]
        self.options = ["Камера", "Лампа", "Розетка", "Термостат", "Принтер", "Датчик", "Выключатель", "Счётчик",
                        "Замок",
                        "Пропустить устройство"]

        self.table_devices = Frame(self.window)
        self.table_devices.pack(pady=10, padx=10, fill="both", expand=True)

        # Column Headers
        for col_index, col_name in enumerate(columns):
            header_label = Label(self.table_devices, text=col_name, width=20, bg="#EEEEEE")
            header_label.grid(row=0, column=col_index, sticky="nsew")  # Use grid for layout

        # Populate Table Rows
        for row_index, item in enumerate(self.data):
            ip_label = Label(self.table_devices, text=item["ip"], width=20)
            ip_label.grid(row=row_index + 1, column=0, sticky="nsew")

            mac_label = Label(self.table_devices, text=item["mac"], width=20)
            mac_label.grid(row=row_index + 1, column=1, sticky="nsew")

            # Add Dropdown to the last column
            self.create_dropdown(self.table_devices, row_index + 1, 2, item["тип"], self.options)

    def create_dropdown(self, parent, row, column, initial_value, options):  # added parent
        """Creates a dropdown for the last column of a specific row, but integrated."""
        # A StringVar that will be used with the OptionMenu
        current_option = StringVar(self.window)  # Make it an instance variable

        # Set the default value
        current_option.set(initial_value)  # initial value

        # Create the OptionMenu
        dropdown = OptionMenu(parent, current_option, *options,
                              command=lambda value: self.on_dropdown_changed(row, value))

        dropdown.config(width=15)  # Set default width for OptionMenu

        dropdown.grid(row=row, column=column, sticky="nsew")  # Put in grid, not pack

    def on_dropdown_changed(self, row, selected_value):
        """Handles change of dropdown value."""
        self.data[row - 1]["type"] = selected_value  # updated
        print(f"Row: {row}, New Type: {selected_value}")

    def show_vulns_table(self, initial_data):
        """Creates a table with 7 columns using Labels and Grids."""
        if self.table_shown2:
            return
        self.table_shown2 = True
        for widget in self.window.winfo_children():
            if widget != self.canvas:
                widget.destroy()

        self.data = []
        print(initial_data)
        columns = ("№", "ip", "mac", "type", "vuln", "desc", "threats", 'methods')
        self.data = [{col: item[col] for col in columns} for item in initial_data]

        self.table_devices = Frame(self.window)
        self.table_devices.pack(pady=10, padx=10, fill="both", expand=True)

        # Column Headers
        for col_index, col_name in enumerate(columns):
            header_label = Label(self.table_devices, text=col_name, width=20, bg="#EEEEEE")
            header_label.grid(row=0, column=col_index, sticky="nsew")  # Use grid for layout

        # Populate Table Rows
        for row_index, item in enumerate(self.data):
            for col_index, col_name in enumerate(columns):
                cell_label = Label(self.table_devices, text=item[col_name], width=20)
                cell_label.grid(row=row_index + 1, column=col_index, sticky="nsew")
