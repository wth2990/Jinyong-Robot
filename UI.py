from tkinter import *

class UI():
    Main_Display_Text = None;
    F = "fa";

    def __init__(self):
        self.root = Tk()
        from tkinter import ttk
        self.root.geometry("1800x1000")
        frm = ttk.Frame(self.root, padding=10)
        frm.grid()

        UI.Main_Display_Text = Text(frm, height = 30, width = 120);
        UI.Second_Display_Text = Text(frm, height = 30, width = 120);
        scrollbar1 = ttk.Scrollbar(frm)
        scrollbar1.pack(side = 'right',fill='y')
        scrollbar2 = ttk.Scrollbar(frm)
        scrollbar2.pack(side = 'right',fill='y')
        #text.tag_configure("red", foreground="red")
        UI.Main_Display_Text.tag_config('warning', background="white", foreground="red")
        UI.Second_Display_Text.tag_config('warning', background="white", foreground="red")

        UI.Main_Display_Text.yview('end')
        UI.Main_Display_Text.config(yscrollcommand=scrollbar1.set)
        UI.Second_Display_Text.config(yscrollcommand=scrollbar2.set)
        #ttk.Button(frm, text="Quit", command=root.destroy).grid(column=1, row=0)
        UI.Main_Display_Text.pack(side = LEFT);
        UI.Second_Display_Text.pack(side = LEFT)
        #Main_Display_Text.insert("end", "1111 Bold'...")

    @staticmethod
    def maintain():
        line_no_float = float(UI.Main_Display_Text.index('end'));
        line_no_int = int(line_no_float)
        if line_no_int > 50:
            UI.Main_Display_Text.delete("1.0", "10.0")
        else:
            print("Right")
        line_no_float = float(UI.Main_Display_Text.index('end'));
        line_no_int = int(line_no_float)
        print("No of Line: " + str(line_no_int));

    def start(self):
        self.root.mainloop()
