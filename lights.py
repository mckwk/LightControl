import tkinter as tk
from tkinter import ttk
from yeelight import Bulb
import nmap
from mac_vendor_lookup import MacLookup
import threading
from PIL import Image, ImageTk
import socket
import netifaces

nmap_path = [r"C:\Nmap\nmap.exe"]

class BulbControllerApp:
    def __init__(self, root):
        self.root = root
        self.configure_root()
        self.initialize_styles()
        self.bulbs = []
        self.bulb_widgets = {}

        self.main_frame = ttk.Frame(root, style="TFrame")
        self.bulb_frame = ttk.Frame(self.main_frame, style="TFrame")

        self.lightbulb_icon = self.load_icon("res/lightbulb.png", (20, 20))

        self.refresh_bulbs()

    def configure_root(self):
        self.root.title("")
        self.root.attributes("-alpha", 0.9)
        self.root.overrideredirect(True)
        self.root.wm_attributes("-transparentcolor", self.root["bg"])
        self.root.geometry("1x1+0+0")
        self.root.config(bg="white")
        self.root.update_idletasks()

    def initialize_styles(self):
        style = ttk.Style()
        style.configure("TFrame", padding=10, background="white")
        style.configure("TButton", padding=5, background="white")
        style.configure("TLabel", padding=5, background="white")
        style.configure("TScale", background="white", troughcolor="gray")

    def load_icon(self, path, size):
        image = Image.open(path).resize(size)
        return ImageTk.PhotoImage(image)

    def refresh_bulbs(self):
        self.clear_bulb_widgets()
        threading.Thread(target=self.scan_and_update_bulbs).start()

    def clear_bulb_widgets(self):
        for widget in self.bulb_frame.winfo_children():
            widget.destroy()

    def scan_and_update_bulbs(self):
        self.bulbs = self.scan_network_for_bulbs()
        if self.bulbs:
            self.show_main_frame()
            self.update_window_height()

        for bulb_info in self.bulbs:
            bulb = Bulb(bulb_info["ip"])
            self.create_bulb_widget(bulb)

    def show_main_frame(self):
        self.main_frame.pack(fill="both", expand=True)
        self.bulb_frame.pack(pady=5, fill="both", expand=True)

    def update_window_height(self):
        new_height = len(self.bulbs) * 50
        screen_width = self.root.winfo_screenwidth()
        self.root.geometry(f"400x{new_height}+{screen_width-400}+0")
        self.root.resizable(True, True)

    def get_network_range(self):
        local_ip = socket.gethostbyname(socket.gethostname())
        netmask = self.get_netmask(local_ip)

        if netmask:
            network_parts = [
                str(int(ip_part) & int(mask_part))
                for ip_part, mask_part in zip(local_ip.split("."), netmask.split("."))
            ]
            return ".".join(network_parts) + "/24"
        return None

    def get_netmask(self, local_ip):
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if addr["addr"] == local_ip:
                        return addr.get("netmask")
        return None

    def scan_network_for_bulbs(self):
        network_range = self.get_network_range()
        if not network_range:
            return []

        nm = nmap.PortScanner(nmap_search_path=nmap_path)
        nm.scan(hosts=network_range, arguments="-sn")
        return self.extract_bulbs_from_scan(nm)

    def extract_bulbs_from_scan(self, nm):
        bulbs = []
        mac_lookup = MacLookup()

        for host in nm.all_hosts():
            mac = nm[host]["addresses"].get("mac")
            if mac:
                vendor = self.lookup_vendor(mac, mac_lookup)
                if vendor and "xiaomi" in vendor.lower():
                    bulbs.append({"ip": nm[host]["addresses"]["ipv4"], "mac": mac})

        return bulbs

    def lookup_vendor(self, mac, mac_lookup):
        try:
            return mac_lookup.lookup(mac)
        except Exception:
            return None

    def create_bulb_widget(self, bulb):
        frame = ttk.Frame(self.bulb_frame, style="TFrame")
        frame.pack(pady=5, fill="x")

        icon_label = ttk.Label(frame, image=self.lightbulb_icon, style="TLabel")
        icon_label.pack(side="left", padx=(10, 5))

        label = ttk.Label(frame, text=f"Bulb {bulb._ip}", style="TLabel")
        label.pack(side="left", padx=5)

        bulb_state = tk.BooleanVar(value=bulb.get_properties().get("power") == "on")

        toggle_button = ttk.Button(
            frame,
            text="On" if bulb_state.get() else "Off",
            command=lambda: self.toggle_bulb(bulb, bulb_state, toggle_button),
            style="TButton",
        )
        toggle_button.pack(side="right", padx=5)

        brightness_slider = ttk.Scale(
            frame,
            from_=1,
            to=100,
            orient="horizontal",
            command=lambda val: self.set_brightness(
                bulb, int(float(val)), bulb_state, toggle_button
            ),
            style="TScale",
        )
        brightness_slider.pack(side="right", padx=10)

        self.bulb_widgets[bulb._ip] = {
            "frame": frame,
            "icon_label": icon_label,
            "label": label,
            "toggle_button": toggle_button,
            "brightness_slider": brightness_slider,
            "bulb_state": bulb_state,
        }

    def toggle_bulb(self, bulb, bulb_state, toggle_button):
        if bulb_state.get():
            bulb.turn_off()
            bulb_state.set(False)
            toggle_button.config(text="Off")
        else:
            bulb.turn_on()
            bulb_state.set(True)
            toggle_button.config(text="On")

    def set_brightness(self, bulb, brightness, bulb_state, toggle_button):
        if not bulb_state.get():
            bulb.turn_on()
            bulb_state.set(True)
            toggle_button.config(text="On")
        bulb.set_brightness(brightness)


if __name__ == "__main__":
    root = tk.Tk()
    app = BulbControllerApp(root)
    root.mainloop()