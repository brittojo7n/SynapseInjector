import sys
import os
import ctypes
from ctypes import wintypes
import psutil
from typing import List, Dict
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QComboBox, QPushButton, QTextEdit, QLabel, QCompleter, QStyleFactory, QLineEdit
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QPalette, QColor, QTextCursor

# Windows API setup
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04

kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
dwmapi = ctypes.windll.dwmapi

kernel32.OpenProcess.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_uint]
kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = ctypes.c_int
kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
kernel32.GetProcAddress.restype = ctypes.c_void_p
kernel32.GetModuleHandleA.argtypes = [ctypes.c_char_p]
kernel32.GetModuleHandleA.restype = ctypes.c_void_p
kernel32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
kernel32.CreateRemoteThread.restype = ctypes.c_void_p
kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
kernel32.WaitForSingleObject.restype = ctypes.c_ulong
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = ctypes.c_int
kernel32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
kernel32.VirtualFreeEx.restype = ctypes.c_int


class DLLInjector:
    def __init__(self):
        self.enable_debug_privilege()
    
    def enable_debug_privilege(self):
        try:
            TOKEN_ADJUST_PRIVILEGES = 0x20
            TOKEN_QUERY = 0x8
            SE_PRIVILEGE_ENABLED = 0x2
            
            class LUID(ctypes.Structure):
                _fields_ = [("LowPart", ctypes.c_uint), ("HighPart", ctypes.c_long)]
            
            class LUID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_uint)]
            
            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [("PrivilegeCount", ctypes.c_uint), ("Privileges", LUID_AND_ATTRIBUTES)]
            
            token = ctypes.c_void_p()
            if not ctypes.windll.advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(), 
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
                ctypes.byref(token)
            ):
                return False
            
            luid = LUID()
            if not ctypes.windll.advapi32.LookupPrivilegeValueA(
                None, b"SeDebugPrivilege", ctypes.byref(luid)
            ):
                ctypes.windll.kernel32.CloseHandle(token)
                return False
            
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges.Luid = luid
            tp.Privileges.Attributes = SE_PRIVILEGE_ENABLED
            
            if not ctypes.windll.advapi32.AdjustTokenPrivileges(
                token, False, ctypes.byref(tp), 0, None, None
            ):
                ctypes.windll.kernel32.CloseHandle(token)
                return False
            
            ctypes.windll.kernel32.CloseHandle(token)
            return True
            
        except Exception:
            return False

    def get_processes(self) -> List[Dict]:
        processes = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                })
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
            
            allocated_memory = kernel32.VirtualAllocEx(
                process_handle, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
            )
            
            if not allocated_memory:
                return False, f"Failed to allocate memory in process {target_pid}"
            
            bytes_written = ctypes.c_size_t(0)
            success = kernel32.WriteProcessMemory(
                process_handle, allocated_memory, dll_path_bytes, size, ctypes.byref(bytes_written)
            )
            
            if not success or bytes_written.value != size:
                return False, f"Failed to write to process memory. Error: {ctypes.get_last_error()}"
            
            kernel32_handle = kernel32.GetModuleHandleA(b"kernel32.dll")
            load_library_addr = kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryA")
            
            if not load_library_addr:
                return False, "Failed to get LoadLibraryA address"
            
            thread_handle = kernel32.CreateRemoteThread(
                process_handle, None, 0, load_library_addr, allocated_memory, 0, None
            )
            
            if not thread_handle:
                return False, f"Failed to create remote thread. Error: {ctypes.get_last_error()}"
            
            kernel32.WaitForSingleObject(thread_handle, 5000)
            
            return True, f"Successfully injected DLL into process '{process_name}' (PID: {target_pid})"
            
        except Exception as e:
            return False, f"Error during injection: {str(e)}"
        finally:
            if allocated_memory and process_handle:
                kernel32.VirtualFreeEx(process_handle, allocated_memory, 0, 0x8000)
            if thread_handle:
                kernel32.CloseHandle(thread_handle)
            if process_handle:
                kernel32.CloseHandle(process_handle)

class DarkTheme:
    @staticmethod
    def apply(app):
        app.setStyle(QStyleFactory.create("Fusion"))
        
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(18, 18, 18))
        dark_palette.setColor(QPalette.AlternateBase, QColor(35, 35, 35))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(40, 40, 40))
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(35, 35, 35))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        
        app.setPalette(dark_palette)

        app.setStyleSheet("""
            QMainWindow { background-color: #191919; color: white; border: 1px solid #333; }
            QWidget { background-color: #191919; color: white; }
            QToolTip { color: #ffffff; background-color: #2a2a2a; border: 1px solid #767676; }
            QComboBox {
                background-color: #232323; color: white; border: 1px solid #3a3a3a;
                border-radius: 4px; padding: 5px; padding-left: 10px; selection-background-color: #2a82da;
            }
            QComboBox QAbstractItemView {
                background-color: #191919; color: white; selection-background-color: #2a82da;
                border: 1px solid #3a3a3a;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 25px;
                border-left-width: 1px;
                border-left-color: #3a3a3a;
                border-left-style: solid;
                border-top-right-radius: 3px;
                border-bottom-right-radius: 3px;
            }
            QComboBox::down-arrow {
                /* This is the standard, working method for creating the symbol */
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 6px solid white;
                width: 0px;
                height: 0px;
            }
            QPushButton {
                background-color: #2a2a2a; color: white; border: 1px solid #3a3a3a;
                border-radius: 4px; padding: 8px; font-weight: bold;
            }
            QPushButton:hover { background-color: #3a3a3a; border: 1px solid #4a4a4a; }
            QPushButton:pressed { background-color: #1a1a1a; }
            QPushButton:disabled { background-color: #1a1a1a; color: #666; }
            QTextEdit {
                background-color: #191919; color: #e0e0e0; border: 1px solid #3a3a3a;
                border-radius: 4px; font-family: Consolas, 'Courier New', monospace;
            }
            QLabel { color: #e0e0e0; background-color: transparent; }
            QStatusBar { background-color: #1a1a1a; color: #e0e0e0; }
        """)

class SynapseInjectorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.injector = DLLInjector()
        self.processes = []
        self.init_ui()
        self.refresh_processes()
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_processes)
        self.timer.start(5000)
    
    def init_ui(self):
        self.setWindowTitle("Synapse Injector")
        self.setFixedSize(800, 600)
        
        try:
            if hasattr(ctypes.windll.dwmapi, 'DwmSetWindowAttribute'):
                DWMWA_USE_IMMERSIVE_DARK_MODE = 20
                value = ctypes.c_int(1)
                hwnd = self.winId().__int__()
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    ctypes.c_void_p(hwnd), DWMWA_USE_IMMERSIVE_DARK_MODE, 
                    ctypes.byref(value), ctypes.sizeof(value)
                )
        except Exception as e:
            print(f"Could not set dark title bar: {e}")
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)
        
        title_label = QLabel("Synapse Injector")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("""
            QLabel {
                color: #e0e0e0; background-color: transparent;
                padding: 10px; border-bottom: 2px solid #2a82da;
            }
        """)
        layout.addWidget(title_label)
        
        # Process selection
        process_layout = QHBoxLayout()
        process_label = QLabel("Target Process:")
        process_label.setFixedWidth(100)
        process_layout.addWidget(process_label)
        
        self.process_combo = QComboBox()
        self.process_combo.setEditable(True)
        self.process_combo.setInsertPolicy(QComboBox.NoInsert)
        self.process_combo.completer().setCompletionMode(QCompleter.PopupCompletion)
        self.process_combo.setMinimumWidth(300)
        process_layout.addWidget(self.process_combo)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_processes)
        refresh_btn.setFixedWidth(80)
        process_layout.addWidget(refresh_btn)
        
        process_layout.addStretch()
        layout.addLayout(process_layout)
        
        # DLL selection
        dll_layout = QHBoxLayout()
        dll_label = QLabel("DLL Path:")
        dll_label.setFixedWidth(100)
        dll_layout.addWidget(dll_label)
        
        self.dll_path_input = QLineEdit()
        self.dll_path_input.setPlaceholderText("Enter DLL path or click Browse...")
        self.dll_path_input.setMinimumWidth(300)
        self.dll_path_input.setStyleSheet("""
            QLineEdit {
                background-color: #232323; color: white; border: 1px solid #3a3a3a;
                border-radius: 4px; padding: 5px; selection-background-color: #2a82da;
            }
        """)
        dll_layout.addWidget(self.dll_path_input)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_dll)
        browse_btn.setFixedWidth(80)
        dll_layout.addWidget(browse_btn)
        
        dll_layout.addStretch()
        layout.addLayout(dll_layout)
        
        # Inject button
        self.inject_btn = QPushButton("INJECT DLL")
        self.inject_btn.clicked.connect(self.inject)
        self.inject_btn.setMinimumHeight(45)
        self.inject_btn.setStyleSheet("""
            QPushButton {
                background-color: #2a82da; color: white; border: none;
                border-radius: 4px; font-weight: bold; font-size: 14px;
            }
            QPushButton:hover { background-color: #3a92ea; }
            QPushButton:pressed { background-color: #1a72ca; }
            QPushButton:disabled { background-color: #1a1a1a; color: #666; }
        """)
        layout.addWidget(self.inject_btn)
        
        console_label = QLabel("Console Output:")
        layout.addWidget(console_label)
        
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        layout.addWidget(self.console)
        
        self.statusBar().showMessage("Ready")
        self.log_message("Synapse Injector initialized. Ready to inject.")
    
    def refresh_processes(self):
        try:
            self.processes = self.injector.get_processes()
            current_text = self.process_combo.currentText()
            
            self.process_combo.blockSignals(True)
            self.process_combo.clear()
            process_names = sorted({p['name'] for p in self.processes}, key=lambda x: x.lower())
            self.process_combo.addItems(process_names)
            
            index = self.process_combo.findText(current_text)
            if index >= 0:
                self.process_combo.setCurrentIndex(index)
            else:
                self.process_combo.setCurrentIndex(-1)
            self.process_combo.blockSignals(False)
            
            self.statusBar().showMessage(f"Found {len(process_names)} processes")
        except Exception as e:
            self.log_message(f"Error refreshing processes: {e}")
    
    def browse_dll(self):
        from PyQt5.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select DLL File", "", "DLL Files (*.dll);;All Files (*)"
        )
        if file_path:
            self.dll_path_input.setText(file_path)
    
    def inject(self):
        process_name = self.process_combo.currentText().strip()
        dll_path = self.dll_path_input.text().strip()
        
        if not process_name:
            self.log_message("Error: Please select a process to inject into.")
            return
        
        if not dll_path:
            self.log_message("Error: Please specify a DLL path.")
            return
        
        self.log_message(f"Attempting to inject {dll_path} into {process_name}...")
        self.statusBar().showMessage("Injecting...")
        self.inject_btn.setEnabled(False)
        QApplication.processEvents()
        
        success, message = self.injector.inject_dll(process_name, dll_path)
        
        if success:
            self.log_message(f"SUCCESS: {message}")
            self.statusBar().showMessage("Injection successful")
        else:
            self.log_message(f"ERROR: {message}")
            self.statusBar().showMessage("Injection failed")
        
        self.inject_btn.setEnabled(True)
    
    def log_message(self, message):
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.append(f"[{timestamp}] {message}")
        self.console.moveCursor(QTextCursor.End)


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if __name__ == "__main__":
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

    # High DPI scaling on modern displays
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    app = QApplication(sys.argv)
    DarkTheme.apply(app)
    
    window = SynapseInjectorGUI()
    window.show()
    
    sys.exit(app.exec_())