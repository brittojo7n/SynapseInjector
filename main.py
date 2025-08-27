import sys
import os
import ctypes
import psutil
from typing import List, Dict
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QComboBox, QPushButton, QTextEdit, QLabel, QFrame, QMessageBox,
                             QCompleter, QStyleFactory)
from PyQt5.QtCore import Qt, QTimer, QStringListModel
from PyQt5.QtGui import QFont, QPalette, QColor, QTextCursor

# Windows API setup
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04

kernel32 = ctypes.windll.kernel32
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
                None, "SeDebugPrivilege", ctypes.byref(luid)
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

    def inject_dll(self, process_name: str, dll_path: str) -> (bool, str):
        if not os.path.exists(dll_path):
            return False, f"DLL file not found: {dll_path}"
        
        dll_path = os.path.abspath(dll_path)
        
        # Find process by name
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
            QToolTip { 
                color: #ffffff; 
                background-color: #2a2a2a; 
                border: 1px solid #767676; 
            }
            QComboBox QAbstractItemView {
                background-color: #191919;
                color: white;
                selection-background-color: #2a82da;
            }
            QComboBox::drop-down {
                border: none;
                background: #232323;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 4px solid none;
                border-right: 4px solid none;
                border-top: 5px solid white;
                border-bottom: 4px solid none;
            }
            QPushButton {
                background-color: #2a2a2a;
                border: 1px solid #3a3a3a;
                border-radius: 4px;
                padding: 6px;
            }
            QPushButton:hover {
                background-color: #3a3a3a;
                border: 1px solid #4a4a4a;
            }
            QPushButton:pressed {
                background-color: #1a1a1a;
            }
            QTextEdit {
                background-color: #191919;
                border: 1px solid #3a3a3a;
                border-radius: 4px;
                color: #e0e0e0;
            }
            QLabel {
                color: #e0e0e0;
            }
        """)


class SynapseInjectorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.injector = DLLInjector()
        self.processes = []
        self.init_ui()
        self.refresh_processes()
        
        # Set up a timer to refresh processes every 5 seconds
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_processes)
        self.timer.start(5000)
    
    def init_ui(self):
        self.setWindowTitle("Synapse Injector")
        self.setGeometry(300, 300, 700, 500)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        
        # Title
        title_label = QLabel("Synapse Injector")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Process selection
        process_layout = QHBoxLayout()
        process_layout.addWidget(QLabel("Process:"))
        
        self.process_combo = QComboBox()
        self.process_combo.setEditable(True)
        self.process_combo.setInsertPolicy(QComboBox.NoInsert)
        self.process_combo.completer().setCompletionMode(QCompleter.PopupCompletion)
        self.process_combo.setMinimumWidth(250)
        process_layout.addWidget(self.process_combo)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_processes)
        process_layout.addWidget(refresh_btn)
        
        process_layout.addStretch()
        layout.addLayout(process_layout)
        
        # DLL selection
        dll_layout = QHBoxLayout()
        dll_layout.addWidget(QLabel("DLL Path:"))
        
        self.dll_combo = QComboBox()
        self.dll_combo.setEditable(True)
        self.dll_combo.setMinimumWidth(300)
        dll_layout.addWidget(self.dll_combo)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_dll)
        dll_layout.addWidget(browse_btn)
        
        dll_layout.addStretch()
        layout.addLayout(dll_layout)
        
        # Inject button
        self.inject_btn = QPushButton("Inject DLL")
        self.inject_btn.clicked.connect(self.inject)
        self.inject_btn.setMinimumHeight(40)
        layout.addWidget(self.inject_btn)
        
        # Console
        layout.addWidget(QLabel("Console:"))
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        layout.addWidget(self.console)
        
        self.log_message("Synapse Injector initialized. Ready to inject.")
    
    def refresh_processes(self):
        self.processes = self.injector.get_processes()
        current_text = self.process_combo.currentText()
        
        self.process_combo.clear()
        process_names = sorted({p['name'] for p in self.processes}, key=lambda x: x.lower())
        self.process_combo.addItems(process_names)
        
        # Try to restore the previous selection
        index = self.process_combo.findText(current_text)
        if index >= 0:
            self.process_combo.setCurrentIndex(index)
        else:
            self.process_combo.setCurrentIndex(-1)
    
    def browse_dll(self):
        from PyQt5.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select DLL File", "", "DLL Files (*.dll);;All Files (*)"
        )
        if file_path:
            self.dll_combo.setCurrentText(file_path)
            # Add to recent DLLs if not already there
            if self.dll_combo.findText(file_path) == -1:
                self.dll_combo.addItem(file_path)
    
    def inject(self):
        process_name = self.process_combo.currentText().strip()
        dll_path = self.dll_combo.currentText().strip()
        
        if not process_name:
            self.log_message("Error: Please select a process to inject into.")
            return
        
        if not dll_path:
            self.log_message("Error: Please specify a DLL path.")
            return
        
        self.log_message(f"Attempting to inject {dll_path} into {process_name}...")
        self.inject_btn.setEnabled(False)
        QApplication.processEvents()  # Update UI
        
        success, message = self.injector.inject_dll(process_name, dll_path)
        
        if success:
            self.log_message(f"SUCCESS: {message}")
        else:
            self.log_message(f"ERROR: {message}")
        
        self.inject_btn.setEnabled(True)
    
    def log_message(self, message):
        timestamp = QApplication.instance().property("current_time") or ""
        self.console.append(f"[{timestamp}] {message}")
        self.console.moveCursor(QTextCursor.End)


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if __name__ == "__main__":
    if not is_admin():
        # Restart with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)
    
    app = QApplication(sys.argv)
    DarkTheme.apply(app)
    
    # Set a property to use for timestamps
    from datetime import datetime
    app.setProperty("current_time", datetime.now().strftime("%H:%M:%S"))
    
    window = SynapseInjectorGUI()
    window.show()
    
    sys.exit(app.exec_())