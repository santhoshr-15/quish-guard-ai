import customtkinter as ctk
import pyautogui
import numpy as np
import cv2
from plyer import notification
import threading

# Import your existing engine
from main import scan_url

# Configuration for the GUI
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class QuishGuardApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("Quish-Guard AI")
        self.geometry("450x350")
        self.resizable(False, False)

        # Title Label
        self.label = ctk.CTkLabel(self, text="Quish-Guard AI", font=("Roboto", 24, "bold"))
        self.label.pack(pady=20)

        # Status Label
        self.status_label = ctk.CTkLabel(self, text="System Idle - Ready to Scan", text_color="gray", wraplength=400)
        self.status_label.pack(pady=5)

        # The Big Action Button
        self.scan_btn = ctk.CTkButton(
            self, 
            text="SCAN SCREEN FOR QR", 
            font=("Roboto", 16),
            height=50,
            width=250,
            fg_color="#1f6aa5",
            hover_color="#144870",
            command=self.start_scan_thread
        )
        self.scan_btn.pack(pady=30)

        # Footer
        self.footer = ctk.CTkLabel(self, text="v1.0 | Zero-Click Phishing Defense", font=("Arial", 10))
        self.footer.pack(side="bottom", pady=10)

        # Initialize OpenCV QR Detector
        self.qr_decoder = cv2.QRCodeDetector()

    def start_scan_thread(self):
        """Runs the scan in a background thread to keep GUI responsive"""
        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.status_label.configure(text="Capturing Screen & Analyzing...", text_color="yellow")
        
        # Start the heavy lifting in a separate thread
        threading.Thread(target=self.run_detection_logic, daemon=True).start()

    def run_detection_logic(self):
        try:
            # 1. Capture Screen
            screenshot = pyautogui.screenshot()
            
            # 2. Convert to format OpenCV can read
            img_np = np.array(screenshot)
            frame = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
            
            # 3. Detect QR Codes using OpenCV
            data, bbox, _ = self.qr_decoder.detectAndDecode(frame)

            if not data:
                # SAFE UPDATE: Send "No QR" message to main thread
                self.after(0, lambda: self.finish_gui_update("No QR Code Found", "orange", "Warning: No QR visible"))
                return

            # 4. QR Found! Process it.
            url = data
            # SAFE UPDATE: Update status text
            self.after(0, lambda: self.status_label.configure(text=f"Analyzing: {url[:30]}...", text_color="white"))
            
            # 5. CALL MAIN ENGINE
            verdict, risk_score, report = scan_url(url)
            
            # 6. Prepare Final Result
            if "SAFE" in verdict:
                msg = f"✅ SAFE (Risk: {risk_score})"
                detail = f"URL: {url[:40]}...\nNo threats detected."
                color = "#2cc985" # Green
            else:
                msg = f"🚨 THREAT DETECTED (Risk: {risk_score})"
                detail = f"VERDICT: {verdict}\nFlags: {report[0] if report else 'Unknown'}"
                color = "#ff4d4d" # Red

            # SAFE UPDATE: Send final result to main thread
            self.after(0, lambda: self.finish_gui_update(msg, color, detail))

        except Exception as e:
            print(f"Error: {e}")
            self.after(0, lambda: self.finish_gui_update("System Error", "orange", str(e)))

    def finish_gui_update(self, status_text, color, notif_msg):
        """
        This function runs ONLY on the main thread.
        It updates the GUI and triggers the notification safely.
        """
        # 1. Update Label
        self.status_label.configure(text=status_text, text_color=color)
        
        # 2. Reset Button
        self.scan_btn.configure(state="normal", text="SCAN SCREEN FOR QR")

        # 3. Send Notification (Safe block)
        try:
            notification.notify(
                title=status_text,
                message=notif_msg,
                app_name="Quish-Guard AI",
                timeout=10
            )
        except Exception:
            pass # Even if notification fails, the app won't crash now

if __name__ == "__main__":
    app = QuishGuardApp()
    app.mainloop()