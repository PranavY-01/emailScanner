import tkinter as tk
from tkinter import filedialog, messagebox
from email import policy
from email.parser import BytesParser
import os
import re
import csv

def extract_links_from_body(msg):
    links = []
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                try:
                    body += part.get_content()
                except:
                    continue
    else:
        try:
            body = msg.get_content()
        except:
            pass

    links = re.findall(r'https?://[^\s"\'>]+', body)
    return links

def detect_phishing_keywords(msg):
    keywords = [
        'verify your account', 'login now', 'update your info',
        'click here', 'urgent', 'reset your password'
    ]
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                try:
                    body += part.get_content()
                except:
                    continue
    else:
        try:
            body = msg.get_content()
        except:
            pass

    matches = [kw for kw in keywords if kw.lower() in body.lower()]
    return matches

class EmailAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Spoofing & Phishing Detector")
        self.root.geometry("750x600")
        self.eml_path = None
        self.analysis_results = {}

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Email Spoofing & Phishing Detector", font=("Helvetica", 16, "bold")).pack(pady=10)

        tk.Button(self.root, text="📁 Select .eml File", command=self.load_eml_file).pack(pady=5)
        self.filename_label = tk.Label(self.root, text="No file selected", fg="gray")
        self.filename_label.pack(pady=5)

        self.preview_text = tk.Text(self.root, height=15, width=85, wrap=tk.WORD)
        self.preview_text.pack(pady=10)

        self.scan_button = tk.Button(self.root, text="🔍 Scan Email", command=self.scan_email, state=tk.DISABLED)
        self.scan_button.pack(pady=5)

        self.result_label = tk.Label(self.root, text="", fg="blue", font=("Arial", 12, "bold"))
        self.result_label.pack(pady=10)

        self.export_button = tk.Button(self.root, text="📄 Export Report to CSV", command=self.export_report, state=tk.DISABLED)
        self.export_button.pack(pady=5)

    def load_eml_file(self):
        filetypes = [("EML files", "*.eml")]
        filepath = filedialog.askopenfilename(title="Open .eml file", filetypes=filetypes)

        if filepath:
            self.eml_path = filepath
            self.filename_label.config(text=f"Selected: {os.path.basename(filepath)}", fg="green")
            self.scan_button.config(state=tk.NORMAL)
            self.export_button.config(state=tk.DISABLED)
            self.preview_text.delete("1.0", tk.END)
            self.result_label.config(text="")

            with open(filepath, "rb") as file:
                msg = BytesParser(policy=policy.default).parse(file)

            from_ = msg.get("From", "N/A")
            subject = msg.get("Subject", "N/A")
            received = msg.get_all("Received", [])
            self.preview_text.insert(tk.END, f"From: {from_}\n")
            self.preview_text.insert(tk.END, f"Subject: {subject}\n\n")
            self.preview_text.insert(tk.END, "Received Headers:\n")
            for line in received[:3]:
                self.preview_text.insert(tk.END, f"{line}\n\n")

    def scan_email(self):
        if not self.eml_path:
            messagebox.showwarning("No file", "Please load a .eml file first.")
            return

        with open(self.eml_path, "rb") as file:
            msg = BytesParser(policy=policy.default).parse(file)

        auth_results = msg.get("Authentication-Results", "")
        dkim_sig = msg.get("DKIM-Signature", "")
        spf_header = msg.get("Received-SPF", "")

        results = {}

        # SPF Check
        if "spf=pass" in auth_results.lower():
            results["SPF"] = "Pass"
        elif "spf=fail" in auth_results.lower() or "fail" in spf_header.lower():
            results["SPF"] = "Fail"
        else:
            results["SPF"] = "Unknown"

        # DKIM Check
        if "dkim=pass" in auth_results.lower():
            results["DKIM"] = "Pass"
        elif "dkim=fail" in auth_results.lower() or "b=" in dkim_sig.lower():
            results["DKIM"] = "Fail"
        else:
            results["DKIM"] = "Unknown"

        # DMARC Check
        if "dmarc=pass" in auth_results.lower():
            results["DMARC"] = "Pass"
        elif "dmarc=fail" in auth_results.lower():
            results["DMARC"] = "Fail"
        else:
            results["DMARC"] = "Unknown"

        # Phishing checks
        links = extract_links_from_body(msg)
        suspicious_links = [link for link in links if "login" in link or "verify" in link]
        results["Links Found"] = len(links)
        results["Suspicious Links"] = len(suspicious_links)

        matched_keywords = detect_phishing_keywords(msg)
        results["Phishing Keywords"] = ", ".join(matched_keywords) if matched_keywords else "None"

        self.analysis_results = results

        # Show results
        result_text = "\n".join([f"{key}: {val}" for key, val in results.items()])
        risk_level = self.get_risk_level(results)
        self.result_label.config(text=f"Scan Result:\n{result_text}\n\nRisk Level: {risk_level}")
        self.export_button.config(state=tk.NORMAL)

    def get_risk_level(self, results):
        if results.get("SPF") == "Fail" or results.get("DKIM") == "Fail" or results.get("DMARC") == "Fail":
            return "🚨 High Risk (Possible Spoofing)"
        elif results.get("Suspicious Links", 0) > 0 or results.get("Phishing Keywords") != "None":
            return "⚠️ Medium Risk (Possible Phishing)"
        else:
            return "✅ Low Risk (No major threats found)"

def export_report(self):
        if not self.analysis_results:
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not save_path:
            return

        with open(save_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Check", "Result"])
            for k, v in self.analysis_results.items():
                writer.writerow([k, v])
        messagebox.showinfo("Success", f"Report saved to:\n{save_path}")
    
# To run the tool
if __name__ == "__main__":
    root = tk.Tk()
    app = EmailAnalyzerApp(root)
    root.mainloop()
