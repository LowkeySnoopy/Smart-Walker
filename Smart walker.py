import tkinter as tk
from tkinter import ttk
import random

# Simulated status for assisted mode, sign-in, and power
assisted_mode = True
signed_in = False
powered_on = True
users = {}  # Dictionary to store user credentials (username: password)

# Global variable to store the current logged-in user
current_user = ""

# Functions for button actions
def toggle_assisted_mode():
    global assisted_mode
    assisted_mode = not assisted_mode
    assisted_mode_btn.config(text="Turn On Assisted Mode" if not assisted_mode else "Turn Off Assisted Mode")
    status_label.config(text="Assisted Mode: OFF" if not assisted_mode else "Assisted Mode: ON")

def open_sign_in_window():
    sign_in_window = tk.Toplevel(root)
    sign_in_window.title("Sign In")
    sign_in_window.geometry("300x200")
    sign_in_window.configure(bg="#e6f7ff")

    label = tk.Label(sign_in_window, text="Enter Your Credentials", font=("Arial", 14), bg="#e6f7ff")
    label.pack(pady=10)

    username_label = tk.Label(sign_in_window, text="Username:", font=("Arial", 12), bg="#e6f7ff")
    username_label.pack(pady=5)
    username_entry = ttk.Entry(sign_in_window)
    username_entry.pack(pady=5)

    password_label = tk.Label(sign_in_window, text="Password:", font=("Arial", 12), bg="#e6f7ff")
    password_label.pack(pady=5)
    password_entry = ttk.Entry(sign_in_window, show="*")
    password_entry.pack(pady=5)

    login_button = ttk.Button(sign_in_window, text="Login", command=lambda: login(username_entry.get(), password_entry.get(), sign_in_window))
    login_button.pack(pady=10)

def login(username, password, sign_in_window):
    global signed_in, current_user
    if username in users and users[username] == password:
        signed_in = True
        current_user = username
        sign_in_window.destroy()  # Close the sign-in window
        update_user_status()  # Update the GUI with the logged-in user
    else:
        error_label = tk.Label(sign_in_window, text="Invalid credentials. Please try again.", font=("Arial", 12), fg="red", bg="#e6f7ff")
        error_label.pack(pady=10)

def sign_up():
    sign_up_window = tk.Toplevel(root)
    sign_up_window.title("Sign Up")
    sign_up_window.geometry("300x250")
    sign_up_window.configure(bg="#e6f7ff")

    label = tk.Label(sign_up_window, text="Create Your Account", font=("Arial", 14), bg="#e6f7ff")
    label.pack(pady=10)

    username_label = tk.Label(sign_up_window, text="Username:", font=("Arial", 12), bg="#e6f7ff")
    username_label.pack(pady=5)
    username_entry = ttk.Entry(sign_up_window)
    username_entry.pack(pady=5)

    password_label = tk.Label(sign_up_window, text="Password:", font=("Arial", 12), bg="#e6f7ff")
    password_label.pack(pady=5)
    password_entry = ttk.Entry(sign_up_window, show="*")
    password_entry.pack(pady=5)

    confirm_password_label = tk.Label(sign_up_window, text="Confirm Password:", font=("Arial", 12), bg="#e6f7ff")
    confirm_password_label.pack(pady=5)
    confirm_password_entry = ttk.Entry(sign_up_window, show="*")
    confirm_password_entry.pack(pady=5)

    sign_up_button = ttk.Button(sign_up_window, text="Sign Up", command=lambda: create_account(username_entry.get(), password_entry.get(), confirm_password_entry.get(), sign_up_window))
    sign_up_button.pack(pady=10)

def create_account(username, password, confirm_password, sign_up_window):
    if password == confirm_password:
        if username not in users:
            users[username] = password
            sign_up_window.destroy()  # Close the sign-up window
            open_sign_in_window()  # Open the sign-in window after successful sign-up
        else:
            error_label = tk.Label(sign_up_window, text="Username already exists.", font=("Arial", 12), fg="red", bg="#e6f7ff")
            error_label.pack(pady=10)
    else:
        error_label = tk.Label(sign_up_window, text="Passwords do not match.", font=("Arial", 12), fg="red", bg="#e6f7ff")
        error_label.pack(pady=10)

def logout():
    global signed_in, current_user
    signed_in = False
    current_user = ""
    update_user_status()

def update_user_status():
    if signed_in:
        user_status_label.config(text=f"Signed in as: {current_user}")
        sign_in_btn.config(state="disabled")  # Disable sign-in button after logging in
        sign_up_btn.config(state="disabled")  # Disable sign-up button after logging in
        logout_btn.config(state="normal")  # Enable logout button after logging in
    else:
        user_status_label.config(text="Not signed in")
        sign_in_btn.config(state="normal")  # Enable sign-in button when logged out
        sign_up_btn.config(state="normal")  # Enable sign-up button when logged out
        logout_btn.config(state="disabled")  # Disable logout button when logged out

def toggle_power():
    global powered_on
    powered_on = not powered_on
    power_btn.config(text="Power On" if not powered_on else "Power Off")
    power_status_label.config(text="Power: OFF" if not powered_on else "Power: ON")

def open_map_window():
    map_window = tk.Toplevel(root)
    map_window.title("Location Map")
    map_window.geometry("400x300")
    map_window.configure(bg="#e6f7ff")

    label = tk.Label(map_window, text="Current Location Map", font=("Arial", 14), bg="#e6f7ff")
    label.pack(pady=10)

    # Placeholder for the map
    map_canvas = tk.Canvas(map_window, width=350, height=200, bg="white", highlightbackground="#ddd")
    map_canvas.create_text(175, 100, text="Map Placeholder", font=("Arial", 12))
    map_canvas.pack(pady=10)

def update_gui():
    """
    Simulates updates to the GUI. Replace this with real data from Jetson Nano.
    """
    # Simulate obstacle and crack detection
    obstacle_status = random.choice(["No Obstacles", "Obstacle Detected"])
    crack_status = random.choice(["No Cracks", "Crack Detected"])

    # Update the GUI labels
    obstacle_label.config(text=f"Obstacle Status: {obstacle_status}")
    crack_label.config(text=f"Crack Status: {crack_status}")

    # Update the 3D model placeholder (if real 3D data is provided, integrate it here)
    model_canvas.delete("all")
    model_canvas.create_text(150, 100, text="3D Model Placeholder", font=("Arial", 14))

    # Schedule the next update
    root.after(1000, update_gui)


# Initialize the Tkinter window
root = tk.Tk()
root.title("Smart Walker GUI")
root.geometry("600x500")
root.configure(bg="#e6f7ff")

# GUI Header
header_label = tk.Label(root, text="Smart Walker", font=("Arial", 24, "bold"), bg="#e6f7ff", fg="#003366")
header_label.pack(pady=10)

# Status Display Frame
status_frame = ttk.Frame(root)
status_frame.pack(pady=10, fill="x")

# Obstacle Status Label
obstacle_label = tk.Label(status_frame, text="Obstacle Status: Loading...", font=("Arial", 12), bg="#e6f7ff")
obstacle_label.pack(anchor="w", padx=10, pady=5)

# Crack Status Label
crack_label = tk.Label(status_frame, text="Crack Status: Loading...", font=("Arial", 12), bg="#e6f7ff")
crack_label.pack(anchor="w", padx=10, pady=5)

# Power Status
power_status_label = tk.Label(status_frame, text="Power: ON", font=("Arial", 12), bg="#e6f7ff")
power_status_label.pack(anchor="w", padx=10, pady=5)

# 3D Model Display Frame
model_frame = ttk.Frame(root)
model_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Placeholder for the 3D model
model_canvas = tk.Canvas(model_frame, width=300, height=200, bg="white", highlightbackground="#ddd")
model_canvas.pack(pady=10)

# Buttons Frame
buttons_frame = ttk.Frame(root)
buttons_frame.pack(pady=10)

# Buttons for functionalities
assisted_mode_btn = ttk.Button(buttons_frame, text="Turn Off Assisted Mode", command=toggle_assisted_mode)
assisted_mode_btn.grid(row=0, column=0, padx=10, pady=5)

sign_in_btn = ttk.Button(buttons_frame, text="Sign In", command=open_sign_in_window)
sign_in_btn.grid(row=0, column=1, padx=10, pady=5)

sign_up_btn = ttk.Button(buttons_frame, text="Sign Up", command=sign_up)
sign_up_btn.grid(row=0, column=2, padx=10, pady=5)

logout_btn = ttk.Button(buttons_frame, text="Logout", command=logout, state="disabled")
logout_btn.grid(row=0, column=3, padx=10, pady=5)

map_btn = ttk.Button(buttons_frame, text="Open Map", command=open_map_window)
map_btn.grid(row=0, column=4, padx=10, pady=5)

power_btn = ttk.Button(buttons_frame, text="Power Off", command=toggle_power)
power_btn.grid(row=1, column=0, padx=10, pady=5)

# User status label (show the signed-in user)
user_status_label = tk.Label(root, text="Not signed in", font=("Arial", 12), bg="#e6f7ff")
user_status_label.pack(pady=10)

# Update the GUI periodically
update_gui()

root.mainloop()
