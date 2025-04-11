import subprocess
import sys
import os
import threading
import requests
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.ttk import Progressbar
from requests_oauthlib import OAuth2Session

# Intentamos importar Flask
try:
    from flask import Flask, redirect, request, session
except ImportError:
    print("Flask no está instalado. Instalando Flask...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "Flask"])
    from flask import Flask, redirect, request, session

# Configuración de la app en Epic Games
CLIENT_ID = "TU_CLIENT_ID"
CLIENT_SECRET = "TU_CLIENT_SECRET"
REDIRECT_URI = "http://localhost:5000/callback"
AUTHORIZATION_BASE_URL = "https://www.epicgames.com/id/authorize"
TOKEN_URL = "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token"
API_URL = "https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/game/v2/profile/"

# Clave API de fortnite-api.com
FORTNITE_API_KEY = "35b2f455-02f9-4bda-b9e8-c9fb7742b8e4"
HEADERS = {
    "Authorization": f"Bearer {FORTNITE_API_KEY}"
}

# Flask setup para manejar OAuth
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Tkinter Setup
root = tk.Tk()
root.title("Checker de Cuentas Fortnite y Login Epic")
root.geometry("800x600")
root.config(bg="black")

# Global variables
cuentas_validas = 0
cuentas_invalidas = 0
oauth_session = None
access_token = None

def iniciar_sesion_epic():
    """ Inicia sesión con Epic Games mediante OAuth """
    global oauth_session
    oauth_session = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, scope=["profile", "offline_access", "openid"])
    authorization_url, state = oauth_session.authorization_url(AUTHORIZATION_BASE_URL)
    session["oauth_state"] = state
    messagebox.showinfo("Iniciar sesión", f"Por favor, accede a este enlace: {authorization_url}")
    redirect(authorization_url)

def cargar_archivo():
    """ Cargar cuentas desde archivo .txt """
    global cuentas_validas, cuentas_invalidas
    cuentas_validas = 0
    cuentas_invalidas = 0

    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if not file_path:
        return
    with open(file_path, "r") as f:
        cuentas = [line.strip() for line in f.readlines() if line.strip()]
    
    resultado.delete("1.0", tk.END)
    progress_bar["value"] = 0
    progress_bar["maximum"] = len(cuentas)

    for i, cuenta in enumerate(cuentas):
        root.update()
        chequear_cuenta(cuenta)
        progress_bar["value"] = i + 1

    resumen = f"\n✔️ Cuentas válidas: {cuentas_validas} | ❌ Inválidas: {cuentas_invalidas}\n"
    resultado.insert(tk.END, resumen)

def chequear_cuenta(nombre_usuario):
    """ Chequear la cuenta usando fortnite-api.com """
    global cuentas_validas, cuentas_invalidas

    url = f"https://fortnite-api.com/v2/stats/br/v2?name={nombre_usuario}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
    except Exception as e:
        resultado.insert(tk.END, f"Error al conectar con la API para {nombre_usuario}: {e}\n")
        return

    if response.status_code == 200:
        data = response.json().get("data", {})
        platform = data.get("platform", "N/A")
        level = data.get("battlePass", {}).get("level", "N/A")
        stats = data.get("stats", {}).get("all", {}).get("overall", {})
        
        if access_token:
            locker_info = obtener_locker_privado()
            skins = locker_info.get("skins", [])
            skins_str = "\n  ".join([f"Skin: {skin['name']}" for skin in skins]) if skins else "No tiene skins disponibles."

            texto = f"Cuenta: {nombre_usuario}\n"
            texto += f"  Plataforma: {platform}\n"
            texto += f"  Nivel del pase de batalla: {level}\n"
            texto += f"  Kills: {stats.get('kills', 'N/A')}\n"
            texto += f"  Wins: {stats.get('wins', 'N/A')}\n"
            texto += f"  Partidas: {stats.get('matches', 'N/A')}\n"
            texto += f"  Skins:\n  {skins_str}\n"
            texto += "-" * 50 + "\n"
            cuentas_validas += 1
        else:
            texto = f"Cuenta: {nombre_usuario} ❌ Sin acceso al locker (OAuth requerido)\n" + "-" * 50 + "\n"
            cuentas_invalidas += 1

    elif response.status_code == 404:
        texto = f"Cuenta: {nombre_usuario} ❌ NO ENCONTRADA\n" + "-" * 50 + "\n"
        cuentas_invalidas += 1
    else:
        texto = f"⚠️ Error al chequear {nombre_usuario}: {response.status_code}\n"
        cuentas_invalidas += 1

    resultado.insert(tk.END, texto)

def obtener_locker_privado():
    """ Obtener el locker privado (skins) del jugador usando su access_token """
    global access_token
    if not access_token:
        messagebox.showerror("Error", "No se ha obtenido un token de acceso válido.")
        return {}

    locker_url = f"https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/game/v2/profile/me"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(locker_url, headers=headers)

    if response.status_code == 200:
        return response.json().get("profile", {}).get("locker", {})
    else:
        messagebox.showerror("Error al obtener locker", f"Error al obtener el locker privado: {response.status_code} - {response.text}")
        return {}

def guardar_resultados():
    """ Guardar los resultados en archivo .txt """
    texto = resultado.get("1.0", tk.END)
    if not texto.strip():
        messagebox.showwarning("Aviso", "No hay resultados para guardar.")
        return
    archivo = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if archivo:
        with open(archivo, "w", encoding="utf-8") as f:
            f.write(texto)
        messagebox.showinfo("Guardado", "Resultados guardados correctamente.")

# Interfaz gráfica Tkinter
frame_botones = tk.Frame(root, bg="black")
frame_botones.pack(pady=10)

boton_iniciar_sesion = tk.Button(frame_botones, text="Iniciar sesión con Epic", command=iniciar_sesion_epic, bg="#0f0", fg="black", font=("Arial", 10, "bold"))
boton_iniciar_sesion.pack(side=tk.LEFT, padx=10)

boton_cargar = tk.Button(frame_botones, text="Cargar cuentas de Epic", command=cargar_archivo, bg="#0f0", fg="black", font=("Arial", 10, "bold"))
boton_cargar.pack(side=tk.LEFT, padx=10)

boton_guardar = tk.Button(frame_botones, text="Guardar información", command=guardar_resultados, bg="#0f0", fg="black", font=("Arial", 10, "bold"))
boton_guardar.pack(side=tk.LEFT, padx=10)

progress_bar = Progressbar(root, orient=tk.HORIZONTAL, length=700, mode='determinate')
progress_bar.pack(pady=10)

resultado = tk.Text(root, bg="black", fg="lime", font=("Courier New", 10), wrap=tk.WORD)
resultado.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

# Flask route to handle OAuth callback
@app.route("/callback")
def callback():
    global oauth_session, access_token
    try:
        oauth_session = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, state=session["oauth_state"])
        oauth_session.fetch_token(TOKEN_URL, client_secret=CLIENT_SECRET, authorization_response=request.url)

        access_token = oauth_session.token.get('access_token', None)

        # Depuración adicional
        print(f"Access Token: {access_token}")
        if access_token:
            messagebox.showinfo("Autenticación Exitosa", "¡Has iniciado sesión con Epic Games!")
        else:
            messagebox.showerror("Error", "No se pudo obtener el token de acceso.")
    except Exception as e:
        print(f"Error durante la autenticación: {e}")
        messagebox.showerror("Error de Autenticación", f"Error durante la autenticación: {e}")

    return redirect("/")

# Ejecutar la aplicación Flask
if __name__ == "__main__":
    if "gunicorn" not in sys.argv:
        subprocess.Popen([sys.executable, "checker fortnite.py", "gunicorn"])
    else:
        app.run(debug=False, use_reloader=False, port=5000)
