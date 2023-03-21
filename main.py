import pandas as pd
import sqlite3
import json

con = sqlite3.connect("database.db")
cur = con.cursor()

#alerts
alerts = pd.read_csv("data/alerts.csv")
alerts.to_sql("alerts", con, if_exists="replace", index=False)

#devices
dev=open("data/devices.json", "r")
devices = json.load(dev)

# create tables
cur.execute('''CREATE TABLE IF NOT EXISTS devices (id TEXT, ip TEXT, localizacion TEST, responsable_id TEXT, analisis_id INTEGER)''')
cur.execute('''CREATE TABLE IF NOT EXISTS responsable (nombre TEXT PRIMARY KEY, telefono TEXT, rol TEXT)''')
cur.execute('''CREATE TABLE IF NOT EXISTS analisis (id INTEGER PRIMARY_KEY, puertos_abiertos TEXT, no_puertos_abiertos INTEGER, servicios INTEGER, servicios_inseguros INTEGER, vulnerabilidades_detectadas INTEGER)''')

for d in devices:
    responsable = d['responsable']
    cur.execute("INSERT OR IGNORE INTO responsable VALUES (?, ?, ?)", (responsable['nombre'], responsable['telefono'], responsable['rol']))
    analisis = d['analisis']
    if analisis["puertos_abiertos"] == 'None':
        ports = 0
    else:
        ports = len(analisis["puertos_abiertos"])
    cur.execute("INSERT INTO analisis (puertos_abiertos, no_puertos_abiertos, servicios, servicios_inseguros, vulnerabilidades_detectadas) VALUES (?, ?, ?, ?, ?)", (json.dumps(analisis['puertos_abiertos']), ports, analisis['servicios'], analisis['servicios_inseguros'], analisis['vulnerabilidades_detectadas']))
    analisis_id = cur.lastrowid
    cur.execute("INSERT INTO devices (id, ip, localizacion, responsable_id, analisis_id) VALUES (?, ?, ?, ?, ?)", (d['id'], d['ip'], d['localizacion'], responsable['nombre'], analisis_id))

con.commit()

