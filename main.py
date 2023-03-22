import pandas as pd
import sqlite3
import json
import matplotlib.pyplot as plt
import matplotlib.dates as mdates


def createBase(con):
    #alerts
    alerts = pd.read_csv("data/alerts.csv")
    alerts.to_sql("alerts", con, if_exists="replace", index=False)

    #devices
    dev = open("data/devices.json")
    devices = json.load(dev)

    # create tables
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, ip TEXT, localizacion TEXT, responsable_id TEXT, analisis_id INTEGER)")
    cur.execute("CREATE TABLE IF NOT EXISTS responsable (nombre TEXT PRIMARY KEY, telefono TEXT, rol TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS analisis (id INTEGER PRIMARY KEY, puertos_abiertos TEXT, no_puertos_abiertos INTEGER, servicios INTEGER, servicios_inseguros INTEGER, vulnerabilidades_detectadas INTEGER)")

    for d in devices:
        responsable = d['responsable']
        cur.execute("INSERT OR IGNORE INTO responsable (nombre,telefono,rol) VALUES (?, ?, ?)", (responsable['nombre'], responsable['telefono'], responsable['rol']))
        analisis = d['analisis']
        if analisis["puertos_abiertos"] == 'None':
            ports = 0
        else:
            ports = len(analisis["puertos_abiertos"])
        cur.execute("INSERT OR IGNORE INTO analisis (puertos_abiertos, no_puertos_abiertos, servicios, servicios_inseguros, vulnerabilidades_detectadas) VALUES (?, ?, ?, ?, ?)", (json.dumps(analisis['puertos_abiertos']), ports, analisis['servicios'], analisis['servicios_inseguros'], analisis['vulnerabilidades_detectadas']))
        analisis_id = cur.lastrowid
        cur.execute("INSERT OR IGNORE INTO devices (id, ip, localizacion, responsable_id, analisis_id) VALUES (?, ?, ?, ?, ?)", (d['id'], d['ip'], d['localizacion'], responsable['nombre'], analisis_id))

def ex2(con):
    devices = pd.read_sql_query("SELECT * from devices", con)
    alerts = pd.read_sql_query("SELECT * from alerts", con)
    analisis = pd.read_sql_query("SELECT * from analisis", con)
    print("Ejercicio 2:")
    print("Número de dispositivos: ",devices.shape[0])
    print("Número de alertas: ", alerts.shape[0])
    print("Media de puertos abiertos: ", analisis['no_puertos_abiertos'].mean())
    print("Desviación estandar de puertos abiertos: ", analisis['no_puertos_abiertos'].std())
    print("Media de servicios inseguros: ", analisis['servicios_inseguros'].mean())
    print("Desviación estandar de servicios inseguros: ", analisis['servicios_inseguros'].std())
    print("Media de vulnerabilidades encontradas: ", analisis['vulnerabilidades_detectadas'].mean())
    print("Desviación estandar de vulnerabilidades encontradas: ", analisis['vulnerabilidades_detectadas'].std())
    print("Mínimo de puertos abiertos: ", analisis['no_puertos_abiertos'].min())
    print("Máximo de puertos abiertos: ", analisis['no_puertos_abiertos'].max())
    print("Mínimo de vulnerabilidades encontradas: ", analisis['vulnerabilidades_detectadas'].min())
    print("Máximo de vulnerabilidades encontradas: ", analisis['vulnerabilidades_detectadas'].max())
    print()

def ex3(con):
    alertasPrioridad = pd.read_sql_query("SELECT * from alerts GROUP BY PRIORIDAD", con)
    alertasFecha = pd.read_sql_query("SELECT * from alerts GROUP BY PRIORIDAD", con)


    print("Ejercicio 3:")
    print()

def ex4(con):
    cur = con.cursor()
    cur.execute("SELECT origen, COUNT(*) as num_alertas FROM alerts WHERE prioridad = 1 GROUP BY origen ORDER BY num_alertas DESC LIMIT 10")
    ips = []
    num = []
    for row in cur.fetchall():
        ips.append(row[0])
        num.append(row[1])
    plt.bar(ips, num)
    plt.xticks(rotation=20, ha='right')
    plt.title('IP de origen más problemáticas')
    plt.xlabel('IP de origen')
    plt.ylabel('Número de alertas')
    plt.show()

    cur.execute("SELECT strftime('%Y-%m-%d',timestamp), COUNT(*) FROM alerts GROUP BY strftime('%Y-%m-%d',timestamp)")
    fechas = []
    num2 = []
    for row in cur.fetchall():
        fechas.append(row[0])
        num2.append(row[1])
    fig, ax = plt.subplots()
    ax.plot(fechas, num2)
    plt.xticks(rotation=25)
    ax.set_title('Número de alertas por día')
    ax.set_xlabel('Fecha')
    ax.set_ylabel('Número de alertas')
    ax.xaxis.set_major_locator(mdates.DayLocator(interval=7))
    plt.show()




con = sqlite3.connect("database.db")
createBase(con)
ex2(con)
ex3(con)
ex4(con)
con.commit()

